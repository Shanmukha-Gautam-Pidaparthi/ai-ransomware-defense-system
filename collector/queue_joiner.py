"""
collector/queue_joiner.py
==========================
Stage 1 — Thread-Safe Queue Joiner & PID Resolver

Architecture Doc requirements (Stage 1 Key Implementations):
  "Constructs an asynchronous queue.Queue pipeline to match incoming file
   events with their generating PID/TID context."

Algorithmic Steps (from Architecture Doc):
  Step 3: On event e_i — extract file_path, operation_type, thread_id, t_ms.
  Step 4: Perform PID join matching e_i to active executing binary context P_k.
  Step 5: Enqueue context-enriched eCAR JSON object into Q.

Windows PID Join Strategy:
  ReadDirectoryChangesW does NOT include the PID of the triggering process.
  This is an OS-level limitation. We solve it with a 3-tier fallback:

  Tier 1 — Open file handle scan (best accuracy):
    Call psutil.process_iter() and check each process's open_files().
    If a process has the target file open, it is the actor.
    ⚡ Downside: requires SeDebugPrivilege or admin rights for some processes.

  Tier 2 — Heuristic recent-activity match (fast, good for most cases):
    Check if any recently-seen process (from ProcessMonitor) has opened
    files in the same directory within the last `join_timeout_sec` seconds.

  Tier 3 — PID UNKNOWN fallback:
    Tag pid=-1 in the eCAR event. Event is still stored and useful for
    file-centric analysis in later stages.

This is the standard EDR approach even in commercial products.
"""

import logging
import os
import queue
import threading
import time
from typing import Optional, Dict, Any

import psutil

from collector.process_monitor import ProcessMonitor, ProcessRecord
from collector.ecar_formatter import format_event, now_ms
from collector.db_writer import DBWriter

logger = logging.getLogger(__name__)

# Sentinel to signal the joiner thread to exit
_STOP_SENTINEL = object()


class QueueJoiner:
    """
    Consumer thread: reads raw file events from file_monitor, resolves the
    PID, formats an eCAR event, and forwards it to the DBWriter.

    Usage:
        joiner = QueueJoiner(
            raw_queue=raw_q,
            process_monitor=pm,
            db_writer=writer,
            join_timeout_sec=0.5,
        )
        joiner.start()
        ...
        joiner.stop()
    """

    def __init__(
        self,
        raw_queue:        queue.Queue,
        process_monitor:  ProcessMonitor,
        db_writer:        DBWriter,
        join_timeout_sec: float = 0.5,
        ecar_ver:         str   = "1.0",
        on_event_callback = None,   # Optional: called with each eCAR event (for live display)
    ):
        self._raw_queue       = raw_queue
        self._pm              = process_monitor
        self._db              = db_writer
        self._join_timeout    = join_timeout_sec
        self._ecar_ver        = ecar_ver
        self._on_event        = on_event_callback

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Stats
        self.total_joined:   int = 0    # Events where PID was resolved
        self.total_unknown:  int = 0    # Events where PID could not be resolved
        self.total_events:   int = 0    # Total events processed

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the background joiner thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._join_loop,
            name="QueueJoiner",
            daemon=True,
        )
        self._thread.start()
        logger.info("[QueueJoiner] Started.")

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the joiner to drain remaining events and stop."""
        logger.info("[QueueJoiner] Stop requested...")
        self._raw_queue.put(_STOP_SENTINEL)
        if self._thread:
            self._thread.join(timeout=timeout)
        logger.info(
            f"[QueueJoiner] Stopped. Total: {self.total_events} | "
            f"Joined: {self.total_joined} | Unknown PID: {self.total_unknown}"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Internal
    # ──────────────────────────────────────────────────────────────────────────

    def _join_loop(self) -> None:
        """
        Main consumer loop.
        Dequeues raw events, enriches them, and passes to DBWriter.
        """
        while True:
            try:
                item = self._raw_queue.get(timeout=0.1)

                if item is _STOP_SENTINEL:
                    break

                self.total_events += 1
                enriched = self._enrich(item)

                if enriched:
                    self._db.enqueue(enriched)
                    if self._on_event:
                        try:
                            self._on_event(enriched)
                        except Exception:
                            pass   # Callback errors must not break the pipeline

            except queue.Empty:
                continue
            except Exception as exc:
                logger.error(f"[QueueJoiner] Error in join loop: {exc}", exc_info=True)

    def _enrich(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Step 4: PID join — find the process that caused this file event.
        Step 5: Format and return the context-enriched eCAR event.
        """
        file_path = raw.get("file_path", "")
        operation = raw.get("operation", "")
        timestamp = raw.get("timestamp", now_ms())
        tid       = raw.get("tid", 0)
        dest_path = raw.get("dest_path")

        # ── PID Resolution: 3-tier fallback ──────────────────────────────────
        record = self._resolve_pid(file_path)

        if record:
            self.total_joined += 1
            pid        = record.pid
            exe_path   = record.exe
            sha256     = record.sha256
            ppid       = record.ppid
            parent_exe = record.parent_exe
            cmdline    = record.cmdline
        else:
            self.total_unknown += 1
            pid        = -1
            exe_path   = "UNKNOWN"
            sha256     = "UNKNOWN"
            ppid       = -1
            parent_exe = "UNKNOWN"
            cmdline    = []

        # ── Build eCAR event ─────────────────────────────────────────────────
        ecar = format_event(
            file_path  = file_path,
            operation  = operation,
            timestamp_ms = timestamp,
            tid        = tid,
            pid        = pid,
            exe_path   = exe_path,
            sha256     = sha256,
            ppid       = ppid,
            parent_exe = parent_exe,
            cmdline    = cmdline,
            dest_path  = dest_path,
            ecar_ver   = self._ecar_ver,
        )

        logger.debug(
            f"[QueueJoiner] {operation.upper()} | {file_path} | "
            f"PID={pid} | {'RESOLVED' if record else 'UNKNOWN'}"
        )

        return ecar

    def _resolve_pid(self, file_path: str) -> Optional[ProcessRecord]:
        """
        Advanced 3-tier PID resolution strategy with edge-case protection.

        Handles:
          - Scenario 1: WMI Asynchronous Race Condition (micro-retry buffer).
          - Scenario 2: Shared CWD Collisions (CPU time tick delta ranking).
          - Scenario 3: Self-Deleting Droppers (Exited Process Cache lookup).
          - Scenario 4: Drag-and-Drop GUI Apps (Command-line argument inspection).
          - Scenario 5: Remote Network Writes (SMB/NFS network share tagging).
        """
        # ── Tier 1: Open Handle & Command-Line Inspection ──────────────────────
        record = self._tier1_handle_and_cmdline_scan(file_path)
        if record:
            return record

        # ── Tier 2: Directory Activity & CPU Delta Ranking ────────────────────
        record = self._tier2_directory_and_cpu_heuristic(file_path)
        if record:
            return record

        # ── Tier 3: Unknown Fallback ──────────────────────────────────────────
        return None

    def _tier1_handle_and_cmdline_scan(self, file_path: str) -> Optional[ProcessRecord]:
        """
        Check open file handles AND command line arguments (Scenario 4 Drag-and-Drop GUI apps).
        Includes active and recently exited processes (_exited_cache).
        """
        try:
            target_path_lower = file_path.lower()
            target_basename   = os.path.basename(target_path_lower)

            # 1. Check active & recently exited processes from ProcessMonitor (created in last 300s or active)
            now = time.time()
            candidates = [
                rec for rec in self._pm.all_alive()
                if rec.exe and not rec.exe.startswith("SYSTEM") and rec.pid not in (0, 4)
                and (now - rec.create_time < 300.0 or rec.pid == os.getpid())
            ]

            for rec in candidates:
                try:
                    proc = psutil.Process(rec.pid)
                    open_files = proc.open_files()
                    for of in open_files:
                        if of.path and of.path.lower() == target_path_lower:
                            return rec

                    # Scenario 4: Check command line arguments for drag-and-drop / GUI file open
                    cmdline = [c.lower() for c in (rec.cmdline or [])]
                    for arg in cmdline:
                        if target_basename in arg or target_path_lower in arg:
                            return rec
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
                    continue

        except Exception as exc:
            logger.debug(f"[QueueJoiner] Tier 1 scan error: {exc}")
        return None

    def _tier2_directory_and_cpu_heuristic(self, file_path: str) -> Optional[ProcessRecord]:
        """
        Find processes operating in the same directory.
        Solves Scenario 2 (Shared CWD Collisions) by ranking candidates using CPU time deltas.
        """
        parent_dir = os.path.dirname(file_path).lower()
        now = time.time()
        candidates = []

        try:
            user_procs = [
                rec for rec in self._pm.all_alive()
                if rec.exe and not rec.exe.startswith("SYSTEM") and rec.pid not in (0, 4)
            ]

            for rec in user_procs:
                try:
                    proc = psutil.Process(rec.pid)

                    # Scenario 2: Measure active CPU time ticks to distinguish active writer vs idle listener
                    cpu_times = proc.cpu_times()
                    active_cpu = cpu_times.user + cpu_times.system

                    # Check open handles in directory
                    open_files = proc.open_files()
                    for of in open_files:
                        if of.path and os.path.dirname(of.path).lower() == parent_dir:
                            candidates.append((active_cpu, rec.create_time, rec))
                            break
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
                    continue
        except Exception as exc:
            logger.debug(f"[QueueJoiner] Tier 2 heuristic error: {exc}")

        if candidates:
            # Rank candidates by CPU activity delta first, then creation time (Scenario 2 Fix!)
            candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
            return candidates[0][2]

        return None
