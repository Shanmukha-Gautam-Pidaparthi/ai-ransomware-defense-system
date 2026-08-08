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

import ctypes
import logging
import os
import queue
import threading
import time
from typing import Optional, Dict, Any, List, Tuple

import psutil

from collector.process_monitor import ProcessMonitor, ProcessRecord
from collector.ecar_formatter import format_event, now_ms
from collector.db_writer import DBWriter

logger = logging.getLogger(__name__)

# Sentinel to signal the joiner thread to exit
_STOP_SENTINEL = object()


def get_foreground_pid() -> Optional[int]:
    """Returns the PID of the process owning the currently active foreground window."""
    try:
        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return None
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return pid.value if pid.value > 0 else None
    except Exception:
        return None


def normalize_path(p: str) -> str:
    """Normalize Windows paths resolving 8.3 short paths and relative paths."""
    if not p:
        return ""
    try:
        return os.path.realpath(os.path.normpath(p)).lower()
    except Exception:
        return os.path.normpath(p).lower()


class QueueJoiner:
    """
    Consumer thread: reads raw file events from file_monitor, resolves the
    PID, formats an eCAR event, and forwards it to the DBWriter.
    """

    def __init__(
        self,
        raw_queue:        queue.Queue,
        process_monitor:  ProcessMonitor,
        db_writer:        DBWriter,
        join_timeout_sec: float = 0.5,
        ecar_ver:         str   = "1.0",
        on_event_callback = None,   # Optional: called with each eCAR event
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
                            pass

            except queue.Empty:
                continue
            except Exception as exc:
                logger.error(f"[QueueJoiner] Error in join loop: {exc}", exc_info=True)

    def _enrich(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Step 4: PID join — find the process that caused this file event.
        Step 5: Format and return the context-enriched eCAR event.
        """
        file_path    = raw.get("file_path", "")
        operation    = raw.get("operation", "")
        timestamp    = raw.get("timestamp", now_ms())
        tid          = raw.get("tid", 0)
        dest_path    = raw.get("dest_path")
        is_directory = raw.get("is_directory", False)

        # ── PID Resolution ───────────────────────────────────────────────────
        record = self._resolve_pid(file_path, is_directory=is_directory)

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

    def _resolve_pid(self, file_path: str, is_directory: bool = False) -> Optional[ProcessRecord]:
        """
        2-Pass Multi-Signal Process Attribution Engine:
          Pass 1 (Sub-5ms): Evaluates fast metadata (I/O write deltas, recent spawn age, cmdline, CWD, active window)
          Pass 2 (Sub-2ms): Checks open_files() ONLY on the Top 3 candidate processes.
        """
        now = time.time()
        target_norm = normalize_path(file_path)

        if not hasattr(self, '_path_cache'):
            self._path_cache = {}

        # ── Tier 0: 5-Second Path Cache ─────────────────────────────────────
        if target_norm in self._path_cache:
            cached_record, cached_time = self._path_cache[target_norm]
            if (now - cached_time) < 5.0:
                return cached_record

        record, reason = self._fast_multi_signal_resolve(file_path, target_norm, is_directory=is_directory)

        if record:
            self._path_cache[target_norm] = (record, now)
            logger.info(
                f"[PID RESOLVED] File: {os.path.basename(file_path)} | "
                f"PID={record.pid} ({record.name or record.exe}) | Reason: {reason}"
            )
        else:
            logger.debug(f"[PID UNKNOWN] File: {os.path.basename(file_path)} | Reason: {reason}")

        return record

    def _fast_multi_signal_resolve(
        self,
        file_path: str,
        target_norm: str,
        is_directory: bool = False
    ) -> Tuple[Optional[ProcessRecord], str]:
        """
        High-accuracy, 2-pass Process Attribution Engine.
        """
        target_base = os.path.basename(target_norm)
        target_dir  = os.path.dirname(target_norm)
        now = time.time()
        my_pid = os.getpid()

        fg_pid = get_foreground_pid()
        is_dir_op = is_directory or ("new folder" in target_norm) or (not os.path.splitext(target_norm)[1])

        BACKGROUND_HELPERS = (
            'antigravity ide.exe', 'antigravity.exe', 'language_server_windows_x64.exe', 'code.exe',
            'onedrive.exe', 'brave.exe', 'chrome.exe', 'msedge.exe', 'msedgewebview2.exe'
        )
        SHELLS = ('powershell.exe', 'cmd.exe', 'pwsh.exe', 'bash.exe', 'windowsterminal.exe', 'wt.exe')
        SKIP_PREFIXES = (
            'svchost', 'csrss', 'smss', 'services', 'lsass', 'system', 'conhost',
            'fontdrvhost', 'searchhost', 'taskhostw', 'backgroundtaskhost',
            'runtimebroker', 'sihost', 'dllhost', 'smartscreen', 'compattelrunner'
        )

        candidates: List[Tuple[float, ProcessRecord, List[str]]] = []

        # ── PASS 1: Fast metadata scoring ───────────────────────────────────
        all_records = self._pm.all_recent_records() if hasattr(self._pm, 'all_recent_records') else self._pm.all_alive()

        # Live scan fallback for newly spawned processes (< 5s age) not yet in registry
        known_pids = {r.pid for r in all_records}
        live_recent_records = []
        try:
            for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'ppid']):
                try:
                    pid = p.info['pid']
                    if pid <= 4 or pid == my_pid or pid in known_pids:
                        continue
                    c_time = p.info.get('create_time', 0)
                    if (now - c_time) < 5.0:
                        name = p.info.get('name') or "UNKNOWN"
                        exe  = p.info.get('exe') or ""
                        cmd  = p.info.get('cmdline') or []
                        ppid = p.info.get('ppid', -1)
                        rec  = ProcessRecord(
                            pid=pid, name=name, exe=exe, ppid=ppid,
                            create_time=c_time, cmdline=cmd, sha256="PENDING",
                            alive=True
                        )
                        live_recent_records.append(rec)
                except Exception:
                    pass
        except Exception:
            pass

        combined_records = list(all_records) + live_recent_records

        for rec in combined_records:
            try:
                pid = rec.pid
                if pid <= 4 or pid == my_pid:
                    continue

                name = (rec.name or "").lower()
                if name.startswith(SKIP_PREFIXES):
                    continue

                score = 0.0
                reasons = []

                # Signal A: Active I/O Write Delta
                if rec.dw_bytes > 0 or rec.dw_count > 0:
                    score += min(80.0, 50.0 + (rec.dw_bytes / 1024.0))
                    reasons.append(f"IO_WRITE_DELTA({rec.dw_bytes}b)")

                # Signal B: Command Line Argument Match
                cmdline = [c.strip(' "\'').lower() for c in (rec.cmdline or [])]
                for arg in cmdline:
                    arg_norm = normalize_path(arg)
                    if arg_norm == target_norm:
                        score += 90.0
                        reasons.append("CMDLINE_EXACT")
                        break
                    elif target_base in arg and len(arg) > 3:
                        score += 50.0
                        reasons.append("CMDLINE_SUBSTR")
                        break

                # Signal C: Recent Process Spawn Age (within last 15s)
                age = now - rec.create_time
                if age < 15.0:
                    score += max(20.0, 80.0 - (age * 4.0))
                    reasons.append(f"RECENT_SPAWN({age:.1f}s)")

                # Signal D: Working Directory Match (if process is alive)
                if rec.alive:
                    try:
                        proc = psutil.Process(pid)
                        cwd = normalize_path(proc.cwd())
                        if cwd == target_dir:
                            score += 40.0
                            reasons.append("CWD_EXACT")
                        elif target_dir.startswith(cwd) and len(cwd) > 3:
                            score += 20.0
                            reasons.append("CWD_PARENT")
                    except Exception:
                        pass

                # Signal E: Active Foreground Window Ownership (User GUI Action)
                if fg_pid and pid == fg_pid:
                    score += 85.0
                    reasons.append("FOREGROUND_WINDOW_MATCH")

                # Signal F: Explorer Shell Operations (File/Folder action in Explorer)
                if name == 'explorer.exe':
                    if (fg_pid and pid == fg_pid) or is_dir_op:
                        score += 80.0
                        reasons.append("EXPLORER_SHELL_OP")

                # Signal G: Active Shell Execution (PowerShell / CMD / Terminal Transient Write)
                if name in SHELLS:
                    if rec.cpu_delta > 0.0 or rec.dw_bytes > 0 or rec.dw_count > 0 or (fg_pid and pid == fg_pid):
                        score += 90.0
                        reasons.append("TRANSIENT_SHELL_WRITE")

                # Signal H: Background IDE & Sync Deprioritization
                if name in BACKGROUND_HELPERS:
                    if any(user_dir in target_norm for user_dir in ('downloads', 'desktop', 'documents')):
                        if "CMDLINE_EXACT" not in reasons:
                            score -= 120.0
                            reasons.append("BACKGROUND_APP_PENALTY")

                if score > 0:
                    candidates.append((score, rec, reasons))

            except Exception:
                continue

        if not candidates:
            return None, "NO_CANDIDATES"

        # Sort candidates descending by Pass 1 score
        candidates.sort(key=lambda x: x[0], reverse=True)

        # ── PASS 2: Check open handles ONLY for Top 3 candidates ─────────────
        top_candidates = candidates[:3]
        for sc, rec, reasons in top_candidates:
            if rec.alive:
                try:
                    proc = psutil.Process(rec.pid)
                    for of in proc.open_files():
                        of_norm = normalize_path(of.path)
                        if of_norm == target_norm or (os.path.basename(of_norm) == target_base and target_dir in of_norm):
                            reasons.append("OPEN_HANDLE_CONFIRMED")
                            return rec, f"CONFIRMED_HANDLE (Score={sc+100.0:.1f}: {', '.join(reasons)})"
                except Exception:
                    pass

        # Return top candidate from Pass 1 if score >= 50.0
        top_score, top_rec, top_reasons = top_candidates[0]
        if top_score >= 50.0:
            return top_rec, f"HEURISTIC_MATCH (Score={top_score:.1f}: {', '.join(top_reasons)})"

        return None, "LOW_SCORE"

