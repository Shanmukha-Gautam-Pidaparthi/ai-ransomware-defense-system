"""
collector/process_monitor.py
=============================
Stage 1 — Process Monitor

Architecture Doc requirements (Stage 1 Key Implementations):
  "Uses psutil or OS-level kernel hooks to poll and record process
   creation/termination, executable SHA-256 binary hash, start time,
   PID, and TID."

What this module does:
  1. Runs a background polling thread at a configurable interval.
  2. On every poll, calls psutil.process_iter() to get all running processes.
  3. For each NEW process (not seen before), records:
       - pid, name, exe path, ppid (parent PID), create_time, cmdline
       - SHA-256 hash of the executable binary
  4. For exited processes, marks them as terminated in the registry.
  5. Exposes get_process_by_pid(pid) for use by queue_joiner.py during PID joins.

Windows-specific:
  - psutil.Process.exe() raises AccessDenied for some system processes (PID 0, 4).
    These are handled gracefully with a fallback "SYSTEM" label.
  - SHA-256 hashing respects hash_timeout_sec to avoid stalling on large binaries.
  - Binary hashing uses read-only streaming (4 MB chunks) to minimise memory use.
"""

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import psutil

logger = logging.getLogger(__name__)

# ─── Data Model ───────────────────────────────────────────────────────────────

@dataclass
class ProcessRecord:
    """Immutable snapshot of a process captured at first observation."""
    pid:         int
    name:        str
    exe:         str                     # Full path to executable
    ppid:        int                     # Parent PID
    create_time: float                   # Unix timestamp (from psutil)
    cmdline:     List[str]               # Command-line arguments
    sha256:      str                     # SHA-256 of the executable binary
    alive:       bool = True             # False once termination is detected
    parent_exe:  str  = "UNKNOWN"        # Resolved parent exe path

    def to_dict(self) -> dict:
        return {
            "pid":         self.pid,
            "name":        self.name,
            "exe":         self.exe,
            "ppid":        self.ppid,
            "create_time": self.create_time,
            "cmdline":     self.cmdline,
            "sha256":      self.sha256,
            "alive":       self.alive,
            "parent_exe":  self.parent_exe,
        }


# ─── SHA-256 Hashing ──────────────────────────────────────────────────────────

# Global in-memory hash cache: exe_path -> (mtime, sha256_hash)
_HASH_CACHE: Dict[str, tuple] = {}
_HASH_CACHE_LOCK = threading.Lock()


def _hash_binary(exe_path: str, timeout_sec: float = 2.0) -> str:
    """
    Stream-hash the executable at exe_path using SHA-256 with mtime caching.

    Returns the hex digest string, or "HASH_TIMEOUT" / "HASH_ERROR" on failure.
    Uses an in-memory mtime cache to avoid redundant binary reads and CPU overhead.
    """
    if not exe_path or not os.path.isfile(exe_path):
        return "HASH_ERROR:FILE_NOT_FOUND"

    try:
        current_mtime = os.path.getmtime(exe_path)
    except (PermissionError, OSError):
        current_mtime = 0.0

    # ── Check LRU/mtime Cache ────────────────────────────────────────────────
    with _HASH_CACHE_LOCK:
        if exe_path in _HASH_CACHE:
            cached_mtime, cached_hash = _HASH_CACHE[exe_path]
            if cached_mtime == current_mtime:
                return cached_hash

    # ── Compute SHA-256 Stream Hash ──────────────────────────────────────────
    hasher    = hashlib.sha256()
    deadline  = time.monotonic() + timeout_sec
    chunk_sz  = 4 * 1024 * 1024  # 4 MB

    try:
        with open(exe_path, "rb") as fh:
            while True:
                if time.monotonic() > deadline:
                    return "HASH_TIMEOUT"
                chunk = fh.read(chunk_sz)
                if not chunk:
                    break
                hasher.update(chunk)

        digest = hasher.hexdigest()

        # Cache result
        with _HASH_CACHE_LOCK:
            _HASH_CACHE[exe_path] = (current_mtime, digest)

        return digest
    except (PermissionError, OSError) as exc:
        return f"HASH_ERROR:{type(exc).__name__}"


# ─── Process Monitor ──────────────────────────────────────────────────────────

class ProcessMonitor:
    """
    Background thread that maintains a live registry of running processes.

    Usage:
        pm = ProcessMonitor(poll_interval_sec=1.0, hash_timeout_sec=2.0)
        pm.start()
        record = pm.get_process_by_pid(1234)
        pm.stop()
    """

    def __init__(
        self,
        poll_interval_sec: float = 1.0,
        hash_timeout_sec:  float = 2.0,
        skip_system_pids:  bool  = True,
    ):
        self._poll_interval  = poll_interval_sec
        self._hash_timeout   = hash_timeout_sec
        self._skip_system    = skip_system_pids

        # pid → ProcessRecord (thread-safe via RLock)
        self._registry: Dict[int, ProcessRecord] = {}
        self._lock = threading.RLock()

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Stats
        self.total_seen:      int = 0
        self.total_exited:    int = 0

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Run an initial snapshot then launch the background polling thread."""
        self._snapshot()   # Populate registry immediately on start
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._poll_loop,
            name="ProcessMonitor",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            f"[ProcessMonitor] Started. Poll interval: {self._poll_interval}s | "
            f"Initial processes: {len(self._registry)}"
        )

    def stop(self, timeout: float = 3.0) -> None:
        """Signal the polling thread to stop and wait for it to join."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        logger.info(
            f"[ProcessMonitor] Stopped. Seen: {self.total_seen} | "
            f"Exited: {self.total_exited}"
        )

    def get_process_by_pid(self, pid: int) -> Optional[ProcessRecord]:
        """
        Thread-safe lookup. Returns the ProcessRecord for a given PID,
        or None if not found (e.g., very short-lived processes).
        """
        with self._lock:
            return self._registry.get(pid)

    def all_alive(self) -> List[ProcessRecord]:
        """Return a list of all currently alive ProcessRecords."""
        with self._lock:
            return [r for r in self._registry.values() if r.alive]

    def snapshot_pids(self) -> List[int]:
        """Return list of all known PIDs (alive + exited)."""
        with self._lock:
            return list(self._registry.keys())

    # ──────────────────────────────────────────────────────────────────────────
    # Internal
    # ──────────────────────────────────────────────────────────────────────────

    def _poll_loop(self) -> None:
        """Poll psutil every poll_interval_sec until stop is signalled."""
        while not self._stop_event.wait(timeout=self._poll_interval):
            try:
                self._snapshot()
            except Exception as exc:
                logger.error(f"[ProcessMonitor] Error during snapshot: {exc}", exc_info=True)

    def _snapshot(self) -> None:
        """
        Single-pass scan of all running processes.

        1. Collect current live PIDs from psutil.
        2. Register new PIDs (hash binary, build ProcessRecord).
        3. Mark departed PIDs as alive=False.
        """
        try:
            live_pids = set()

            for proc in psutil.process_iter(
                attrs=["pid", "name", "exe", "ppid", "create_time", "cmdline"],
                ad_value=None,
            ):
                info = proc.info
                pid  = info.get("pid")

                if pid is None:
                    continue

                # Skip Windows idle/system processes if configured
                if self._skip_system and pid in (0, 4):
                    continue

                live_pids.add(pid)

                with self._lock:
                    if pid in self._registry:
                        continue    # Already recorded — skip re-hashing

                # New process — build a record
                record = self._build_record(info)
                if record:
                    with self._lock:
                        self._registry[pid] = record
                    self.total_seen += 1
                    logger.debug(
                        f"[ProcessMonitor] New process: PID={pid} | "
                        f"Name={record.name} | SHA256={record.sha256[:12]}..."
                    )

            # Mark exited processes
            with self._lock:
                for pid, record in self._registry.items():
                    if record.alive and pid not in live_pids:
                        record.alive = False
                        self.total_exited += 1
                        logger.debug(f"[ProcessMonitor] Process exited: PID={pid} | {record.name}")

        except Exception as exc:
            logger.error(f"[ProcessMonitor] _snapshot error: {exc}", exc_info=True)

    def _build_record(self, info: dict) -> Optional[ProcessRecord]:
        """Construct a ProcessRecord from a psutil process info dict."""
        pid   = info.get("pid",   -1)
        name  = info.get("name",  "UNKNOWN") or "UNKNOWN"
        exe   = info.get("exe",   "")  or ""
        ppid  = info.get("ppid",  -1)
        ctime = info.get("create_time", 0.0) or 0.0

        # cmdline may be None for system processes
        cmdline_raw = info.get("cmdline")
        cmdline = list(cmdline_raw) if cmdline_raw else []

        # Gracefully handle exe access denial (common on Windows for system procs)
        if not exe:
            exe = "SYSTEM_PROCESS"

        # SHA-256 hash of the executable
        sha256 = _hash_binary(exe, timeout_sec=self._hash_timeout)

        # Resolve parent exe path
        parent_exe = "UNKNOWN"
        if ppid and ppid > 0:
            parent_rec = None
            with self._lock:
                parent_rec = self._registry.get(ppid)
            if parent_rec:
                parent_exe = parent_rec.exe
            else:
                # Try to resolve directly from psutil
                try:
                    parent_proc = psutil.Process(ppid)
                    parent_exe  = parent_proc.exe() or "UNKNOWN"
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    parent_exe = "UNKNOWN"

        try:
            return ProcessRecord(
                pid         = pid,
                name        = name,
                exe         = exe,
                ppid        = ppid,
                create_time = ctime,
                cmdline     = cmdline,
                sha256      = sha256,
                parent_exe  = parent_exe,
                alive       = True,
            )
        except Exception as exc:
            logger.warning(f"[ProcessMonitor] Could not build record for PID {pid}: {exc}")
            return None
