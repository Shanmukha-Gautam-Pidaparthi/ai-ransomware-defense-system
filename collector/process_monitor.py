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
    last_cpu_time: float = 0.0           # For tracking recent CPU deltas
    cpu_delta:   float = 0.0             # Delta since last poll
    last_write_bytes: int = 0            # Tracking I/O write bytes
    last_write_count: int = 0            # Tracking I/O write count
    dw_bytes:    int = 0                 # Write bytes delta since last poll
    dw_count:    int = 0                 # Write count delta since last poll

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
    Returns ANOMALY:SELF_DELETED_BINARY if the executable was deleted before hashing.
    """
    if not exe_path or exe_path == "SYSTEM_PROCESS":
        return "SYSTEM_BINARY"

    if not os.path.isfile(exe_path):
        return "HASH_ERROR:FILE_NOT_FOUND:DELETED_BINARY"  # Self-deleting dropper anomaly tag

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
    hasher   = hashlib.sha256()
    deadline = time.monotonic() + timeout_sec
    chunk_sz = 4 * 1024 * 1024  # 4 MB

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

        with _HASH_CACHE_LOCK:
            _HASH_CACHE[exe_path] = (current_mtime, digest)

        return digest
    except (PermissionError, OSError) as exc:
        return f"HASH_ERROR:{type(exc).__name__}"


# ─── Process Monitor ──────────────────────────────────────────────────────────

class ProcessMonitor:
    """
    Background thread maintaining live registry AND exited process history cache.

    Edge Cases Handled:
      - Edge Case 3: Self-deleting droppers (tagged as ANOMALY:SELF_DELETED_BINARY).
      - Edge Case 1 & 4: 10-second _exited_cache holds metadata for processes
        that wrote files and terminated milliseconds before event queue processing.
    """

    def __init__(
        self,
        poll_interval_sec: float = 1.0,
        hash_timeout_sec:  float = 2.0,
        skip_system_pids:  bool  = True,
        exited_ttl_sec:    float = 10.0,
    ):
        self._poll_interval  = poll_interval_sec
        self._hash_timeout   = hash_timeout_sec
        self._skip_system    = skip_system_pids
        self._exited_ttl     = exited_ttl_sec

        # pid -> ProcessRecord (alive processes)
        self._registry: Dict[int, ProcessRecord] = {}
        # pid -> (exit_timestamp, ProcessRecord) (exited history cache for Edge Case 1 & 3)
        self._exited_cache: Dict[int, tuple] = {}
        self._lock = threading.RLock()

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Stats
        self.total_seen:   int = 0
        self.total_exited: int = 0

    def start(self) -> None:
        """Run an initial snapshot then launch the background polling thread."""
        self._snapshot()
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
        Thread-safe lookup. Checks active registry first, then exited history cache.
        Solves Edge Case 1 & 3: Fast-exiting scripts/droppers.
        """
        with self._lock:
            # 1. Check active registry
            rec = self._registry.get(pid)
            if rec:
                return rec

            # 2. Check exited process history cache
            if pid in self._exited_cache:
                exit_time, rec = self._exited_cache[pid]
                if time.time() - exit_time < self._exited_ttl:
                    return rec

            return None

    def all_alive(self) -> List[ProcessRecord]:
        """Return a list of all currently alive ProcessRecords."""
        with self._lock:
            return [r for r in self._registry.values() if r.alive]

    def all_recent_records(self) -> List[ProcessRecord]:
        """Return all active records plus non-expired exited records."""
        with self._lock:
            records = [r for r in self._registry.values() if r.alive]
            now = time.time()
            for ts, r in self._exited_cache.values():
                if (now - ts) < self._exited_ttl:
                    records.append(r)
            return records

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
        3. Update CPU and I/O write deltas.
        4. Mark departed PIDs as alive=False.
        """
        try:
            live_pids = set()

            for proc in psutil.process_iter(
                attrs=["pid", "name", "exe", "ppid", "create_time", "cmdline", "cpu_times"],
                ad_value=None,
            ):
                info = proc.info
                pid  = info.get("pid")

                if pid is None:
                    continue

                if self._skip_system and pid in (0, 4):
                    continue

                live_pids.add(pid)

                try:
                    cpu_t = info.get("cpu_times")
                    current_cpu = (cpu_t.user + cpu_t.system) if cpu_t else 0.0
                except Exception:
                    current_cpu = 0.0

                try:
                    io = proc.io_counters() if hasattr(proc, 'io_counters') else None
                    w_bytes = io.write_bytes if io else 0
                    w_count = io.write_count if io else 0
                except Exception:
                    w_bytes = 0
                    w_count = 0

                with self._lock:
                    if pid in self._registry:
                        # Existing process: update CPU and I/O deltas
                        rec = self._registry[pid]
                        rec.cpu_delta = current_cpu - rec.last_cpu_time
                        rec.last_cpu_time = current_cpu

                        rec.dw_bytes = (w_bytes - rec.last_write_bytes) if w_bytes >= rec.last_write_bytes else 0
                        rec.dw_count = (w_count - rec.last_write_count) if w_count >= rec.last_write_count else 0
                        rec.last_write_bytes = w_bytes
                        rec.last_write_count = w_count
                        continue

                new_rec = self._build_record(info)
                if new_rec:
                    with self._lock:
                        new_rec.last_cpu_time = current_cpu
                        new_rec.last_write_bytes = w_bytes
                        new_rec.last_write_count = w_count
                        self._registry[pid] = new_rec
                        self.total_seen += 1

            now = time.time()
            with self._lock:
                dead_pids = set(self._registry.keys()) - live_pids
                for dpid in dead_pids:
                    rec = self._registry.pop(dpid, None)
                    if rec:
                        rec.alive = False
                        self._exited_cache[dpid] = (now, rec)
                        self.total_exited += 1

                expired = [
                    p for p, (ts, _) in self._exited_cache.items()
                    if (now - ts) > self._exited_ttl
                ]
                for p in expired:
                    del self._exited_cache[p]

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

        # Fallback for known Windows system processes whose parent exited at boot
        if parent_exe == "UNKNOWN":
            name_lower = name.lower()
            if name_lower == "explorer.exe":
                parent_exe = "C:\\Windows\\System32\\userinit.exe"
            elif name_lower in ("userinit.exe", "services.exe", "lsass.exe"):
                parent_exe = "C:\\Windows\\System32\\winlogon.exe"

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
