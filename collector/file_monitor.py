"""
collector/file_monitor.py
==========================
Stage 1 — Async File Interception

Architecture Doc requirements (Stage 1 Key Implementations):
  "Utilizes watchdog.Observer (leveraging Linux inotify or Windows
   ReadDirectoryChangesW) to capture file operations (create, modify,
   rename, delete)."

Algorithmic Steps (from Architecture Doc):
  Step 1: Initialize asynchronous thread-safe event queue Q.
  Step 2: Register kernel file watchdogs on monitored volume paths.
  Step 3: On event e_i — extract file_path, operation_type, thread_id,
          high-resolution timestamp (t_ms).
  Step 4: Enqueue raw event dict into Q (PID join happens in queue_joiner).

Design decisions:
  - Uses watchdog.Observer which internally selects the best OS backend:
      Windows  → WindowsApiObserver  (ReadDirectoryChangesW)
      Linux    → InotifyObserver     (inotify)
  - Raw events are enqueued immediately (NO blocking I/O in handler).
  - High-resolution timestamp uses time.perf_counter_ns() anchored to
    time.time() for a wall-clock millisecond timestamp.
  - The handler captures threading.get_ident() as the TID since watchdog
    does not expose the OS-level TID of the triggering process.
"""

import logging
import queue
import threading
import time
from pathlib import Path
from typing import Dict, Any, List, Optional

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileDeletedEvent,
    FileMovedEvent,
)

logger = logging.getLogger(__name__)


# ─── Timestamp Helper ─────────────────────────────────────────────────────────

# Anchor point: compute the wall-clock offset once at import time.
_PERF_EPOCH_NS: int = time.perf_counter_ns()
_WALL_EPOCH_MS: float = time.time() * 1000.0  # Unix ms at anchor


def _now_ms() -> int:
    """
    Return a high-resolution Unix timestamp in milliseconds.

    Uses perf_counter_ns (monotonic, sub-ms resolution) anchored to the
    system wall clock captured at module import time.
    """
    elapsed_ms = (time.perf_counter_ns() - _PERF_EPOCH_NS) / 1_000_000.0
    return int(_WALL_EPOCH_MS + elapsed_ms)


# ─── Event Handler ────────────────────────────────────────────────────────────

class _RansomwareFileEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler that captures file system events and enqueues them.

    All methods must return as fast as possible — no I/O, no blocking calls.
    Includes a sliding deduplication filter to eliminate Windows ReadDirectoryChangesW
    event spam (e.g. 2-4 identical FILE_MODIFY events within 50ms for a single write).
    """

    def __init__(self, event_queue: queue.Queue, dedup_window_ms: int = 50):
        super().__init__()
        self._queue = event_queue
        self._dedup_window_ms = dedup_window_ms
        self._recent_events: Dict[tuple, int] = {}
        self._lock = threading.Lock()
        self._clean_counter = 0

    def on_created(self, event: FileCreatedEvent) -> None:
        if not event.is_directory:
            self._enqueue(event.src_path, "created")

    def on_modified(self, event: FileModifiedEvent) -> None:
        if not event.is_directory:
            self._enqueue(event.src_path, "modified")

    def on_deleted(self, event: FileDeletedEvent) -> None:
        if not event.is_directory:
            self._enqueue(event.src_path, "deleted")

    def on_moved(self, event: FileMovedEvent) -> None:
        if not event.is_directory:
            self._enqueue(event.src_path, "moved", dest_path=event.dest_path)

    def _enqueue(
        self,
        file_path: str,
        operation: str,
        dest_path: Optional[str] = None,
    ) -> None:
        """
        Build a minimal raw event dict and non-blockingly put it in the queue.
        Applies sliding window deduplication to prevent Windows event spam.
        """
        now = _now_ms()
        norm_path = file_path.lower()
        dedup_key = (norm_path, operation)

        with self._lock:
            last_ts = self._recent_events.get(dedup_key, 0)
            if (now - last_ts) < self._dedup_window_ms:
                # Duplicate event within deduplication window — drop it!
                return
            self._recent_events[dedup_key] = now

            # Periodic cleanup of old keys (every 500 events) to keep dict small
            self._clean_counter += 1
            if self._clean_counter > 500:
                self._clean_counter = 0
                cutoff = now - 1000  # Remove keys older than 1 second
                self._recent_events = {
                    k: v for k, v in self._recent_events.items() if v > cutoff
                }

        raw_event: Dict[str, Any] = {
            "file_path":  file_path,
            "operation":  operation,
            "tid":        threading.get_ident(),
            "timestamp":  now,
            "dest_path":  dest_path,
        }

        try:
            self._queue.put_nowait(raw_event)
        except queue.Full:
            logger.warning(
                f"[FileMonitor] Event queue full — dropping event: "
                f"{operation} @ {file_path}"
            )


# ─── File Monitor ─────────────────────────────────────────────────────────────

class FileMonitor:
    """
    Manages one or more watchdog.Observer watches on configured paths.

    Usage:
        fm = FileMonitor(paths=["C:/Users/kalya/Downloads"], recursive=True)
        fm.start(event_queue)
        # ... running ...
        fm.stop()
    """

    def __init__(
        self,
        paths: List[str],
        recursive: bool = True,
        dedup_window_ms: int = 50,
    ):
        self._paths     = [str(Path(p).expanduser().resolve()) for p in paths]
        self._recursive = recursive
        self._dedup_window_ms = dedup_window_ms
        self._observer: Optional[Observer] = None
        self._handler:  Optional[_RansomwareFileEventHandler] = None

    def start(self, event_queue: queue.Queue) -> None:
        """
        Register watchdog watches on all configured paths and start the observer.
        """
        self._handler  = _RansomwareFileEventHandler(event_queue, dedup_window_ms=self._dedup_window_ms)
        self._observer = Observer()

        valid_paths: List[str] = []
        for path in self._paths:
            if not Path(path).exists():
                logger.warning(f"[FileMonitor] Path does not exist, skipping: {path}")
                continue
            self._observer.schedule(
                self._handler,
                path,
                recursive=self._recursive,
            )
            valid_paths.append(path)
            logger.info(f"[FileMonitor] Watching: {path} (recursive={self._recursive})")

        if not valid_paths:
            raise RuntimeError(
                "[FileMonitor] No valid paths to monitor. "
                "Check your config.yaml monitor.paths entries."
            )

        self._observer.start()
        logger.info(
            f"[FileMonitor] Observer started on {len(valid_paths)} path(s). "
            f"Backend: {type(self._observer).__name__}"
        )

    def stop(self) -> None:
        """Stop the watchdog observer and wait for its thread to exit."""
        if self._observer:
            logger.info("[FileMonitor] Stopping observer...")
            self._observer.stop()
            self._observer.join()
            logger.info("[FileMonitor] Observer stopped.")

    @property
    def monitored_paths(self) -> List[str]:
        """Return the resolved list of paths being monitored."""
        return list(self._paths)

    def is_alive(self) -> bool:
        """Returns True if the observer thread is currently running."""
        return self._observer is not None and self._observer.is_alive()
