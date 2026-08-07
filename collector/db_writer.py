"""
collector/db_writer.py
=======================
Stage 1 — SQLite Persistence Layer

Writes incoming eCAR telemetry events to a local SQLite database.

Architecture Doc requirements (Stage 1 Minor Implementations):
  - "Writes incoming telemetry streams to local SQLite database tables
     with indexed timestamp keys."

Design decisions:
  - WAL (Write-Ahead Log) mode: concurrent reads (Stage 2+) don't block writes.
  - Batch inserts (configurable batch_size) to reduce I/O overhead.
  - Separate background daemon thread flushes the queue continuously.
  - Indexed on both timestamp (for time-range queries) and pid (for lineage).
  - Thread-safe: uses its own input queue; no external locking required.
"""

import sqlite3
import queue
import threading
import logging
import time
from typing import Dict, Any, Optional

from collector.ecar_formatter import serialize

logger = logging.getLogger(__name__)

# ─── SQL Definitions ──────────────────────────────────────────────────────────

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS telemetry_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL,
    pid         INTEGER,
    tid         INTEGER,
    operation   TEXT,
    object_id   TEXT,
    actor_id    TEXT,
    principal   TEXT,
    sha256      TEXT,
    raw_json    TEXT NOT NULL
);
"""

_CREATE_IDX_TIMESTAMP_SQL = """
CREATE INDEX IF NOT EXISTS idx_timestamp ON telemetry_events(timestamp);
"""

_CREATE_IDX_PID_SQL = """
CREATE INDEX IF NOT EXISTS idx_pid ON telemetry_events(pid);
"""

_INSERT_SQL = """
INSERT INTO telemetry_events
    (timestamp, pid, tid, operation, object_id, actor_id, principal, sha256, raw_json)
VALUES
    (?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

# Sentinel object: when placed in the write_queue, the writer thread exits.
_STOP_SENTINEL = object()


class DBWriter:
    """
    Thread-safe SQLite writer for eCAR telemetry events.

    Usage:
        writer = DBWriter(db_path="telemetry.db", batch_size=50)
        writer.start()
        writer.enqueue(ecar_event_dict)
        ...
        writer.stop()
    """

    def __init__(
        self,
        db_path: str   = "telemetry.db",
        batch_size: int = 500,
        wal_mode: bool  = True,
        queue_maxsize: int = 100000,
    ):
        self.db_path    = db_path
        self.batch_size = batch_size
        self.wal_mode   = wal_mode

        # Internal queue: eCAR dicts arrive here from queue_joiner
        self._write_queue: queue.Queue = queue.Queue(maxsize=queue_maxsize)

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Stats
        self.total_written: int = 0
        self.total_dropped: int = 0

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Initialize the SQLite schema and start the background writer thread."""
        self._init_db()
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._writer_loop,
            name="DBWriter",
            daemon=True,
        )
        self._thread.start()
        logger.info(f"[DBWriter] Started. DB: {self.db_path} | Batch: {self.batch_size}")

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the writer to flush remaining events and stop gracefully."""
        logger.info("[DBWriter] Stop requested — flushing remaining events...")
        self._write_queue.put(_STOP_SENTINEL)
        if self._thread:
            self._thread.join(timeout=timeout)
        logger.info(
            f"[DBWriter] Stopped. Total written: {self.total_written} | "
            f"Dropped: {self.total_dropped}"
        )

    def enqueue(self, ecar_event: Dict[str, Any]) -> bool:
        """
        Thread-safe: put one eCAR event on the write queue.

        Returns True if enqueued, False if the queue is full (event dropped).
        Non-blocking — the caller (queue_joiner) must never be stalled by I/O.
        """
        try:
            self._write_queue.put_nowait(ecar_event)
            return True
        except queue.Full:
            self.total_dropped += 1
            logger.warning(
                f"[DBWriter] Write queue full — event dropped. "
                f"Total dropped: {self.total_dropped}"
            )
            return False

    def query_recent(self, limit: int = 20) -> list:
        """
        Convenience: return the N most recent events from the DB.
        Used by manual verification and tests.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(
                "SELECT * FROM telemetry_events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
            return [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()

    def count(self) -> int:
        """Return total number of events stored in the DB."""
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute(
                "SELECT COUNT(*) FROM telemetry_events"
            ).fetchone()[0]
        finally:
            conn.close()

    # ──────────────────────────────────────────────────────────────────────────
    # Internal
    # ──────────────────────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        """Create table and indexes if they don't already exist."""
        conn = sqlite3.connect(self.db_path)
        try:
            if self.wal_mode:
                conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute(_CREATE_TABLE_SQL)
            conn.execute(_CREATE_IDX_TIMESTAMP_SQL)
            conn.execute(_CREATE_IDX_PID_SQL)
            conn.commit()
            logger.info(f"[DBWriter] Schema initialized at: {self.db_path}")
        finally:
            conn.close()

    def _writer_loop(self) -> None:
        """
        Background thread: drains the write queue and batch-inserts into SQLite.

        Strategy: collect up to `batch_size` events, then commit in one
        transaction. If queue is empty, commit whatever we have and wait.
        """
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        if self.wal_mode:
            conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")  # Safe with WAL

        batch = []

        try:
            while True:
                try:
                    item = self._write_queue.get(timeout=0.5)

                    # Stop sentinel received → flush and exit
                    if item is _STOP_SENTINEL:
                        if batch:
                            self._flush(conn, batch)
                            batch = []
                        break

                    batch.append(item)

                    # Flush when batch is full
                    if len(batch) >= self.batch_size:
                        self._flush(conn, batch)
                        batch = []

                except queue.Empty:
                    # Flush whatever is accumulated on timeout
                    if batch:
                        self._flush(conn, batch)
                        batch = []

        except Exception as exc:
            logger.error(f"[DBWriter] Fatal error in writer loop: {exc}", exc_info=True)
        finally:
            conn.close()

    def _flush(self, conn: sqlite3.Connection, batch: list) -> None:
        """Batch-insert a list of eCAR event dicts into the DB."""
        rows = []
        for evt in batch:
            ctx = evt.get("context", {})
            rows.append((
                evt.get("timestamp"),
                evt.get("pid"),
                evt.get("tid"),
                evt.get("operation"),
                evt.get("objectID"),
                evt.get("actorID"),
                evt.get("principal"),
                ctx.get("sha256"),
                serialize(evt),
            ))

        try:
            conn.executemany(_INSERT_SQL, rows)
            conn.commit()
            self.total_written += len(rows)
            logger.debug(f"[DBWriter] Flushed {len(rows)} events (total: {self.total_written})")
        except sqlite3.Error as exc:
            logger.error(f"[DBWriter] Insert error: {exc}", exc_info=True)
            conn.rollback()
