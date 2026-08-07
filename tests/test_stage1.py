"""
tests/test_stage1.py
=====================
Stage 1 — Unit Tests

Tests verify each sub-component in isolation using temporary files and
in-memory structures. No real monitored paths are modified.

Run with:
    cd H:/Final_year_project/ai-ransomware-defense-system
    pytest tests/test_stage1.py -v

Requirements:
    pip install pytest watchdog psutil pyyaml
"""

import json
import os
import queue
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

# ── Ensure project root is importable ────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ─── Test 1: eCAR Formatter ──────────────────────────────────────────────────

class TestECARFormatter:

    def test_required_keys_present(self):
        """eCAR event must contain all required schema keys."""
        from collector.ecar_formatter import format_event

        evt = format_event(
            file_path    = "C:/Users/kalya/Downloads/test.txt",
            operation    = "created",
            timestamp_ms = 1000000,
            tid          = 12345,
            pid          = 99,
            exe_path     = "C:/Program Files/test.exe",
            sha256       = "abc123",
        )

        required_keys = ["actorID", "objectID", "pid", "tid", "principal",
                         "timestamp", "operation", "ecar_ver", "context"]
        for key in required_keys:
            assert key in evt, f"Missing required eCAR key: '{key}'"

    def test_actor_id_format(self):
        """actorID must be formatted as 'pid:<PID>'."""
        from collector.ecar_formatter import format_event

        evt = format_event(
            file_path    = "C:/test.txt",
            operation    = "modified",
            timestamp_ms = 2000000,
            tid          = 1,
            pid          = 42,
        )
        assert evt["actorID"] == "pid:42"

    def test_object_id_format(self):
        """objectID must be formatted as 'file:<path>'."""
        from collector.ecar_formatter import format_event

        evt = format_event(
            file_path    = "C:/Users/test.txt",
            operation    = "deleted",
            timestamp_ms = 3000000,
            tid          = 1,
        )
        assert evt["objectID"] == "file:C:/Users/test.txt"

    def test_operation_mapping(self):
        """Watchdog operation strings must map to canonical eCAR operation names."""
        from collector.ecar_formatter import format_event

        mapping = {
            "created":  "FILE_CREATE",
            "modified": "FILE_MODIFY",
            "deleted":  "FILE_DELETE",
            "moved":    "FILE_MOVE",
        }
        for op_in, op_out in mapping.items():
            evt = format_event("C:/f.txt", op_in, 1, 1)
            assert evt["operation"] == op_out, (
                f"Expected '{op_out}' for input '{op_in}', got '{evt['operation']}'"
            )

    def test_context_contains_sha256(self):
        """Context must contain sha256 key."""
        from collector.ecar_formatter import format_event

        evt = format_event(
            file_path    = "C:/a.txt",
            operation    = "created",
            timestamp_ms = 1,
            tid          = 1,
            sha256       = "deadbeef",
        )
        assert evt["context"]["sha256"] == "deadbeef"

    def test_serialize_deserialize_roundtrip(self):
        """Serialized and deserialized event must be identical."""
        from collector.ecar_formatter import format_event, serialize, deserialize

        evt  = format_event("C:/round.txt", "created", 9999, 1, pid=7)
        s    = serialize(evt)
        back = deserialize(s)
        assert evt == back

    def test_now_ms_is_unix_milliseconds(self):
        """now_ms() must return a Unix timestamp in milliseconds (> year 2020)."""
        from collector.ecar_formatter import now_ms

        ts = now_ms()
        # 2020-01-01 in Unix ms = 1577836800000
        assert ts > 1_577_836_800_000, f"Timestamp looks wrong: {ts}"


# ─── Test 2: Process Monitor ─────────────────────────────────────────────────

class TestProcessMonitor:

    def test_captures_current_python_process(self):
        """ProcessMonitor must find the current Python process in its registry."""
        from collector.process_monitor import ProcessMonitor

        pm = ProcessMonitor(poll_interval_sec=999, skip_system_pids=False)
        pm.start()
        time.sleep(0.2)

        current_pid = os.getpid()
        record = pm.get_process_by_pid(current_pid)

        pm.stop()

        assert record is not None, "Current Python process not found in registry"
        assert record.pid == current_pid

    def test_captures_subprocess(self):
        """ProcessMonitor must detect a newly spawned subprocess within 3 seconds."""
        from collector.process_monitor import ProcessMonitor

        pm = ProcessMonitor(poll_interval_sec=0.5, skip_system_pids=False)
        pm.start()

        # Spawn a subprocess that lives for 5 seconds
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(5)"],
        )
        child_pid = proc.pid

        # Wait up to 3 seconds for the monitor to detect it
        deadline = time.monotonic() + 3.0
        found = False
        while time.monotonic() < deadline:
            record = pm.get_process_by_pid(child_pid)
            if record:
                found = True
                break
            time.sleep(0.1)

        proc.terminate()
        proc.wait(timeout=3)
        pm.stop()

        assert found, f"ProcessMonitor did not detect child PID {child_pid} within 3s"

    def test_sha256_hash_computed(self):
        """SHA-256 of the Python interpreter itself must be a valid hex string."""
        from collector.process_monitor import ProcessMonitor

        pm = ProcessMonitor(poll_interval_sec=999, skip_system_pids=False)
        pm.start()
        time.sleep(0.2)

        record = pm.get_process_by_pid(os.getpid())
        pm.stop()

        if record is None:
            pytest.skip("Python process not found in registry")

        sha = record.sha256
        # Must be a 64-char hex string OR a known error prefix
        assert (
            len(sha) == 64 or sha.startswith("HASH_")
        ), f"SHA-256 value unexpected: '{sha}'"

    def test_hash_binary_function(self):
        """_hash_binary must return a 64-char hex digest for an existing file."""
        from collector.process_monitor import _hash_binary

        # Use the Python executable itself as a guaranteed-existing binary
        sha = _hash_binary(sys.executable, timeout_sec=10.0)
        assert len(sha) == 64, f"Expected 64-char hex, got: '{sha}'"

    def test_hash_binary_missing_file(self):
        """_hash_binary must return HASH_ERROR for a non-existent path."""
        from collector.process_monitor import _hash_binary

        sha = _hash_binary("C:/this/does/not/exist.exe", timeout_sec=1.0)
        assert sha.startswith("HASH_ERROR"), f"Expected HASH_ERROR prefix, got: '{sha}'"


# ─── Test 3: File Monitor ────────────────────────────────────────────────────

class TestFileMonitor:

    def test_file_create_event_enqueued(self):
        """Creating a file in a monitored directory must enqueue a FILE_CREATE event."""
        from collector.file_monitor import FileMonitor

        with tempfile.TemporaryDirectory() as tmpdir:
            raw_q  = queue.Queue(maxsize=100)
            fm     = FileMonitor(paths=[tmpdir], recursive=False)
            fm.start(raw_q)
            time.sleep(0.5)  # Allow observer to settle

            test_file = os.path.join(tmpdir, "test_stage1_create.txt")
            with open(test_file, "w") as f:
                f.write("ransomware defense test")

            # Wait up to 4 seconds for event to appear in queue
            event = None
            deadline = time.monotonic() + 4.0
            while time.monotonic() < deadline:
                try:
                    event = raw_q.get(timeout=0.3)
                    if "created" in event.get("operation", "").lower():
                        break
                    event = None
                except queue.Empty:
                    continue

            fm.stop()

        assert event is not None, "FILE_CREATE event was not enqueued within 4 seconds"
        assert event["operation"] == "created"
        assert "test_stage1_create.txt" in event["file_path"]

    def test_file_modify_event_enqueued(self):
        """Modifying a file must enqueue a FILE_MODIFY event."""
        from collector.file_monitor import FileMonitor

        with tempfile.TemporaryDirectory() as tmpdir:
            # Pre-create the file
            test_file = os.path.join(tmpdir, "test_modify.txt")
            with open(test_file, "w") as f:
                f.write("original")

            raw_q = queue.Queue(maxsize=100)
            fm    = FileMonitor(paths=[tmpdir], recursive=False)
            fm.start(raw_q)
            time.sleep(0.5)

            # Clear any creation events from pre-created file
            while not raw_q.empty():
                raw_q.get_nowait()

            # Modify the file
            with open(test_file, "a") as f:
                f.write("modified")

            event = None
            deadline = time.monotonic() + 4.0
            while time.monotonic() < deadline:
                try:
                    event = raw_q.get(timeout=0.3)
                    if "modified" in event.get("operation", "").lower():
                        break
                    event = None
                except queue.Empty:
                    continue

            fm.stop()

        assert event is not None, "FILE_MODIFY event was not enqueued within 4 seconds"
        assert event["operation"] == "modified"

    def test_event_has_required_keys(self):
        """Every raw file event must contain: file_path, operation, tid, timestamp."""
        from collector.file_monitor import FileMonitor

        with tempfile.TemporaryDirectory() as tmpdir:
            raw_q = queue.Queue(maxsize=100)
            fm    = FileMonitor(paths=[tmpdir], recursive=False)
            fm.start(raw_q)
            time.sleep(0.5)

            with open(os.path.join(tmpdir, "keys_test.txt"), "w") as f:
                f.write("test")

            event = None
            deadline = time.monotonic() + 4.0
            while time.monotonic() < deadline:
                try:
                    event = raw_q.get(timeout=0.3)
                    if event:
                        break
                except queue.Empty:
                    continue

            fm.stop()

        assert event is not None, "No event received"
        for key in ["file_path", "operation", "tid", "timestamp"]:
            assert key in event, f"Raw event missing key: '{key}'"


# ─── Test 4: DB Writer ────────────────────────────────────────────────────────

class TestDBWriter:

    def test_db_schema_created(self):
        """DBWriter must create the telemetry_events table on start."""
        from collector.db_writer import DBWriter

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            writer = DBWriter(db_path=db_path, batch_size=10)
            writer.start()
            writer.stop()

            conn   = sqlite3.connect(db_path)
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            conn.close()

            table_names = [t[0] for t in tables]
            assert "telemetry_events" in table_names

        finally:
            os.unlink(db_path)

    def test_event_inserted_and_queryable(self):
        """DBWriter must persist an enqueued eCAR event to SQLite."""
        from collector.db_writer import DBWriter
        from collector.ecar_formatter import format_event

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            writer = DBWriter(db_path=db_path, batch_size=1, wal_mode=False)
            writer.start()

            evt = format_event(
                file_path    = "C:/test_write.txt",
                operation    = "created",
                timestamp_ms = 9999999,
                tid          = 1,
                pid          = 1234,
                sha256       = "cafebabe" * 8,
            )
            writer.enqueue(evt)

            # Give the background thread time to flush
            time.sleep(1.0)
            writer.stop()

            # Verify via direct SQLite query
            conn  = sqlite3.connect(db_path)
            rows  = conn.execute(
                "SELECT * FROM telemetry_events WHERE pid=1234"
            ).fetchall()
            conn.close()

            assert len(rows) == 1, f"Expected 1 row, got {len(rows)}"
            assert rows[0][2] == 1234  # pid column

        finally:
            os.unlink(db_path)

    def test_batch_insert_multiple_events(self):
        """DBWriter must correctly batch-insert multiple events."""
        from collector.db_writer import DBWriter
        from collector.ecar_formatter import format_event

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        N = 25

        try:
            writer = DBWriter(db_path=db_path, batch_size=10, wal_mode=False)
            writer.start()

            for i in range(N):
                evt = format_event(
                    file_path    = f"C:/file_{i}.txt",
                    operation    = "created",
                    timestamp_ms = i * 1000,
                    tid          = 1,
                    pid          = 5000 + i,
                )
                writer.enqueue(evt)

            time.sleep(1.5)
            writer.stop()

            count = writer.count()
            assert count == N, f"Expected {N} rows, got {count}"

        finally:
            os.unlink(db_path)

    def test_wal_mode_enabled(self):
        """When wal_mode=True, the SQLite journal_mode must be WAL."""
        from collector.db_writer import DBWriter

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            writer = DBWriter(db_path=db_path, wal_mode=True)
            writer.start()
            writer.stop()

            conn  = sqlite3.connect(db_path)
            mode  = conn.execute("PRAGMA journal_mode;").fetchone()[0]
            conn.close()

            assert mode.lower() == "wal", f"Expected WAL mode, got: '{mode}'"

        finally:
            try:
                os.unlink(db_path)
                os.unlink(db_path + "-wal")
                os.unlink(db_path + "-shm")
            except FileNotFoundError:
                pass


# ─── Test 5: End-to-End Integration ──────────────────────────────────────────

class TestEndToEnd:
    """
    End-to-end smoke test: create a real file in a temp directory and verify
    the complete Stage 1 pipeline (FileMonitor → QueueJoiner → DBWriter)
    stores the event in SQLite.
    """

    def test_full_pipeline_smoke(self):
        """
        A file creation event must flow through the full Stage 1 pipeline.

        Note: psutil.open_files() on Windows is slow (scans all process handles).
        We wait up to 20 seconds while threads are alive, then flush and verify.
        """
        from collector.file_monitor    import FileMonitor
        from collector.process_monitor import ProcessMonitor
        from collector.queue_joiner    import QueueJoiner
        from collector.db_writer       import DBWriter

        db_fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(db_fd)

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                raw_q  = queue.Queue(maxsize=1000)
                writer = DBWriter(db_path=db_path, batch_size=1, wal_mode=False)
                pm     = ProcessMonitor(poll_interval_sec=0.3, skip_system_pids=True)
                joiner = QueueJoiner(
                    raw_queue        = raw_q,
                    process_monitor  = pm,
                    db_writer        = writer,
                    join_timeout_sec = 0.1,
                )
                fm = FileMonitor(paths=[tmpdir], recursive=False)

                writer.start()
                pm.start()
                joiner.start()
                fm.start(raw_q)
                time.sleep(1.0)  # Let all threads settle

                # Trigger multiple file events to maximise detection chances
                for i in range(5):
                    test_file = os.path.join(tmpdir, f"e2e_test_{i}.txt")
                    with open(test_file, "w") as f:
                        f.write(f"end-to-end stage1 test {i}")
                    time.sleep(0.1)

                # Wait up to 20 seconds while threads are still alive.
                # PID resolution (psutil.open_files across all Windows procs)
                # can take 3-10 seconds on a busy system — this is expected.
                deadline = time.monotonic() + 20.0
                while time.monotonic() < deadline:
                    if writer.count() > 0 or writer.total_written > 0:
                        break
                    time.sleep(0.3)

                # Stop everything — flushes any in-flight events
                fm.stop()
                joiner.stop()
                writer.stop()
                pm.stop()

                # Count includes anything flushed during stop()
                count = writer.total_written
                assert count > 0, (
                    "End-to-end test FAILED: No events were written to the DB.\n"
                    "The full Stage 1 pipeline did not produce a record within 20s.\n"
                    f"QueueJoiner stats: total={joiner.total_events}, "
                    f"joined={joiner.total_joined}, unknown={joiner.total_unknown}"
                )

                # Verify eCAR schema in stored rows
                rows = writer.query_recent(limit=10)
                assert len(rows) > 0, "DB has rows but query_recent returned nothing"
                operations = [r.get("operation", "") for r in rows]
                assert any(
                    op in ("FILE_CREATE", "FILE_MODIFY") for op in operations
                ), f"Expected FILE_CREATE or FILE_MODIFY in DB, found: {operations}"

            finally:
                try:
                    os.unlink(db_path)
                except Exception:
                    pass
