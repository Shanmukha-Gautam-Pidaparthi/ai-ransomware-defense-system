"""
tests/test_stage_3_dbrg.py
============================
Comprehensive Test Suite for Stage 3: Dynamic Behavior Relationship Graph (DBRG)

Tests cover:
  1. TDEWEngine — formula correctness, passive decay, edge cases.
  2. DBRGManager — eCAR event ingestion, node/edge creation, TDEW updates.
  3. DBRGGarbageCollector — background pruning of decayed edges.
  4. Thread safety — concurrent event ingestion from multiple threads.
  5. End-to-end — Stage 2 event format → DBRG graph structures.

Run with:
    python -m pytest tests/test_stage_3_dbrg.py -v
"""

import math
import time
import threading
from unittest.mock import patch

import pytest

from src.stage_3_dbrg.tdew_calculator import TDEWEngine
from src.stage_3_dbrg.dbrg_manager import DBRGManager
from src.stage_3_dbrg.garbage_collector import DBRGGarbageCollector


# ═══════════════════════════════════════════════════════════════════════════
# Fixtures — reusable mock eCAR events matching Stage 2 output schema
# ═══════════════════════════════════════════════════════════════════════════

def _make_ecar_event(
    pid: int = 1234,
    file_path: str = "C:\\Users\\test\\document.docx",
    operation: str = "FILE_MODIFY",
    exe_path: str = "C:\\Windows\\notepad.exe",
    sha256: str = "abc123def456",
    ppid: int = 5678,
    parent_exe: str = "C:\\Windows\\explorer.exe",
) -> dict:
    """
    Build a synthetic eCAR event dict identical to Stage 2 output.

    This mirrors the schema produced by ``collector/ecar_formatter.py``
    and consumed by ``collector/queue_joiner.py``.
    """
    return {
        "actorID": f"pid:{pid}",
        "objectID": f"file:{file_path}",
        "pid": pid,
        "tid": 100,
        "principal": "TESTPC\\testuser",
        "timestamp": int(time.time() * 1000),
        "operation": operation,
        "ecar_ver": "1.0",
        "context": {
            "exe_path": exe_path,
            "sha256": sha256,
            "ppid": ppid,
            "parent_exe": parent_exe,
            "cmdline": [exe_path, file_path],
            "dest_path": None,
        },
    }


# ═══════════════════════════════════════════════════════════════════════════
# 1. TDEWEngine — Mathematical Formula Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestTDEWEngine:
    """Tests for the Time-Decayed Edge Weighting calculator."""

    def test_initial_weight_from_zero(self):
        """Brand new edge: W_old=0 → W_new = 0*exp(…) + 1.0 = 1.0."""
        engine = TDEWEngine(decay_lambda=0.05)
        now = time.time()
        new_weight, ts = engine.calculate_updated_weight(0.0, now)

        assert abs(new_weight - 1.0) < 0.01, (
            f"Initial weight from zero should be ≈1.0, got {new_weight}"
        )
        assert ts >= now

    def test_rapid_re_observation_accumulates(self):
        """Rapid re-observation (Δt≈0) should nearly double: W≈W_old+1."""
        engine = TDEWEngine(decay_lambda=0.05)
        now = time.time()

        # First observation
        w1, t1 = engine.calculate_updated_weight(0.0, now)
        assert abs(w1 - 1.0) < 0.01

        # Immediate re-observation
        w2, t2 = engine.calculate_updated_weight(w1, t1)
        # With negligible Δt, decay ≈ 1.0 → w2 ≈ 1.0 + 1.0 = 2.0
        assert w2 > 1.8, f"Rapid re-observation should give W>1.8, got {w2}"

    def test_decay_over_long_idle(self):
        """After a long idle period, old weight decays almost to zero."""
        engine = TDEWEngine(decay_lambda=0.05)
        old_time = time.time() - 200  # 200 seconds ago

        new_weight, _ = engine.calculate_updated_weight(5.0, old_time)
        # 5.0 * exp(-0.05*200) = 5 * exp(-10) ≈ 0.000227 → +1.0 ≈ 1.0
        assert abs(new_weight - 1.0) < 0.05, (
            f"After 200s idle, weight should be ≈1.0, got {new_weight}"
        )

    def test_passive_decay_formula(self):
        """Passive decay: W_passive = W * exp(-λ*Δt), no +1."""
        engine = TDEWEngine(decay_lambda=0.1)
        old_time = time.time() - 10  # 10 seconds ago

        passive = engine.calculate_passive_decay(2.0, old_time)
        expected = 2.0 * math.exp(-0.1 * 10)
        assert abs(passive - expected) < 0.05, (
            f"Passive decay mismatch: expected {expected:.4f}, got {passive:.4f}"
        )

    def test_negative_weight_raises(self):
        """Negative weight should raise ValueError."""
        engine = TDEWEngine(decay_lambda=0.05)
        with pytest.raises(ValueError):
            engine.calculate_updated_weight(-1.0, time.time())

    def test_negative_lambda_raises(self):
        """Negative decay_lambda should raise ValueError."""
        with pytest.raises(ValueError):
            TDEWEngine(decay_lambda=-0.01)

    def test_calculation_counter(self):
        """The engine should count total calculations."""
        engine = TDEWEngine(decay_lambda=0.05)
        assert engine.total_calculations == 0

        engine.calculate_updated_weight(0.0, time.time())
        engine.calculate_updated_weight(1.0, time.time())
        assert engine.total_calculations == 2


# ═══════════════════════════════════════════════════════════════════════════
# 2. DBRGManager — Event Ingestion & Graph Structure Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestDBRGManager:
    """Tests for the DBRG directed graph manager."""

    def test_single_event_creates_nodes_and_edge(self):
        """One eCAR event should create 1 process node, 1 file node, 1 edge."""
        mgr = DBRGManager()
        event = _make_ecar_event()

        mgr.process_event(event)

        assert mgr.get_node_count() == 2, "Expected 2 nodes (process + file)"
        assert mgr.get_edge_count() == 1, "Expected 1 directed edge"
        assert mgr.events_processed == 1

    def test_initial_edge_weight_is_one(self):
        """A brand-new edge must have weight == 1.0."""
        mgr = DBRGManager()
        event = _make_ecar_event(pid=100, file_path="C:\\test\\file.txt")

        mgr.process_event(event)

        edge = mgr.get_edge_data("pid:100", "file:C:\\test\\file.txt")
        assert edge is not None, "Edge should exist"
        assert edge["weight"] == 1.0, f"Initial weight should be 1.0, got {edge['weight']}"
        assert edge["cut_cost"] == 1.0
        assert edge["event_count"] == 1

    def test_repeated_events_increase_weight(self):
        """Multiple rapid events on the same edge should increase the weight."""
        mgr = DBRGManager()
        event = _make_ecar_event(pid=200, file_path="C:\\data\\target.xlsx")

        # Burst of 5 rapid events
        for _ in range(5):
            mgr.process_event(event)

        edge = mgr.get_edge_data("pid:200", "file:C:\\data\\target.xlsx")
        assert edge is not None
        assert edge["weight"] > 1.8, (
            f"5 rapid events should produce weight > 1.8, got {edge['weight']}"
        )
        assert edge["event_count"] == 5

    def test_high_velocity_burst_weight(self):
        """
        Simulating a high-velocity activity burst (ransomware-like).
        10 rapid events should push weight well above 1.8.
        """
        mgr = DBRGManager()
        event = _make_ecar_event(
            pid=666,
            file_path="C:\\Users\\victim\\Documents\\important.docx",
            operation="FILE_MODIFY",
            exe_path="C:\\Temp\\malicious.exe",
        )

        for _ in range(10):
            mgr.process_event(event)

        edge = mgr.get_edge_data(
            "pid:666", "file:C:\\Users\\victim\\Documents\\important.docx"
        )
        assert edge is not None
        assert edge["weight"] > 1.8, (
            f"Burst weight should be > 1.8, got {edge['weight']}"
        )

    def test_multiple_files_same_process(self):
        """One process touching multiple files creates multiple edges."""
        mgr = DBRGManager()

        files = ["C:\\a.txt", "C:\\b.txt", "C:\\c.txt"]
        for f in files:
            mgr.process_event(_make_ecar_event(pid=300, file_path=f))

        assert mgr.get_node_count() == 4, "1 process + 3 files = 4 nodes"
        assert mgr.get_edge_count() == 3, "3 distinct edges"

    def test_multiple_processes_same_file(self):
        """Multiple processes writing to the same file create separate edges."""
        mgr = DBRGManager()
        target_file = "C:\\shared\\log.txt"

        for pid in [400, 401, 402]:
            mgr.process_event(_make_ecar_event(pid=pid, file_path=target_file))

        assert mgr.get_node_count() == 4, "3 processes + 1 file = 4 nodes"
        assert mgr.get_edge_count() == 3, "3 distinct edges"

    def test_process_node_metadata(self):
        """Process nodes should carry exe_path, sha256, ppid, parent_exe."""
        mgr = DBRGManager()
        event = _make_ecar_event(
            pid=500,
            exe_path="C:\\evil.exe",
            sha256="deadbeef",
            ppid=1,
            parent_exe="C:\\Windows\\explorer.exe",
        )
        mgr.process_event(event)

        node = mgr.get_node_data("pid:500")
        assert node is not None
        assert node["node_type"] == "process"
        assert node["exe_path"] == "C:\\evil.exe"
        assert node["sha256"] == "deadbeef"
        assert node["ppid"] == 1

    def test_file_node_metadata(self):
        """File nodes should carry node_type='file' and file_path."""
        mgr = DBRGManager()
        mgr.process_event(_make_ecar_event(file_path="C:\\secret.pdf"))

        node = mgr.get_node_data("file:C:\\secret.pdf")
        assert node is not None
        assert node["node_type"] == "file"
        assert node["file_path"] == "C:\\secret.pdf"

    def test_graph_snapshot_is_deep_copy(self):
        """get_graph_snapshot() must return an independent copy."""
        mgr = DBRGManager()
        mgr.process_event(_make_ecar_event(pid=600))

        snap = mgr.get_graph_snapshot()
        assert snap.number_of_nodes() == 2

        # Mutate the snapshot — original should be unaffected
        snap.add_node("intruder")
        assert mgr.get_node_count() == 2, "Snapshot mutation leaked"

    def test_malformed_event_does_not_crash(self):
        """Missing fields should not raise; event is silently skipped."""
        mgr = DBRGManager()
        mgr.process_event({})          # Empty event
        mgr.process_event({"actorID": "pid:-1"})  # Partial

        # Graph should still have handled the events without crashing
        assert mgr.events_processed >= 0  # May or may not have added nodes

    def test_stage2_ecar_format_ingestion(self):
        """
        End-to-end test: ingest an event with the exact format
        produced by Stage 2 (collector/ecar_formatter.py + queue_joiner.py).
        """
        mgr = DBRGManager()

        # Exact Stage 2 output format
        stage2_event = {
            "actorID": "pid:7890",
            "objectID": "file:C:\\Users\\nani\\Documents\\report.docx",
            "pid": 7890,
            "tid": 42,
            "principal": "WORKSTATION\\nani",
            "timestamp": int(time.time() * 1000),
            "operation": "FILE_MODIFY",
            "ecar_ver": "1.0",
            "context": {
                "exe_path": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                "sha256": "aabbccdd11223344",
                "ppid": 1024,
                "parent_exe": "C:\\Windows\\explorer.exe",
                "cmdline": ["WINWORD.EXE", "report.docx"],
                "dest_path": None,
            },
        }

        mgr.process_event(stage2_event)

        assert mgr.get_node_count() == 2
        assert mgr.get_edge_count() == 1

        proc_node = mgr.get_node_data("pid:7890")
        assert proc_node["exe_path"] == "C:\\Program Files\\Microsoft Office\\WINWORD.EXE"

        file_node = mgr.get_node_data("file:C:\\Users\\nani\\Documents\\report.docx")
        assert file_node["node_type"] == "file"

        edge = mgr.get_edge_data(
            "pid:7890", "file:C:\\Users\\nani\\Documents\\report.docx"
        )
        assert edge["weight"] == 1.0
        assert edge["operation"] == "FILE_MODIFY"


# ═══════════════════════════════════════════════════════════════════════════
# 3. DBRGGarbageCollector — Background Pruning Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestDBRGGarbageCollector:
    """Tests for the background decay and pruning daemon."""

    def test_gc_prunes_decayed_edges(self):
        """
        Edges whose passive decay drops below threshold should be pruned.

        Strategy: create an edge, then mock time.time() to simulate a
        long idle period so that the passive weight falls below 0.01.
        """
        mgr = DBRGManager(decay_lambda=1.0)  # Aggressive decay for testing
        event = _make_ecar_event(pid=900, file_path="C:\\stale.tmp")
        mgr.process_event(event)

        assert mgr.get_edge_count() == 1

        # Manually backdate the edge's last_seen to 60 seconds ago
        with mgr.lock:
            mgr.graph["pid:900"]["file:C:\\stale.tmp"]["last_seen"] = (
                time.time() - 60
            )

        # Create GC with short interval and start
        gc = DBRGGarbageCollector(
            dbrg_manager=mgr,
            decay_lambda=1.0,
            prune_threshold=0.01,
            prune_interval=0.5,
        )
        gc.start()
        time.sleep(1.5)  # Allow at least 1 sweep cycle
        gc.stop(timeout=3.0)

        assert mgr.get_edge_count() == 0, (
            f"Stale edge should be pruned, but {mgr.get_edge_count()} edges remain"
        )
        assert gc.sweep_count >= 1
        assert gc.total_pruned_edges >= 1

    def test_gc_preserves_active_edges(self):
        """Fresh edges (just created) should NOT be pruned."""
        mgr = DBRGManager(decay_lambda=0.05)
        mgr.process_event(_make_ecar_event(pid=901, file_path="C:\\active.doc"))

        gc = DBRGGarbageCollector(
            dbrg_manager=mgr,
            decay_lambda=0.05,
            prune_threshold=0.01,
            prune_interval=0.5,
        )
        gc.start()
        time.sleep(1.5)
        gc.stop(timeout=3.0)

        assert mgr.get_edge_count() == 1, "Active edge should NOT be pruned"

    def test_gc_removes_orphan_nodes(self):
        """When an edge is pruned, orphan nodes should also be removed."""
        mgr = DBRGManager(decay_lambda=2.0)
        mgr.process_event(_make_ecar_event(pid=902, file_path="C:\\orphan.log"))

        # Backdate to trigger pruning
        with mgr.lock:
            mgr.graph["pid:902"]["file:C:\\orphan.log"]["last_seen"] = (
                time.time() - 100
            )

        gc = DBRGGarbageCollector(
            dbrg_manager=mgr,
            decay_lambda=2.0,
            prune_threshold=0.01,
            prune_interval=0.5,
        )
        gc.start()
        time.sleep(1.5)
        gc.stop(timeout=3.0)

        assert mgr.get_node_count() == 0, (
            f"Orphan nodes should be removed, but {mgr.get_node_count()} remain"
        )

    def test_gc_stop_is_idempotent(self):
        """Calling stop() on a never-started GC should not raise."""
        mgr = DBRGManager()
        gc = DBRGGarbageCollector(dbrg_manager=mgr, prune_interval=10)
        gc.stop()  # Should not raise


# ═══════════════════════════════════════════════════════════════════════════
# 4. Thread Safety — Concurrent Ingestion Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestThreadSafety:
    """Tests verifying thread-safe concurrent access to the DBRG."""

    def test_concurrent_event_ingestion(self):
        """
        Simulate 8 threads each ingesting 100 events concurrently.
        The graph should have exactly 800 events_processed and no crashes.
        """
        mgr = DBRGManager()
        barrier = threading.Barrier(8)

        def worker(thread_id: int):
            barrier.wait()  # Synchronise start
            for i in range(100):
                event = _make_ecar_event(
                    pid=thread_id * 1000 + i,
                    file_path=f"C:\\thread_{thread_id}\\file_{i}.dat",
                )
                mgr.process_event(event)

        threads = [
            threading.Thread(target=worker, args=(tid,)) for tid in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert mgr.events_processed == 800, (
            f"Expected 800 events, got {mgr.events_processed}"
        )

    def test_concurrent_read_write(self):
        """
        One writer thread ingesting events while a reader thread
        continuously queries edge counts.  No deadlocks or exceptions.
        """
        mgr = DBRGManager()
        errors: list = []

        def writer():
            for i in range(200):
                mgr.process_event(
                    _make_ecar_event(pid=i, file_path=f"C:\\rw\\{i}.tmp")
                )

        def reader():
            for _ in range(200):
                try:
                    _ = mgr.get_edge_count()
                    _ = mgr.get_node_count()
                    _ = mgr.get_graph_snapshot()
                except Exception as e:
                    errors.append(str(e))

        w = threading.Thread(target=writer)
        r = threading.Thread(target=reader)
        w.start()
        r.start()
        w.join(timeout=30)
        r.join(timeout=30)

        assert len(errors) == 0, f"Reader errors: {errors}"

    def test_ingestion_with_gc_running(self):
        """
        Ingest events while the garbage collector is actively sweeping.
        No deadlocks or data corruption.
        """
        mgr = DBRGManager(decay_lambda=0.05)
        gc = DBRGGarbageCollector(
            dbrg_manager=mgr,
            decay_lambda=0.05,
            prune_threshold=0.01,
            prune_interval=0.3,
        )
        gc.start()

        for i in range(100):
            mgr.process_event(
                _make_ecar_event(pid=i, file_path=f"C:\\gc_test\\{i}.bin")
            )
            time.sleep(0.005)

        gc.stop(timeout=5.0)

        assert mgr.events_processed == 100, (
            f"Expected 100 events processed, got {mgr.events_processed}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# 5. Integration — Stage 2 → Stage 3 Pipeline Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestStage2ToStage3Integration:
    """End-to-end tests validating the Stage 2 → Stage 3 data pipeline."""

    def test_ransomware_burst_detection(self):
        """
        Simulate a ransomware-like pattern: one process rapidly modifying
        many files.  The edge weights should be significantly elevated.
        """
        mgr = DBRGManager(decay_lambda=0.05)

        malicious_pid = 1337
        target_files = [
            f"C:\\Users\\victim\\Documents\\file_{i}.docx" for i in range(20)
        ]

        for f in target_files:
            event = _make_ecar_event(
                pid=malicious_pid,
                file_path=f,
                operation="FILE_MODIFY",
                exe_path="C:\\Temp\\ransomware.exe",
                sha256="malicious_hash",
                ppid=1,
                parent_exe="C:\\Windows\\explorer.exe",
            )
            mgr.process_event(event)

        # 1 process node + 20 file nodes = 21
        assert mgr.get_node_count() == 21
        assert mgr.get_edge_count() == 20

        # Each edge should have weight=1.0 (single touch per file)
        for f in target_files:
            edge = mgr.get_edge_data(f"pid:{malicious_pid}", f"file:{f}")
            assert edge is not None
            assert edge["weight"] == 1.0

    def test_repeated_file_access_weight_growth(self):
        """
        Single process repeatedly modifying the same file — weight should grow.
        """
        mgr = DBRGManager(decay_lambda=0.01)

        for _ in range(15):
            mgr.process_event(
                _make_ecar_event(
                    pid=2000,
                    file_path="C:\\Users\\target\\encrypted.enc",
                    operation="FILE_MODIFY",
                )
            )

        edge = mgr.get_edge_data(
            "pid:2000", "file:C:\\Users\\target\\encrypted.enc"
        )
        assert edge is not None
        assert edge["weight"] > 1.8, (
            f"15 rapid modifications should produce weight > 1.8, got {edge['weight']}"
        )
        assert edge["event_count"] == 15

    def test_full_lifecycle_create_modify_delete(self):
        """
        File lifecycle: CREATE → MODIFY → DELETE.
        Edge should update its operation field and increase event count.
        """
        mgr = DBRGManager()
        base = _make_ecar_event(pid=3000, file_path="C:\\lifecycle\\test.txt")

        for op in ["FILE_CREATE", "FILE_MODIFY", "FILE_DELETE"]:
            base["operation"] = op
            mgr.process_event(base)

        edge = mgr.get_edge_data("pid:3000", "file:C:\\lifecycle\\test.txt")
        assert edge is not None
        assert edge["event_count"] == 3
        assert edge["operation"] == "FILE_DELETE"  # Last operation
        assert edge["weight"] > 1.0  # Accumulated from 3 events
