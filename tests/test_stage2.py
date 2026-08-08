"""
tests/test_stage2.py
====================
Comprehensive Test Suite for Stage 2: Process Identification & Lineage Analysis

Tests cover:
  1. RarityEngine safe, self-spawn, malicious (LotL), and unknown transition scoring.
  2. Dynamic frequency ratio calculation (S_rel formula validation).
  3. Case-insensitivity and full path extraction.
  4. LineageTracker eCAR JSON context parsing.
  5. SQLite telemetry database polling, event caching, and lineage tree tracking.
  6. End-to-end integration test (SQLite telemetry_events -> Tracker -> Rarity Engine).
"""

import json
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from lineage.rarity_engine import RarityEngine
from lineage.tracker import LineageTracker


# ─── 1. RarityEngine Tests ───────────────────────────────────────────────────

def test_rarity_engine_known_safe_transitions():
    """Verify that known benign desktop applications produce low S_rel scores."""
    engine = RarityEngine()

    safe_pairs = [
        ("C:\\Windows\\explorer.exe", "C:\\Windows\\notepad.exe"),
        ("C:\\Windows\\explorer.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
        ("C:\\Windows\\System32\\cmd.exe", "C:\\Program Files\\Git\\cmd\\git.exe"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Program Files\\Python314\\python.exe"),
        ("C:\\Program Files\\Microsoft VS Code\\Code.exe", "C:\\Windows\\System32\\cmd.exe"),
    ]

    for parent, child in safe_pairs:
        score = engine.calculate_s_rel(parent, child)
        assert score <= 0.20, f"Expected safe score (<=0.20) for {parent} -> {child}, got {score}"


def test_rarity_engine_self_spawning():
    """Verify that multi-process self-spawns (e.g. Chrome/Brave renderer helper) yield low scores."""
    engine = RarityEngine()

    self_spawn_pairs = [
        ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
        ("C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"),
    ]

    for parent, child in self_spawn_pairs:
        score = engine.calculate_s_rel(parent, child)
        assert score == 0.05, f"Expected 0.05 for self-spawning {parent}, got {score}"


def test_rarity_engine_malicious_lotl_attacks():
    """Verify that Living-off-the-Land (LotL) malicious spawning chains trigger S_rel = 1.0."""
    engine = RarityEngine()

    malicious_pairs = [
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "C:\\Windows\\System32\\cmd.exe"),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "C:\\Windows\\System32\\wscript.exe"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Windows\\System32\\vssadmin.exe"),
        ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\bcdedit.exe"),
    ]

    for parent, child in malicious_pairs:
        score = engine.calculate_s_rel(parent, child)
        assert score == 1.0, f"Expected maximum anomaly score (1.0) for LotL attack {parent} -> {child}, got {score}"


def test_rarity_engine_unknown_and_dropped_pids():
    """Verify neutral score (0.5) when parent or child path is UNKNOWN."""
    engine = RarityEngine()

    assert engine.calculate_s_rel("UNKNOWN", "C:\\Windows\\notepad.exe") == 0.5
    assert engine.calculate_s_rel("C:\\Windows\\explorer.exe", "UNKNOWN") == 0.5
    assert engine.calculate_s_rel("", "") == 0.5


def test_rarity_engine_dynamic_frequency_decay():
    """Verify that repeated observations of unlisted transitions lower the S_rel score over time."""
    engine = RarityEngine()

    parent = "C:\\CustomApp\\custom_parent.exe"
    child = "C:\\CustomApp\\custom_worker.exe"

    # First observation should be higher (rarer)
    score1 = engine.calculate_s_rel(parent, child)
    
    # Observe 50 times
    for _ in range(50):
        score_last = engine.calculate_s_rel(parent, child)

    # High frequency observation should reduce rarity score
    assert score_last < score1, f"Expected score to decrease with frequency (first={score1}, last={score_last})"


# ─── 2. LineageTracker Context Parsing Tests ─────────────────────────────────

def test_tracker_parse_ecar_context_valid():
    """Verify correct parsing of structured eCAR JSON context."""
    tracker = LineageTracker(db_path=":memory:")

    payload = json.dumps({
        "actorID": "pid:1234",
        "objectID": "file:C:\\test\\file_1.txt",
        "pid": 1234,
        "operation": "FILE_MODIFY",
        "context": {
            "exe_path": "C:\\Windows\\notepad.exe",
            "ppid": 5678,
            "parent_exe": "C:\\Windows\\explorer.exe",
            "sha256": "a1b2c3d4e5f67890",
        }
    })

    parsed = tracker.parse_ecar_context(payload)
    assert parsed is not None
    assert parsed["pid"] == 1234
    assert parsed["exe_path"] == "C:\\Windows\\notepad.exe"
    assert parsed["ppid"] == 5678
    assert parsed["parent_exe"] == "C:\\Windows\\explorer.exe"
    assert parsed["operation"] == "FILE_MODIFY"
    assert parsed["file_path"] == "C:\\test\\file_1.txt"


def test_tracker_parse_ecar_context_malformed():
    """Verify resilient handling of invalid JSON or missing fields."""
    tracker = LineageTracker(db_path=":memory:")

    assert tracker.parse_ecar_context("INVALID_JSON") is None

    empty_parsed = tracker.parse_ecar_context("{}")
    assert empty_parsed is not None
    assert empty_parsed["pid"] is None
    assert empty_parsed["exe_path"] == "UNKNOWN"


# ─── 3. LineageTracker Database & Polling Integration Tests ───────────────────

def test_tracker_sqlite_database_polling():
    """Test polling new events from SQLite telemetry_events table."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        # Initialize SQLite database schema matching Stage 1 DBWriter
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE telemetry_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                operation TEXT,
                file_path TEXT,
                pid INTEGER,
                exe_path TEXT,
                raw_json TEXT
            )
        """)

        # Insert 3 mock telemetry events
        events_data = [
            (1000, "FILE_CREATE", "C:\\test\\file_1.txt", 2001, "C:\\Windows\\notepad.exe",
             json.dumps({"pid": 2001, "operation": "FILE_CREATE", "objectID": "file:C:\\test\\file_1.txt",
                         "context": {"exe_path": "C:\\Windows\\notepad.exe", "ppid": 1000, "parent_exe": "C:\\Windows\\explorer.exe"}})),
            (1005, "FILE_MODIFY", "C:\\test\\file_1.txt", 2001, "C:\\Windows\\notepad.exe",
             json.dumps({"pid": 2001, "operation": "FILE_MODIFY", "objectID": "file:C:\\test\\file_1.txt",
                         "context": {"exe_path": "C:\\Windows\\notepad.exe", "ppid": 1000, "parent_exe": "C:\\Windows\\explorer.exe"}})),
            (1010, "FILE_DELETE", "C:\\test\\file_2.txt", 3002, "C:\\Windows\\System32\\cmd.exe",
             json.dumps({"pid": 3002, "operation": "FILE_DELETE", "objectID": "file:C:\\test\\file_2.txt",
                         "context": {"exe_path": "C:\\Windows\\System32\\cmd.exe", "ppid": 4000, "parent_exe": "C:\\Program Files\\Office\\WINWORD.EXE"}})),
        ]

        conn.executemany(
            "INSERT INTO telemetry_events (timestamp, operation, file_path, pid, exe_path, raw_json) VALUES (?, ?, ?, ?, ?, ?)",
            events_data
        )
        conn.commit()
        conn.close()

        # Run LineageTracker update_tree
        tracker = LineageTracker(db_path=db_path)
        fetched = tracker.update_tree()

        assert len(fetched) == 3
        assert tracker.last_processed_id == 3

        # Verify cached PIDs
        assert 2001 in tracker.process_cache
        assert 3002 in tracker.process_cache
        assert tracker.get_lineage(2001)["parent_exe"] == "C:\\Windows\\explorer.exe"

        # Subsequent poll with no new events should return empty list
        fetched_second = tracker.update_tree()
        assert len(fetched_second) == 0

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_stage2_end_to_end_scoring_pipeline():
    """Full integration: DB event -> Tracker -> RarityEngine scoring."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE telemetry_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER, operation TEXT, file_path TEXT, pid INTEGER, exe_path TEXT, raw_json TEXT
            )
        """)

        # Insert a benign event and a malicious attack event
        conn.execute(
            "INSERT INTO telemetry_events (timestamp, operation, file_path, pid, exe_path, raw_json) VALUES (?, ?, ?, ?, ?, ?)",
            (2000, "FILE_CREATE", "C:\\test\\doc.txt", 500, "notepad.exe",
             json.dumps({"pid": 500, "operation": "FILE_CREATE", "objectID": "file:C:\\test\\doc.txt",
                         "context": {"exe_path": "C:\\Windows\\notepad.exe", "ppid": 100, "parent_exe": "C:\\Windows\\explorer.exe"}}))
        )
        conn.execute(
            "INSERT INTO telemetry_events (timestamp, operation, file_path, pid, exe_path, raw_json) VALUES (?, ?, ?, ?, ?, ?)",
            (2001, "FILE_MODIFY", "C:\\test\\doc.txt", 600, "powershell.exe",
             json.dumps({"pid": 600, "operation": "FILE_MODIFY", "objectID": "file:C:\\test\\doc.txt",
                         "context": {"exe_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ppid": 700, "parent_exe": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"}}))
        )
        conn.commit()
        conn.close()

        tracker = LineageTracker(db_path=db_path)
        engine = RarityEngine()

        events = tracker.update_tree()
        scores = [engine.calculate_s_rel(ev["parent_exe"], ev["exe_path"]) for ev in events]

        # Benign event (explorer -> notepad)
        assert scores[0] <= 0.20
        # Malicious event (word -> powershell)
        assert scores[1] == 1.0

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)
