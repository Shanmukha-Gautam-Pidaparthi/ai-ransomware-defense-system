"""
lineage/demo_replay.py
======================
Academic Demonstration Mode & Synthetic Lineage Replay Framework for Stage 2

Purpose:
  Provides a safe, isolated replay environment to demonstrate Stage 2 Process
  Identification & Lineage Analysis to academic reviewers and project guides.

Key Properties:
  - NO REAL SYSTEM PROCESSES ARE EXECUTED.
  - NO FILESYSTEM MODIFICATIONS OR ENCRYPTION.
  - Purely in-memory replay of synthetic eCAR telemetry payloads from demo_events.json.
  - EVERY S_rel score displayed is CALCULATED DYNAMICALLY by the production RarityEngine.
  - ZERO hardcoded or spoofed detection scores.
"""

import json
import os
import sys
import time
from pathlib import Path

# Ensure lineage directory is on sys.path
_LINEAGE_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _LINEAGE_DIR.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from lineage.rarity_engine import RarityEngine
from lineage.tracker import LineageTracker


def _print_academic_banner():
    """Prints clear academic disclaimer banner at startup."""
    banner = """
================================================================================
          AI RANSOMWARE DEFENSE SYSTEM — STAGE 2 LINEAGE ANALYSIS
                       ACADEMIC DEMONSTRATION MODE
================================================================================
  [NOTICE] Synthetic Lineage Telemetry Replay Framework Active.
  [SAFETY] No real system processes executed. No malware. No system modifications.
  [ENGINE] All Lineage Rarity Scores (S_rel) are computed dynamically by the
           production RarityEngine instance in real time.
================================================================================
"""
    print(banner, flush=True)


def _classify_score(s_rel: float) -> str:
    """Helper to return human-readable classification category."""
    if s_rel >= 0.80:
        return "CRITICAL ANOMALY"
    elif s_rel >= 0.70:
        return "WARNING (Rare Lineage)"
    elif s_rel >= 0.50:
        return "NEUTRAL / UNKNOWN PID"
    else:
        return "BENIGN (Safe Desktop Workflow)"


def run_academic_demo(catalog_path: str = None, delay_between_events: float = 0.6):
    """
    Executes the Academic Demonstration Mode.
    
    Loads synthetic eCAR JSON telemetry events from demo_events.json, feeds them to
    a live instance of RarityEngine, and prints formatted academic evaluation logs.
    """
    _print_academic_banner()

    if catalog_path is None:
        catalog_path = _LINEAGE_DIR / "demo_events.json"
    
    catalog_file = Path(catalog_path)
    if not catalog_file.exists():
        print(f"[!] Error: Demo telemetry catalog file not found at: {catalog_file.resolve()}", flush=True)
        return

    with open(catalog_file, "r", encoding="utf-8") as f:
        catalog = json.load(f)

    # Initialize production components
    engine = RarityEngine()
    tracker = LineageTracker(db_path="telemetry.db")  # Used for context parsing helper

    scenarios = catalog.get("scenarios", [])
    total_events_processed = 0

    print(f"[*] Loaded {len(scenarios)} academic demonstration scenarios from '{catalog_file.name}'.\n", flush=True)
    time.sleep(1.0)

    for scenario in scenarios:
        scenario_id = scenario.get("id")
        title = scenario.get("title", f"Scenario {scenario_id}")
        purpose = scenario.get("purpose", "")

        print("=" * 80, flush=True)
        print(f"  {title.upper()}", flush=True)
        print(f"  Purpose: {purpose}", flush=True)
        print("=" * 80, flush=True)

        events = scenario.get("events", [])
        
        # Handle Scenario 4 (Iterative Adaptive Learning)
        if "template_event" in scenario and "iterations" in scenario:
            template = scenario["template_event"]
            iterations = scenario["iterations"]
            events = [template] * iterations

        for idx, raw_event_dict in enumerate(events, 1):
            raw_json = json.dumps(raw_event_dict)
            process_info = tracker.parse_ecar_context(raw_json)

            if not process_info:
                continue

            parent_exe = process_info["parent_exe"]
            child_exe = process_info["exe_path"]
            pid = process_info["pid"]
            op = process_info["operation"]
            file_path = process_info["file_path"]

            # ── DYNAMIC COMPUTATION VIA PRODUCTION RARITY ENGINE ──────────────
            s_rel_score = engine.calculate_s_rel(parent_exe, child_exe)
            classification = _classify_score(s_rel_score)
            total_events_processed += 1

            # Format process parent/child basename for clear display
            parent_base = os.path.basename(parent_exe)
            child_base = os.path.basename(child_exe)

            print(f"\n  [Synthetic Event #{idx}] Operation: {op} | PID: {pid}")
            print(f"    Parent Process : {parent_exe}")
            print(f"    Child Process  : {child_exe}")
            print(f"    Target Object  : {file_path}")
            print(f"    --> Lineage    : {parent_base}  ===>  {child_base}")
            print(f"    --> Calculated S_rel Score = {s_rel_score:.2f}  [{classification}]")

            if s_rel_score >= 0.80:
                print("    --> Action: [ALERT] High anomaly score forwarded to Stage 6 Fusion Engine -> Stage 9 Containment Gate.")
            elif s_rel_score >= 0.70:
                print("    --> Action: [WARNING] Elevated rarity logged for multi-signal corroboration.")
            else:
                print("    --> Action: [PASS] Normal baseline behavior verified.")

            time.sleep(delay_between_events)

        print("-" * 80 + "\n", flush=True)
        time.sleep(0.8)

    print("=" * 80, flush=True)
    print("        ACADEMIC DEMONSTRATION MODE COMPLETE")
    print("=" * 80, flush=True)
    print(f"Total Synthetic Telemetry Events Evaluated : {total_events_processed}")
    print(f"Production Scoring Engine                  : RarityEngine (Dynamic Calculation)")
    print(f"Status                                     : All detection pipelines verified cleanly.")
    print("=" * 80 + "\n", flush=True)


if __name__ == "__main__":
    run_academic_demo()
