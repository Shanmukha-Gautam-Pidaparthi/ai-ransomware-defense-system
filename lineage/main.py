import argparse
import os
import sys
import time
from pathlib import Path

# Ensure lineage directory is on sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from tracker import LineageTracker
from rarity_engine import RarityEngine
from demo_replay import run_academic_demo

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    parser = argparse.ArgumentParser(
        description="AI Ransomware Defense — Stage 2: Process Identification & Lineage Analysis"
    )
    parser.add_argument(
        "--demo", "-d",
        action="store_true",
        help="Run Academic Demonstration Mode using synthetic telemetry replay"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.4,
        help="Delay in seconds between demo events (Default: 0.4s)"
    )
    parser.add_argument(
        "--replay-all",
        action="store_true",
        help="Replay all historical telemetry events from database start instead of live tailing"
    )
    args = parser.parse_args()

    if args.demo:
        run_academic_demo(delay_between_events=args.delay)
        return

    print("[*] Starting Stage 2: Process Identification & Lineage Analysis...", flush=True)
    start_latest = not args.replay_all
    tracker = LineageTracker(db_path="telemetry.db", start_at_latest=start_latest)
    engine = RarityEngine()
    
    mode_str = "LIVE TAILING (Skipping past events)" if start_latest else "FULL DATABASE REPLAY"
    print(f"[*] Connected to database: {tracker.db_path}", flush=True)
    print(f"[*] Mode: {mode_str}", flush=True)
    print(f"[*] Listening for incoming telemetry events from Stage 1...\n", flush=True)

    try:
        while True:
            # 1. Fetch newly discovered process events from Stage 1 Database
            events = tracker.update_tree()
            
            # 2. Score each parent-child chain
            for process in events:
                parent_exe = process["parent_exe"]
                child_exe = process["exe_path"]
                pid = process["pid"]
                op = process.get("operation", "FILE_EVENT")
                file_path = process.get("file_path", "")
                chain = process.get("lineage_chain", [os.path.basename(parent_exe), os.path.basename(child_exe)])
                chain_str = " -> ".join(chain)
                
                # Calculate Lineage Rarity (S_rel)
                s_rel_score = engine.calculate_s_rel(parent_exe, child_exe)
                
                # 3. Alerting & Logging Logic
                if s_rel_score >= 0.8:
                    print(f"[CRITICAL ANOMALY] S_rel: {s_rel_score:.2f} | PID={pid} | {op} | file:{file_path}", flush=True)
                    print(f"    --> Full Provenance Lineage: {chain_str}", flush=True)
                elif s_rel_score >= 0.7:
                    print(f"[WARNING] Rare Lineage (S_rel: {s_rel_score:.2f}) | PID={pid} | Lineage: {chain_str}", flush=True)
                else:
                    print(f"[INFO   ] [Stage 2] {op:<13} | PID={pid:<7} | S_rel={s_rel_score:.2f} (BENIGN) | Lineage: {chain_str} | file:{file_path}", flush=True)
                    
            # Poll every 0.5 seconds to keep up with Stage 1
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[*] Shutting down Stage 2 Lineage Monitor.", flush=True)


if __name__ == "__main__":
    main()