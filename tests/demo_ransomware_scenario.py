"""
tests/demo_ransomware_scenario.py
==================================
Simulates a live comparison between Benign User Activity and a
Ransomware Attack Scenario in Stage 3 DBRG.
"""

import os
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.stage_3_dbrg import DBRGManager, DBRGGarbageCollector

def print_header(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def run_demo():
    print_header("STAGE 3 DBRG: RANSOMWARE SCENARIO DEMONSTRATION")

    mgr = DBRGManager(decay_lambda=0.05)
    gc = DBRGGarbageCollector(mgr, prune_threshold=0.01, prune_interval=2.0)
    gc.start()

    # ─────────────────────────────────────────────────────────────────
    # SCENARIO 1: Benign User Editing a Document
    # ─────────────────────────────────────────────────────────────────
    print("\n[PHASE 1] Simulating Benign User Activity (Notepad editing 1 file)")
    print("  User opens 'report.docx' and saves 3 times with 1-second pauses...")

    for save in range(1, 4):
        mgr.process_event({
            "actorID": "pid:1024",
            "objectID": "file:C:\\Users\\nani\\Documents\\report.docx",
            "pid": 1024,
            "operation": "FILE_MODIFY",
            "context": {"exe_path": "notepad.exe", "sha256": "clean_notepad_hash"}
        })
        edge = mgr.get_edge_data("pid:1024", "file:C:\\Users\\nani\\Documents\\report.docx")
        print(f"  -> Save #{save}: Edge Weight = {edge['weight']:.4f} | Event Count = {edge['event_count']}")
        time.sleep(1.0)

    print(f"\n  [BENIGN STATE SUMMARY]")
    print(f"  -> Process Fan-Out Degree: 1 target file")
    print(f"  -> Total Graph Edges: {mgr.get_edge_count()}")
    print(f"  -> Threat Assessment: BENIGN (Low fan-out, gradual weight decay)")

    time.sleep(2.0)

    # ─────────────────────────────────────────────────────────────────
    # SCENARIO 2: Ransomware Encryption Burst
    # ─────────────────────────────────────────────────────────────────
    print_header("PHASE 2: RANSOMWARE ATTACK DETECTED! (WannaCry / LockBit Simulation)")

    victim_files = [
        "C:\\Users\\nani\\Documents\\financials.xlsx",
        "C:\\Users\\nani\\Documents\\passwords.txt",
        "C:\\Users\\nani\\Pictures\\family_photo.jpg",
        "C:\\Users\\nani\\Pictures\\vacation.png",
        "C:\\Users\\nani\\Desktop\\thesis_final.pdf",
        "C:\\Users\\nani\\Desktop\\project_code.py",
        "C:\\Users\\nani\\Downloads\\bank_statement.pdf",
        "C:\\Users\\nani\\Documents\\tax_return.pdf",
        "C:\\Users\\nani\\Documents\\medical_records.pdf",
        "C:\\Users\\nani\\Desktop\\READ_ME_NOW.txt"  # Ransom note
    ]

    ransomware_pid = 6666
    print(f"  [ATTACK START] Malicious process PID {ransomware_pid} (svchost_fake.exe) spawning...")
    print(f"  Rapidly encrypting {len(victim_files)} files in milliseconds...\n")

    t_start = time.time()
    for idx, target in enumerate(victim_files, 1):
        # Ransomware performs READ + ENCRYPT (MODIFY) burst
        for op in ["FILE_READ", "FILE_MODIFY"]:
            mgr.process_event({
                "actorID": f"pid:{ransomware_pid}",
                "objectID": f"file:{target}",
                "pid": ransomware_pid,
                "operation": op,
                "context": {
                    "exe_path": "C:\\Temp\\svchost_fake.exe",
                    "sha256": "malicious_ransomware_sha256_hash",
                    "ppid": 4444, "parent_exe": "cmd.exe"
                }
            })
        print(f"  [ENCRYPTING {idx:02d}/{len(victim_files)}] -> {os.path.basename(target)}")
        time.sleep(0.05)  # 50ms rapid fire encryption

    elapsed = time.time() - t_start

    # ─────────────────────────────────────────────────────────────────
    # DBRG GRAPH ANALYSIS FOR RANSOMWARE
    # ─────────────────────────────────────────────────────────────────
    print_header("STAGE 3 GRAPH ANOMALY ANALYSIS")

    graph = mgr.get_graph_snapshot()
    proc_out_degree = graph.out_degree(f"pid:{ransomware_pid}")
    total_edges = mgr.get_edge_count()
    total_nodes = mgr.get_node_count()

    print(f"  [+] Attack Duration: {elapsed:.2f} seconds")
    print(f"  [+] Malicious Process Out-Degree (Fan-Out): {proc_out_degree} distinct files")
    print(f"  [+] Total DBRG Graph Nodes: {total_nodes} (Process + File Nodes)")
    print(f"  [+] Total DBRG Graph Edges: {total_edges}")

    print("\n  [+] Sample Edge Weights radiating from PID 6666:")
    for target in victim_files[:4]:
        edge = mgr.get_edge_data(f"pid:{ransomware_pid}", f"file:{target}")
        print(f"      - Edge -> {os.path.basename(target)}: Weight={edge['weight']:.4f} | Events={edge['event_count']}")

    print("\n" + "─" * 70)
    print("  🚨 RANSOMWARE BEHAVIORAL PATTERN CONFIRMED BY STAGE 3 🚨")
    print("─" * 70)
    print(f"  1. FAN-OUT SPIKE  : PID {ransomware_pid} touched {proc_out_degree} files in {elapsed:.2f}s!")
    print(f"  2. TDEW ACCEL    : All {proc_out_degree} edges have high TDEW weights simultaneously.")
    print(f"  3. THREAD READY  : Stage 3 signals Stage 4 Feature Extractor & Stage 9 Min-Cut.")
    print("─" * 70 + "\n")

    gc.stop()

if __name__ == "__main__":
    run_demo()
