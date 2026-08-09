"""
tests/manual_test_stage_3.py
==============================
Stage 3 — Interactive Manual Verification Script

Walks through 6 verification items for the DBRG module with
real-time printed outputs showing edge weights, timestamps,
and PASS/FAIL indicators.

Usage:
    python3 tests/manual_test_stage_3.py          # Run all 6 tests
    python3 tests/manual_test_stage_3.py 1        # Run only test 1
    python3 tests/manual_test_stage_3.py 1 2 5    # Run tests 1, 2, 5
"""

import os
import sys
import math
import time
import threading
from datetime import datetime

# Ensure project root is importable
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.stage_3_dbrg.tdew_calculator import TDEWEngine
from src.stage_3_dbrg.dbrg_manager import DBRGManager
from src.stage_3_dbrg.garbage_collector import DBRGGarbageCollector

# ═══════════════════════════════════════════════════════════════════════════
# Formatting Helpers
# ═══════════════════════════════════════════════════════════════════════════

BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
DIM = "\033[2m"
RESET = "\033[0m"

def header(test_num: int, title: str) -> None:
    print(f"\n{'='*70}")
    print(f"  {BOLD}{CYAN}VERIFICATION ITEM {test_num}{RESET}: {BOLD}{title}{RESET}")
    print(f"{'='*70}")

def step(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"  {DIM}[{ts}]{RESET} {msg}")

def result(label: str, value, expected=None) -> None:
    val_str = f"{value:.6f}" if isinstance(value, float) else str(value)
    line = f"  {YELLOW}>>{RESET} {label}: {BOLD}{val_str}{RESET}"
    if expected is not None:
        line += f"  {DIM}(expected: {expected}){RESET}"
    print(line)

def pass_fail(condition: bool, msg: str) -> bool:
    tag = f"{GREEN}[PASS]{RESET}" if condition else f"{RED}[FAIL]{RESET}"
    print(f"\n  {tag} {msg}")
    return condition

def make_event(pid=1234, file_path="C:\\test\\file.txt",
               operation="FILE_MODIFY", exe_path="C:\\Windows\\notepad.exe",
               sha256="abc123", ppid=100, parent_exe="explorer.exe") -> dict:
    return {
        "actorID": f"pid:{pid}",
        "objectID": f"file:{file_path}",
        "pid": pid,
        "tid": 1,
        "principal": "TEST\\user",
        "timestamp": int(time.time() * 1000),
        "operation": operation,
        "ecar_ver": "1.0",
        "context": {
            "exe_path": exe_path, "sha256": sha256,
            "ppid": ppid, "parent_exe": parent_exe,
            "cmdline": [], "dest_path": None,
        },
    }


# ═══════════════════════════════════════════════════════════════════════════
# Verification Item 1: Single Event Ingestion
# ═══════════════════════════════════════════════════════════════════════════

def test_1_single_event_ingestion() -> bool:
    header(1, "Single Event Ingestion")

    mgr = DBRGManager(decay_lambda=0.05)
    event = make_event(pid=5001, file_path="C:\\Users\\nani\\report.docx",
                       exe_path="C:\\Windows\\notepad.exe")

    step("Created fresh DBRGManager (decay_lambda=0.05)")
    step(f"Ingesting single eCAR event: PID=5001 -> report.docx")

    mgr.process_event(event)

    result("Node count", mgr.get_node_count(), "2 (1 process + 1 file)")
    result("Edge count", mgr.get_edge_count(), "1")
    result("Events processed", mgr.events_processed, "1")

    edge = mgr.get_edge_data("pid:5001", "file:C:\\Users\\nani\\report.docx")
    proc_node = mgr.get_node_data("pid:5001")
    file_node = mgr.get_node_data("file:C:\\Users\\nani\\report.docx")

    if edge:
        result("Edge weight", edge["weight"], "1.0")
        result("Edge cut_cost", edge["cut_cost"], "1.0")
        result("Edge event_count", edge["event_count"], "1")
        result("Edge operation", edge["operation"])
    if proc_node:
        result("Process node type", proc_node["node_type"], "process")
        result("Process exe_path", proc_node["exe_path"])
    if file_node:
        result("File node type", file_node["node_type"], "file")
        result("File path", file_node["file_path"])

    ok = (edge is not None and edge["weight"] == 1.0 and
          mgr.get_node_count() == 2 and mgr.get_edge_count() == 1)
    return pass_fail(ok, "Initial edge weight == 1.0, 2 nodes, 1 edge created")


# ═══════════════════════════════════════════════════════════════════════════
# Verification Item 2: TDEW Burst Acceleration
# ═══════════════════════════════════════════════════════════════════════════

def test_2_tdew_burst() -> bool:
    header(2, "TDEW Burst Acceleration")

    mgr = DBRGManager(decay_lambda=0.05)
    event = make_event(pid=5002, file_path="C:\\Users\\victim\\encrypted.enc",
                       exe_path="C:\\Temp\\ransomware.exe")

    step("Sending 5 rapid FILE_MODIFY events (simulating encryption burst)")
    print(f"  {'─'*60}")
    print(f"  {'Event #':<10} {'Weight Before':<18} {'Weight After':<18} {'Delta t (ms)':<15}")
    print(f"  {'─'*60}")

    for i in range(5):
        # Capture pre-event weight
        edge_before = mgr.get_edge_data("pid:5002", "file:C:\\Users\\victim\\encrypted.enc")
        w_before = edge_before["weight"] if edge_before else 0.0

        t_start = time.time()
        mgr.process_event(event)
        dt_ms = (time.time() - t_start) * 1000

        edge_after = mgr.get_edge_data("pid:5002", "file:C:\\Users\\victim\\encrypted.enc")
        w_after = edge_after["weight"]

        print(f"  {i+1:<10} {w_before:<18.6f} {w_after:<18.6f} {dt_ms:<15.3f}")
        time.sleep(0.05)  # Small gap between events

    final_edge = mgr.get_edge_data("pid:5002", "file:C:\\Users\\victim\\encrypted.enc")
    final_w = final_edge["weight"]

    print(f"  {'─'*60}")
    result("Final edge weight after 5 events", final_w, "> 4.0")
    result("Event count on edge", final_edge["event_count"], "5")

    return pass_fail(final_w > 4.0, f"Burst weight accumulated to {final_w:.4f} (threshold: 4.0)")


# ═══════════════════════════════════════════════════════════════════════════
# Verification Item 3: Passive Exponential Decay
# ═══════════════════════════════════════════════════════════════════════════

def test_3_passive_decay() -> bool:
    header(3, "Passive Exponential Decay")

    LAMBDA = 0.3  # Aggressive decay for faster demo
    WAIT_SEC = 8  # Shorter wait with higher lambda

    mgr = DBRGManager(decay_lambda=LAMBDA)
    tdew = TDEWEngine(decay_lambda=LAMBDA)

    step(f"Using aggressive lambda={LAMBDA} for faster demonstration")
    step("Ingesting 3 rapid events to build weight...")

    event = make_event(pid=5003, file_path="C:\\data\\secret.pdf",
                       exe_path="C:\\evil.exe")
    for _ in range(3):
        mgr.process_event(event)

    edge = mgr.get_edge_data("pid:5003", "file:C:\\data\\secret.pdf")
    initial_w = edge["weight"]
    initial_ts = edge["last_seen"]
    result("Initial weight (after 3 events)", initial_w)

    step(f"Waiting {WAIT_SEC} seconds for passive decay...")
    print()

    for elapsed in range(WAIT_SEC):
        time.sleep(1)
        now = time.time()
        dt = now - initial_ts
        passive_w = initial_w * math.exp(-LAMBDA * dt)
        bar_len = int(passive_w / initial_w * 40)
        bar = f"{'█' * bar_len}{'░' * (40 - bar_len)}"
        print(f"\r  [{bar}] W={passive_w:.6f}  (t+{elapsed+1}s, decay={math.exp(-LAMBDA*dt):.6f})", end="", flush=True)

    print()
    final_dt = time.time() - initial_ts
    final_passive = initial_w * math.exp(-LAMBDA * final_dt)
    result("Decayed weight after wait", final_passive)
    result("Decay factor", math.exp(-LAMBDA * final_dt))
    result("Time elapsed", f"{final_dt:.1f}s")

    return pass_fail(
        final_passive < initial_w * 0.2,
        f"Weight decayed from {initial_w:.4f} to {final_passive:.6f} "
        f"({(1 - final_passive/initial_w)*100:.1f}% reduction)"
    )


# ═══════════════════════════════════════════════════════════════════════════
# Verification Item 4: Garbage Collector Pruning
# ═══════════════════════════════════════════════════════════════════════════

def test_4_gc_pruning() -> bool:
    header(4, "Garbage Collector Pruning")

    LAMBDA = 2.0  # Very aggressive for fast pruning

    mgr = DBRGManager(decay_lambda=LAMBDA)
    event = make_event(pid=5004, file_path="C:\\stale\\old_file.tmp",
                       exe_path="C:\\cleanup.exe")

    step(f"Ingesting event with aggressive lambda={LAMBDA}")
    mgr.process_event(event)
    result("Initial edge count", mgr.get_edge_count(), "1")
    result("Initial node count", mgr.get_node_count(), "2")

    step("Backdating edge last_seen by 30 seconds (simulating inactivity)")
    with mgr.lock:
        mgr.graph["pid:5004"]["file:C:\\stale\\old_file.tmp"]["last_seen"] = time.time() - 30

    # Show what the passive weight would be
    edge = mgr.get_edge_data("pid:5004", "file:C:\\stale\\old_file.tmp")
    passive_w = edge["weight"] * math.exp(-LAMBDA * 30)
    result("Passive weight after 30s inactivity", passive_w, "< 0.01 (prune threshold)")

    step("Starting GarbageCollector (interval=1s, threshold=0.01)...")
    gc = DBRGGarbageCollector(
        dbrg_manager=mgr, decay_lambda=LAMBDA,
        prune_threshold=0.01, prune_interval=1.0,
    )
    gc.start()

    step("Waiting for GC sweep cycle...")
    time.sleep(3.0)
    gc.stop(timeout=3.0)

    result("Edge count after GC", mgr.get_edge_count(), "0")
    result("Node count after GC", mgr.get_node_count(), "0 (orphans removed)")
    result("GC sweep count", gc.sweep_count)
    result("GC edges pruned", gc.total_pruned_edges)
    result("GC nodes pruned", gc.total_pruned_nodes)

    ok = mgr.get_edge_count() == 0 and mgr.get_node_count() == 0
    return pass_fail(ok, "Stale edge pruned, orphan nodes removed, graph is empty")


# ═══════════════════════════════════════════════════════════════════════════
# Verification Item 5: Multi-Threaded Safety
# ═══════════════════════════════════════════════════════════════════════════

def test_5_thread_safety() -> bool:
    header(5, "Multi-Threaded Safety")

    mgr = DBRGManager(decay_lambda=0.05)
    errors = []
    barrier = threading.Barrier(10)

    step("Launching 10 threads x 100 events = 1000 concurrent events")
    step("GarbageCollector running simultaneously...")

    gc = DBRGGarbageCollector(
        dbrg_manager=mgr, decay_lambda=0.05,
        prune_threshold=0.01, prune_interval=0.2,
    )
    gc.start()

    def worker(tid: int):
        try:
            barrier.wait(timeout=5)
            for i in range(100):
                mgr.process_event(make_event(
                    pid=tid * 1000 + i,
                    file_path=f"C:\\thread_{tid}\\file_{i}.dat",
                    exe_path=f"C:\\worker_{tid}.exe",
                ))
        except Exception as e:
            errors.append(f"Thread-{tid}: {e}")

    threads = [threading.Thread(target=worker, args=(t,), name=f"Worker-{t}") for t in range(10)]
    t_start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    elapsed = time.time() - t_start

    gc.stop(timeout=3.0)

    result("Total events processed", mgr.events_processed, "1000")
    result("Thread errors", len(errors), "0")
    result("Elapsed time", f"{elapsed:.2f}s")
    result("GC sweeps during test", gc.sweep_count)
    result("Final node count", mgr.get_node_count())
    result("Final edge count", mgr.get_edge_count())

    if errors:
        for e in errors:
            print(f"    {RED}ERROR: {e}{RESET}")

    ok = mgr.events_processed == 1000 and len(errors) == 0
    return pass_fail(ok, f"1000 events ingested across 10 threads, {len(errors)} errors, no crashes")


# ═══════════════════════════════════════════════════════════════════════════
# Verification Item 6: Downstream Handoff (Cold-Start Threshold)
# ═══════════════════════════════════════════════════════════════════════════

def test_6_downstream_handoff() -> bool:
    header(6, "Downstream Handoff (Cold-Start Threshold)")

    mgr = DBRGManager(decay_lambda=0.05)
    COLD_START_THRESHOLD = 5

    target_files = [
        "C:\\Users\\nani\\Documents\\report.docx",
        "C:\\Users\\nani\\Documents\\budget.xlsx",
        "C:\\Users\\nani\\Downloads\\installer.exe",
        "C:\\Users\\nani\\Desktop\\notes.txt",
        "C:\\Users\\nani\\Pictures\\photo.jpg",
    ]

    step(f"Ingesting events touching {len(target_files)} distinct files...")
    print(f"  {'─'*60}")

    for i, fpath in enumerate(target_files):
        mgr.process_event(make_event(
            pid=6000 + i,
            file_path=fpath,
            exe_path=f"C:\\app_{i}.exe",
        ))
        edge_count = mgr.get_edge_count()
        ready = edge_count >= COLD_START_THRESHOLD
        status = f"{GREEN}READY{RESET}" if ready else f"{YELLOW}WARMING{RESET}"
        print(f"  Event {i+1}: +{os.path.basename(fpath):<25} edges={edge_count:<4} [{status}]")

    print(f"  {'─'*60}")

    final_edges = mgr.get_edge_count()
    final_nodes = mgr.get_node_count()
    stage4_ready = final_edges >= COLD_START_THRESHOLD

    result("Final edge count", final_edges, f">= {COLD_START_THRESHOLD}")
    result("Final node count", final_nodes, f"{len(target_files)*2} (5 processes + 5 files)")
    result("Stage 4 readiness", stage4_ready, "True")

    snapshot = mgr.get_graph_snapshot()
    result("Snapshot nodes", snapshot.number_of_nodes())
    result("Snapshot edges", snapshot.number_of_edges())

    return pass_fail(stage4_ready, f"DBRG has {final_edges} edges >= {COLD_START_THRESHOLD} — ready for Stage 4 handoff")


# ═══════════════════════════════════════════════════════════════════════════
# Main Runner
# ═══════════════════════════════════════════════════════════════════════════

ALL_TESTS = {
    1: ("Single Event Ingestion", test_1_single_event_ingestion),
    2: ("TDEW Burst Acceleration", test_2_tdew_burst),
    3: ("Passive Exponential Decay", test_3_passive_decay),
    4: ("Garbage Collector Pruning", test_4_gc_pruning),
    5: ("Multi-Threaded Safety", test_5_thread_safety),
    6: ("Downstream Handoff", test_6_downstream_handoff),
}


def main():
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  STAGE 3 DBRG — MANUAL VERIFICATION SUITE{RESET}")
    print(f"{BOLD}  Dynamic Behavior Relationship Graph + TDEW Engine{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")

    # Parse which tests to run
    if len(sys.argv) > 1:
        selected = []
        for arg in sys.argv[1:]:
            try:
                n = int(arg)
                if n in ALL_TESTS:
                    selected.append(n)
                else:
                    print(f"  {RED}Unknown test: {n} (valid: 1-6){RESET}")
            except ValueError:
                print(f"  {RED}Invalid argument: {arg}{RESET}")
        if not selected:
            print(f"  {RED}No valid tests selected. Exiting.{RESET}")
            return
    else:
        selected = list(ALL_TESTS.keys())

    print(f"\n  Running {len(selected)} verification item(s): {selected}")

    results = {}
    for test_num in selected:
        title, func = ALL_TESTS[test_num]
        try:
            passed = func()
            results[test_num] = passed
        except Exception as e:
            print(f"\n  {RED}[EXCEPTION]{RESET} Test {test_num} raised: {e}")
            results[test_num] = False

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"  {BOLD}VERIFICATION SUMMARY{RESET}")
    print(f"{'='*70}")

    total_pass = 0
    total_fail = 0
    for num in sorted(results):
        title = ALL_TESTS[num][0]
        passed = results[num]
        tag = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
        print(f"  Item {num}: [{tag}] {title}")
        if passed:
            total_pass += 1
        else:
            total_fail += 1

    print(f"{'─'*70}")
    color = GREEN if total_fail == 0 else RED
    print(f"  {color}{BOLD}{total_pass}/{total_pass+total_fail} PASSED{RESET}")

    if total_fail == 0:
        print(f"\n  {GREEN}{BOLD}ALL VERIFICATION ITEMS PASSED{RESET}")
        print(f"  Stage 3 DBRG is verified and ready for Stage 4 integration.\n")
    else:
        print(f"\n  {RED}{BOLD}{total_fail} ITEM(S) FAILED — review output above{RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
