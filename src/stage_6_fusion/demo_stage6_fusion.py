"""
src/stage_6_fusion/demo_stage6_fusion.py
===========================================
Stage 6 Demo: Benign vs Ransomware Signal Fusion

Feeds hand-constructed benign and ransomware-like signal sets through
the Causality Fusion Engine + Sigmoidal Acceleration Engine and prints
side-by-side IntentDrift results, to demonstrate the "no single signal
can trigger containment alone" design principle in practice.

Usage:
    python src/stage_6_fusion/demo_stage6_fusion.py
"""

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.stage_6_fusion import ThreatFusionEngine


def print_header(title: str) -> None:
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)


def run_case(engine: ThreatFusionEngine, label: str, feature_vector: dict, s_rel: float, pid: int):
    result = engine.score(feature_vector, s_rel=s_rel, pid=pid, timestamp=time.time())
    print(f"\n  [{label}]")
    print(
        f"    Inputs : S_entropy={feature_vector['S_entropy']:.2f}  "
        f"S_dist={feature_vector['S_dist']:.2f}  S_dev={feature_vector['S_dev']:.2f}  "
        f"S_rel={s_rel:.2f}  S_stab={feature_vector['S_stab']:.2f}"
    )
    print(f"    S_composite   = {result['s_composite']:.4f}")
    print(f"    IntentDrift   = {result['intent_drift']:.4f}")
    print(f"    DriftVelocity = {result['drift_velocity']:+.4f}")
    verdict = "SUPPRESSED (below 0.50 trigger line)" if result["intent_drift"] < 0.50 else "ESCALATED (crossed 0.50 trigger line)"
    print(f"    Verdict       = {verdict}")
    return result


def main() -> None:
    print_header("STAGE 6: MULTI-SIGNAL CORROBORATION & SIGMOIDAL ACCELERATION DEMO")
    engine = ThreatFusionEngine()
    print(f"\n  Engine: {engine.fusion}")
    print(f"  Engine: {engine.drift}")

    print("\n[CASE 1] Single loud signal only (e.g. legit 7-Zip archive compression)")
    run_case(
        engine,
        "7-Zip Archiving (high entropy, everything else low)",
        {"S_entropy": 0.95, "S_dist": 0.05, "S_dev": 0.02, "S_stab": 0.90},
        s_rel=0.02,
        pid=4001,
    )

    print("\n[CASE 2] Normal multi-file editor save")
    run_case(
        engine,
        "Editor Saving a Few Documents",
        {"S_entropy": 0.30, "S_dist": 0.15, "S_dev": 0.10, "S_stab": 0.80},
        s_rel=0.10,
        pid=4002,
    )

    print("\n[CASE 3] Ransomware burst - all signals elevated together, two events over time")
    run_case(
        engine,
        "Ransomware Burst - Event 1",
        {"S_entropy": 0.95, "S_dist": 0.90, "S_dev": 0.85, "S_stab": 0.15},
        s_rel=0.95,
        pid=6666,
    )
    time.sleep(0.2)
    run_case(
        engine,
        "Ransomware Burst - Event 2 (0.2s later, still climbing)",
        {"S_entropy": 0.97, "S_dist": 0.95, "S_dev": 0.92, "S_stab": 0.10},
        s_rel=0.95,
        pid=6666,
    )

    print_header("SUMMARY")
    print("  Cases 1-2: one or two loud signals alone stay below the 0.50 trigger line.")
    print("  Case 3   : once entropy, distance, trajectory, lineage AND stability all")
    print("             move together, IntentDrift crosses 0.50, and drift_velocity")
    print("             turns positive on the second event, confirming an accelerating")
    print("             trend rather than a one-off spike.")


if __name__ == "__main__":
    main()
