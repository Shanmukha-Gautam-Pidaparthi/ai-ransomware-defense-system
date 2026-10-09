"""
src/stage_6_fusion/threat_fusion.py
=====================================
Stage 6 - Threat Fusion Orchestrator

Ties the Causality Fusion Engine and Sigmoidal Acceleration Engine
together into a single per-event entry point. Takes the Stage 4
feature vector plus the Stage 2 lineage rarity score (S_rel) - these
are two independent upstream outputs merged here, at the Stage 6
boundary, rather than inside Stage 4 or Stage 5.

Deliberately has no import of, or dependency on, anything in
src/stage_5_anomaly. Stage 6 is a second, independent corroboration
path alongside Stage 5, not a consumer of its trained model's output
(see the architecture document, Section 2, Stage 6).

Data Flow:
    Stage 2 (S_rel) + Stage 4 (S_entropy, S_dist, S_dev, S_stab)
        -> ThreatFusionEngine.score()
            -> {s_composite, intent_drift, drift_velocity}
                -> feeds Stage 7 (Trust Decay & Risk State Engine)
"""

import time
from typing import Any, Dict, Optional

from src.stage_6_fusion.fusion_engine import CausalityFusionEngine
from src.stage_6_fusion.drift_engine import SigmoidalDriftEngine


class ThreatFusionEngine:
    """
    Stage 6 orchestrator: fuses Stage 2 + Stage 4 signals into a single
    IntentDrift score (with velocity) per process event.

    Parameters
    ----------
    fusion_engine : CausalityFusionEngine, optional
        Defaults to a new instance with the standard blueprint weights.
    drift_engine : SigmoidalDriftEngine, optional
        Defaults to a new instance with beta=10.0, theta=0.50.
    """

    def __init__(
        self,
        fusion_engine: Optional[CausalityFusionEngine] = None,
        drift_engine: Optional[SigmoidalDriftEngine] = None,
    ) -> None:
        self.fusion = fusion_engine or CausalityFusionEngine()
        self.drift = drift_engine or SigmoidalDriftEngine()
        self.total_scored: int = 0

    def score(
        self,
        feature_vector: Dict[str, Any],
        s_rel: float = 0.0,
        pid: Optional[int] = None,
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Compute the Stage 6 result for one event.

        Parameters
        ----------
        feature_vector : dict
            A Stage 4 FeatureVector dict (or any dict with compatible
            keys). Only S_entropy, S_dist, S_dev, S_stab are read; any
            other keys (e.g. Stage 4's S_ETD, lambda_norm, branching_n)
            are ignored, so this works unmodified against the real
            Stage 4 extractor's output.
        s_rel : float
            Stage 2 Lineage Rarity Score for this process's parent->child
            spawn. Defaults to 0.0 (treated as a common/benign lineage)
            when the caller hasn't wired Stage 2 in yet.
        pid : int, optional
            Process ID, used to track drift velocity over time. Falls
            back to feature_vector["pid"] if not given, then to -1.
        timestamp : float, optional
            Event time in seconds. Defaults to time.time().

        Returns
        -------
        dict
            {
                "s_composite": float,
                "intent_drift": float,
                "drift_velocity": float,
                "pid": int,
                "timestamp": float,
            }
        """
        resolved_pid = pid if pid is not None else feature_vector.get("pid", -1)
        t_now = timestamp if timestamp is not None else time.time()

        signals = {
            "S_entropy": feature_vector.get("S_entropy", 0.0),
            "S_dist": feature_vector.get("S_dist", 0.0),
            "S_dev": feature_vector.get("S_dev", 0.0),
            "S_rel": s_rel,
            "S_stab": feature_vector.get("S_stab", 0.0),
        }

        s_composite = self.fusion.compute_composite(signals)
        drift_result = self.drift.compute_drift_with_velocity(resolved_pid, s_composite, t_now)

        self.total_scored += 1

        return {
            "s_composite": s_composite,
            "intent_drift": drift_result["intent_drift"],
            "drift_velocity": drift_result["drift_velocity"],
            "pid": resolved_pid,
            "timestamp": t_now,
        }

    def reset_pid(self, pid: int) -> None:
        """Clear drift-velocity tracking state for a specific PID."""
        self.drift.reset_pid(pid)

    def __repr__(self) -> str:
        return f"ThreatFusionEngine(scored={self.total_scored}, {self.fusion}, {self.drift})"
