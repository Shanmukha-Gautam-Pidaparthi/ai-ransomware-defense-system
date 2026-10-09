"""
src/stage_6_fusion/fusion_engine.py
=====================================
Stage 6 - Causality Fusion Engine

Combines the independent upstream behavioral signals into a single
priority-weighted composite score. Each signal's weight reflects its
relative reliability as a ransomware indicator per the architecture
blueprint; no single signal's weight is large enough on its own to
push the composite past the Stage 6 sigmoid trigger threshold
(see drift_engine.py) without help from the others.

    S_composite = 0.35*S_entropy + 0.30*S_dist + 0.20*S_dev
                + 0.10*S_rel + 0.05*S_stab

Inputs (all expected in [0, 1]):
    S_entropy : Stage 4 content entropy signal
    S_dist    : Stage 4 graph fan-out / distance signal
    S_dev     : Stage 4 trajectory deviation signal
    S_rel     : Stage 2 lineage rarity score
    S_stab    : Stage 4 operational stability signal

This module has no dependency on Stage 5 (src/stage_5_anomaly) -
Stage 6 is an independent corroboration path, not a consumer of
Stage 5's trained model output.
"""

from typing import Any, Dict, Optional

# Priority weights, fixed per the architecture blueprint (Section 2, Stage 6).
# These are deliberately NOT learned - they encode a hand-set reliability
# ranking of each signal and must sum to 1.0.
WEIGHTS: Dict[str, float] = {
    "S_entropy": 0.35,
    "S_dist": 0.30,
    "S_dev": 0.20,
    "S_rel": 0.10,
    "S_stab": 0.05,
}

REQUIRED_SIGNALS = tuple(WEIGHTS.keys())


class CausalityFusionEngine:
    """
    Fuses independent threat sub-signals into one composite score using
    fixed causality-priority weights.

    Parameters
    ----------
    weights : dict, optional
        Override the default weight table. Must sum to 1.0. Primarily
        useful for the Stage 12 ablation sweep.
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None) -> None:
        self.weights: Dict[str, float] = dict(weights) if weights else dict(WEIGHTS)
        total = sum(self.weights.values())
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"Fusion weights must sum to 1.0, got {total:.6f}: {self.weights}"
            )

    def compute_composite(self, signals: Dict[str, Any]) -> float:
        """
        Compute S_composite from the required signals.

        Parameters
        ----------
        signals : dict
            Should contain S_entropy, S_dist, S_dev, S_rel, S_stab.
            Any missing key defaults to 0.0 (treated as "no signal").
            Values are clamped to [0, 1] before weighting.

        Returns
        -------
        float
            Weighted composite score. In [0, 1] whenever inputs are in [0, 1].
        """
        composite = 0.0
        for name, weight in self.weights.items():
            raw_value = signals.get(name, 0.0)
            try:
                value = float(raw_value)
            except (TypeError, ValueError):
                value = 0.0
            value = max(0.0, min(1.0, value))
            composite += weight * value
        return composite

    def __repr__(self) -> str:
        return f"CausalityFusionEngine(weights={self.weights})"
