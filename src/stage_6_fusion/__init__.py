"""
src/stage_6_fusion
=====================
Stage 6 - Multi-Signal Corroboration & Sigmoidal Acceleration.

Exports:
    CausalityFusionEngine - weighted composite score (S_composite)
    SigmoidalDriftEngine  - logistic transform + velocity tracking (IntentDrift)
    ThreatFusionEngine    - orchestrator combining both into one per-event call
"""

from src.stage_6_fusion.fusion_engine import CausalityFusionEngine, WEIGHTS
from src.stage_6_fusion.drift_engine import (
    SigmoidalDriftEngine,
    DEFAULT_BETA,
    DEFAULT_THETA,
)
from src.stage_6_fusion.threat_fusion import ThreatFusionEngine

__all__ = [
    "CausalityFusionEngine",
    "SigmoidalDriftEngine",
    "ThreatFusionEngine",
    "WEIGHTS",
    "DEFAULT_BETA",
    "DEFAULT_THETA",
]
