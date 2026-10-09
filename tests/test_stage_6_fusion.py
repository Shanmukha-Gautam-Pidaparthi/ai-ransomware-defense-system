"""
tests/test_stage_6_fusion.py
================================
Stage 6 — Automated Test Suite for Multi-Signal Corroboration & Sigmoidal
Acceleration (Causality Fusion Engine + Sigmoidal Drift Engine).

Test Categories:
    1. CausalityFusionEngine (7 tests)  — weighting, clamping, validation
    2. SigmoidalDriftEngine  (8 tests)  — sigmoid math, velocity tracking
    3. ThreatFusionEngine    (8 tests)  — end-to-end per-event scoring
    4. Integration           (3 tests)  — compatibility with real Stage 4 output

Total: 26 tests
"""

import math
import sys
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.stage_6_fusion.fusion_engine import CausalityFusionEngine, WEIGHTS
from src.stage_6_fusion.drift_engine import (
    SigmoidalDriftEngine,
    DEFAULT_BETA,
    DEFAULT_THETA,
)
from src.stage_6_fusion.threat_fusion import ThreatFusionEngine


# ─────────────────────────────────────────────────────────────────────────
# 1. CausalityFusionEngine
# ─────────────────────────────────────────────────────────────────────────

class TestCausalityFusionEngine:

    def test_default_weights_sum_to_one(self):
        assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9

    def test_all_zero_signals_give_zero_composite(self):
        engine = CausalityFusionEngine()
        signals = {k: 0.0 for k in WEIGHTS}
        assert engine.compute_composite(signals) == pytest.approx(0.0)

    def test_all_one_signals_give_one_composite(self):
        engine = CausalityFusionEngine()
        signals = {k: 1.0 for k in WEIGHTS}
        assert engine.compute_composite(signals) == pytest.approx(1.0)

    def test_missing_keys_default_to_zero(self):
        engine = CausalityFusionEngine()
        # Only supply S_entropy; everything else should default to 0.0
        composite = engine.compute_composite({"S_entropy": 1.0})
        assert composite == pytest.approx(WEIGHTS["S_entropy"])

    def test_values_are_clamped_to_unit_range(self):
        engine = CausalityFusionEngine()
        signals = {k: 5.0 for k in WEIGHTS}  # way above 1.0
        assert engine.compute_composite(signals) == pytest.approx(1.0)

        signals_neg = {k: -5.0 for k in WEIGHTS}  # way below 0.0
        assert engine.compute_composite(signals_neg) == pytest.approx(0.0)

    def test_known_weighted_sum(self):
        engine = CausalityFusionEngine()
        signals = {"S_entropy": 0.8, "S_dist": 0.5, "S_dev": 0.2, "S_rel": 0.9, "S_stab": 0.1}
        expected = 0.35 * 0.8 + 0.30 * 0.5 + 0.20 * 0.2 + 0.10 * 0.9 + 0.05 * 0.1
        assert engine.compute_composite(signals) == pytest.approx(expected)

    def test_custom_weights_must_sum_to_one(self):
        with pytest.raises(ValueError):
            CausalityFusionEngine(weights={"S_entropy": 0.5, "S_dist": 0.2})


# ─────────────────────────────────────────────────────────────────────────
# 2. SigmoidalDriftEngine
# ─────────────────────────────────────────────────────────────────────────

class TestSigmoidalDriftEngine:

    def test_drift_at_theta_is_exactly_half(self):
        engine = SigmoidalDriftEngine(beta=DEFAULT_BETA, theta=DEFAULT_THETA)
        assert engine.compute_drift(DEFAULT_THETA) == pytest.approx(0.5, abs=1e-9)

    def test_drift_is_monotonic_increasing(self):
        engine = SigmoidalDriftEngine()
        scores = [0.0, 0.1, 0.3, 0.5, 0.7, 0.9, 1.0]
        drifts = [engine.compute_drift(s) for s in scores]
        assert drifts == sorted(drifts)

    def test_drift_bounded_in_unit_interval(self):
        engine = SigmoidalDriftEngine()
        for s in [0.0, 0.25, 0.5, 0.75, 1.0]:
            d = engine.compute_drift(s)
            assert 0.0 < d < 1.0

    def test_extreme_composite_does_not_overflow(self):
        engine = SigmoidalDriftEngine(beta=1000.0)  # artificially steep
        # Should not raise OverflowError despite an extreme exponent
        assert engine.compute_drift(0.0) == pytest.approx(0.0, abs=1e-6)
        assert engine.compute_drift(1.0) == pytest.approx(1.0, abs=1e-6)

    def test_first_observation_has_zero_velocity(self):
        engine = SigmoidalDriftEngine()
        result = engine.compute_drift_with_velocity(pid=100, s_composite=0.6, t_now=1000.0)
        assert result["drift_velocity"] == 0.0

    def test_velocity_positive_when_escalating(self):
        engine = SigmoidalDriftEngine()
        engine.compute_drift_with_velocity(pid=200, s_composite=0.3, t_now=1000.0)
        result = engine.compute_drift_with_velocity(pid=200, s_composite=0.8, t_now=1001.0)
        assert result["drift_velocity"] > 0.0

    def test_velocity_negative_when_deescalating(self):
        engine = SigmoidalDriftEngine()
        engine.compute_drift_with_velocity(pid=300, s_composite=0.9, t_now=1000.0)
        result = engine.compute_drift_with_velocity(pid=300, s_composite=0.2, t_now=1001.0)
        assert result["drift_velocity"] < 0.0

    def test_reset_pid_clears_history(self):
        engine = SigmoidalDriftEngine()
        engine.compute_drift_with_velocity(pid=400, s_composite=0.9, t_now=1000.0)
        engine.reset_pid(400)
        # After reset, this PID is "new" again -> velocity should be 0.0
        result = engine.compute_drift_with_velocity(pid=400, s_composite=0.1, t_now=2000.0)
        assert result["drift_velocity"] == 0.0


# ─────────────────────────────────────────────────────────────────────────
# 3. ThreatFusionEngine
# ─────────────────────────────────────────────────────────────────────────

class TestThreatFusionEngine:

    def test_single_loud_signal_stays_suppressed(self):
        """Core design property: one maxed-out signal alone must not cross
        the 0.50 trigger line, even at its theoretical maximum weight."""
        engine = ThreatFusionEngine()
        feature_vector = {"S_entropy": 1.0, "S_dist": 0.0, "S_dev": 0.0, "S_stab": 0.0}
        result = engine.score(feature_vector, s_rel=0.0, pid=1)
        assert result["intent_drift"] < 0.50

    def test_all_signals_elevated_crosses_trigger_line(self):
        engine = ThreatFusionEngine()
        feature_vector = {"S_entropy": 0.9, "S_dist": 0.9, "S_dev": 0.9, "S_stab": 0.1}
        result = engine.score(feature_vector, s_rel=0.9, pid=2)
        assert result["intent_drift"] > 0.50

    def test_s_rel_defaults_to_zero_when_not_supplied(self):
        engine = ThreatFusionEngine()
        feature_vector = {"S_entropy": 0.5, "S_dist": 0.5, "S_dev": 0.5, "S_stab": 0.5}
        result_default = engine.score(feature_vector, pid=10)
        result_explicit_zero = engine.score(feature_vector, s_rel=0.0, pid=11)
        assert result_default["s_composite"] == pytest.approx(result_explicit_zero["s_composite"])

    def test_pid_resolved_from_feature_vector_when_not_given(self):
        engine = ThreatFusionEngine()
        feature_vector = {"S_entropy": 0.5, "pid": 777}
        result = engine.score(feature_vector)
        assert result["pid"] == 777

    def test_pid_defaults_to_negative_one(self):
        engine = ThreatFusionEngine()
        result = engine.score({"S_entropy": 0.1})
        assert result["pid"] == -1

    def test_timestamp_defaults_to_now_when_not_given(self):
        engine = ThreatFusionEngine()
        before = time.time()
        result = engine.score({"S_entropy": 0.1}, pid=1)
        after = time.time()
        assert before <= result["timestamp"] <= after

    def test_total_scored_counter_increments(self):
        engine = ThreatFusionEngine()
        engine.score({"S_entropy": 0.1}, pid=1)
        engine.score({"S_entropy": 0.2}, pid=2)
        assert engine.total_scored == 2

    def test_reset_pid_delegates_to_drift_engine(self):
        engine = ThreatFusionEngine()
        engine.score({"S_entropy": 0.9}, pid=555, timestamp=1000.0)
        engine.reset_pid(555)
        result = engine.score({"S_entropy": 0.1}, pid=555, timestamp=2000.0)
        assert result["drift_velocity"] == 0.0


# ─────────────────────────────────────────────────────────────────────────
# 4. Integration — compatibility with the real Stage 4 feature vector shape
# ─────────────────────────────────────────────────────────────────────────

class TestStage4ToStage6Integration:

    def test_accepts_real_stage4_output_shape_without_error(self):
        """Stage 4's real FeatureExtractor emits extra keys (S_ETD,
        lambda_norm, branching_n, is_superheated, entropy_raw, delta_H,
        hist_variance, hist_kurtosis, fan_out_degree, actor_id, operation)
        that the architecture document's 5-signal Stage 6 formula doesn't
        use. Stage 6 must ignore them gracefully rather than erroring."""
        engine = ThreatFusionEngine()
        real_shaped_vector = {
            "S_entropy": 0.4,
            "S_ETD": 0.7,            # Stage 4 extra - not used by Stage 6
            "S_dist": 0.3,
            "S_dev": 0.2,
            "S_stab": 0.6,
            "lambda_norm": 0.5,      # Stage 4 extra - not used by Stage 6
            "branching_n": 0.625,    # Stage 4 extra - not used by Stage 6
            "is_superheated": False,
            "pid": 42,
            "file_path": "C:\\Users\\test\\doc.txt",
            "operation": "FILE_MODIFY",
            "timestamp": 1700000000000.0,
        }
        result = engine.score(real_shaped_vector, s_rel=0.3)
        assert 0.0 <= result["intent_drift"] <= 1.0
        assert result["pid"] == 42

    def test_does_not_import_stage_5_anomaly(self):
        """Stage 6 must remain independent of Stage 5's trained model.

        Checks actual import statements only (docstrings are free to
        *mention* stage_5_anomaly, e.g. to explain this very design
        decision - only a real `import ... stage_5_anomaly` would be
        a violation)."""
        import src.stage_6_fusion.fusion_engine as fe
        import src.stage_6_fusion.drift_engine as de
        import src.stage_6_fusion.threat_fusion as tf
        for module in (fe, de, tf):
            assert "stage_5_anomaly" not in module.__name__
            source = Path(module.__file__).read_text(encoding="utf-8")
            import_lines = [
                line for line in source.splitlines()
                if line.strip().startswith(("import ", "from "))
            ]
            assert not any("stage_5_anomaly" in line for line in import_lines)

    def test_live_two_event_escalation_sequence(self):
        """Simulates two consecutive events from the same PID, as the live
        monitor would call Stage 6, and checks velocity reflects the trend."""
        engine = ThreatFusionEngine()
        pid = 9999

        benign_vector = {"S_entropy": 0.2, "S_dist": 0.1, "S_dev": 0.05, "S_stab": 0.8}
        r1 = engine.score(benign_vector, s_rel=0.1, pid=pid, timestamp=1000.0)

        ransomware_vector = {"S_entropy": 0.95, "S_dist": 0.9, "S_dev": 0.85, "S_stab": 0.1}
        r2 = engine.score(ransomware_vector, s_rel=0.9, pid=pid, timestamp=1000.5)

        assert r1["intent_drift"] < r2["intent_drift"]
        assert r2["drift_velocity"] > 0.0
