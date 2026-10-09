"""
src/stage_6_fusion/drift_engine.py
=====================================
Stage 6 - Sigmoidal Acceleration Engine

Passes the composite score through a steep logistic sigmoid so that
scores move decisively toward 0 or 1 around the trigger threshold,
instead of growing linearly with the composite score. Also tracks
the per-process rate of change of IntentDrift over time, used
downstream by Stage 7 to apply a momentum penalty.

    IntentDrift(t) = 1 / (1 + e^(-beta * (S_composite - theta)))
    d(Drift)/dt    = [IntentDrift(t) - IntentDrift(t - dt)] / dt

Pure Python stdlib (math, threading, time) - no OS-specific calls,
so this runs identically on Windows, macOS, and Linux.
"""

import math
import threading
import time
from typing import Dict, Optional, Tuple

DEFAULT_BETA: float = 10.0
DEFAULT_THETA: float = 0.50

# Clamp the sigmoid exponent to avoid float overflow (math.exp raises
# OverflowError well before this on most platforms, but some extreme
# custom beta/theta combinations from the Stage 12 ablation sweep could
# exceed it).
_MAX_EXPONENT: float = 700.0


class SigmoidalDriftEngine:
    """
    Computes IntentDrift via a logistic sigmoid and tracks its velocity
    (rate of change) per process over time.

    Parameters
    ----------
    beta : float
        Sigmoid steepness. Higher = sharper transition around theta.
    theta : float
        Sigmoid midpoint / trigger threshold on S_composite.
    """

    def __init__(self, beta: float = DEFAULT_BETA, theta: float = DEFAULT_THETA) -> None:
        self.beta = beta
        self.theta = theta
        self._lock = threading.Lock()
        # pid -> (last_drift_value, last_timestamp_sec)
        self._history: Dict[int, Tuple[float, float]] = {}

    def compute_drift(self, s_composite: float) -> float:
        """
        Stateless sigmoid transform of a composite score into [0, 1].

        Parameters
        ----------
        s_composite : float
            Composite score from CausalityFusionEngine, expected in [0, 1].

        Returns
        -------
        float
            IntentDrift in (0, 1). Exactly 0.5 when s_composite == theta.
        """
        s_composite = max(0.0, min(1.0, s_composite))
        exponent = -self.beta * (s_composite - self.theta)
        exponent = max(-_MAX_EXPONENT, min(_MAX_EXPONENT, exponent))
        return 1.0 / (1.0 + math.exp(exponent))

    def compute_drift_with_velocity(
        self, pid: int, s_composite: float, t_now: Optional[float] = None
    ) -> Dict[str, float]:
        """
        Compute IntentDrift for a process and its rate of change since the
        last observation of the same PID.

        Parameters
        ----------
        pid : int
            Process ID being tracked; drift history is kept per PID.
        s_composite : float
            Current composite score from CausalityFusionEngine.
        t_now : float, optional
            Current time in seconds. Defaults to time.time().

        Returns
        -------
        dict
            {"intent_drift": float, "drift_velocity": float}
            drift_velocity is 0.0 on the first observation of a PID
            (no prior value to compare against).
        """
        if t_now is None:
            t_now = time.time()

        drift = self.compute_drift(s_composite)

        with self._lock:
            prev = self._history.get(pid)
            if prev is None:
                velocity = 0.0
            else:
                prev_drift, prev_t = prev
                dt = max(1e-6, t_now - prev_t)
                velocity = (drift - prev_drift) / dt

            self._history[pid] = (drift, t_now)

        return {"intent_drift": drift, "drift_velocity": velocity}

    def reset_pid(self, pid: int) -> None:
        """Clear tracked drift history for a specific PID (e.g. on process exit)."""
        with self._lock:
            self._history.pop(pid, None)

    def __repr__(self) -> str:
        return (
            f"SigmoidalDriftEngine(beta={self.beta}, theta={self.theta}, "
            f"tracked_pids={len(self._history)})"
        )
