"""
src/stage_3_dbrg/tdew_calculator.py
====================================
Stage 3 — Time-Decayed Edge Weighting (TDEW) Engine

Implements the core mathematical formula for the DBRG edge weight model:

    W(e) = W_old · exp(−λ · Δt) + 1.0

Where:
    W_old   = the previous weight on the edge
    λ       = decay constant (decay_lambda); controls how fast old activity fades
    Δt      = time elapsed since the edge was last observed (seconds)
    +1.0    = the fresh contribution from the new observation

Interpretation:
    - If a process→file interaction recurs rapidly (small Δt), the weight
      accumulates aggressively  ⟶  burst detection.
    - If the edge is idle for a long period (large Δt), the exponential
      decay drives the old weight toward 0 before adding the new +1.0.
    - A completely stale edge that is never re-observed will passively
      decay toward 0 under the garbage collector's sweep.

This module is intentionally dependency-free (pure math + stdlib).
"""

import math
import time
import logging
from typing import Tuple

logger = logging.getLogger(__name__)


class TDEWEngine:
    """
    Time-Decayed Edge Weighting calculator.

    Parameters
    ----------
    decay_lambda : float
        Exponential decay constant λ.  Larger values cause faster weight
        loss over idle time.  Default is 0.05 (≈ 14 s half-life).

    Attributes
    ----------
    decay_lambda : float
        The active λ value used in all calculations.
    total_calculations : int
        Running counter of how many weight updates have been performed.

    Examples
    --------
    >>> engine = TDEWEngine(decay_lambda=0.05)
    >>> new_w, ts = engine.calculate_updated_weight(0.0, time.time() - 10)
    >>> # new_w ≈ 0.0 * exp(-0.05*10) + 1.0 ≈ 1.0
    """

    def __init__(self, decay_lambda: float = 0.05) -> None:
        if decay_lambda < 0:
            raise ValueError(
                f"decay_lambda must be non-negative, got {decay_lambda}"
            )
        self.decay_lambda: float = decay_lambda
        self.total_calculations: int = 0

    # ── Core Formula ─────────────────────────────────────────────────────

    def calculate_updated_weight(
        self,
        current_weight: float,
        last_timestamp: float,
    ) -> Tuple[float, float]:
        """
        Apply the TDEW formula and return the updated weight.

        Parameters
        ----------
        current_weight : float
            The existing edge weight (W_old).
        last_timestamp : float
            Unix epoch (seconds) of the last observation on this edge.

        Returns
        -------
        (new_weight, current_timestamp) : Tuple[float, float]
            new_weight       — W_old · exp(−λ·Δt) + 1.0
            current_timestamp — the ``time.time()`` snapshot used for Δt.

        Raises
        ------
        ValueError
            If ``current_weight`` is negative.
        """
        if current_weight < 0:
            raise ValueError(
                f"current_weight must be non-negative, got {current_weight}"
            )

        now: float = time.time()
        delta_t: float = max(0.0, now - last_timestamp)

        decayed: float = current_weight * math.exp(
            -self.decay_lambda * delta_t
        )
        new_weight: float = decayed + 1.0

        self.total_calculations += 1

        logger.debug(
            "[TDEW] W_old=%.4f  Δt=%.3fs  decay=%.6f  W_new=%.4f",
            current_weight,
            delta_t,
            decayed,
            new_weight,
        )

        return new_weight, now

    # ── Passive Decay (no new observation) ───────────────────────────────

    def calculate_passive_decay(
        self,
        current_weight: float,
        last_timestamp: float,
    ) -> float:
        """
        Return the passively decayed weight without adding a new observation.

        Used by the garbage collector to decide whether an edge should be
        pruned.

        Formula: W_passive = W_old · exp(−λ · (now − last_seen))

        Parameters
        ----------
        current_weight : float
            The stored edge weight.
        last_timestamp : float
            Unix epoch of the last observation.

        Returns
        -------
        float
            The weight after passive exponential decay.
        """
        now: float = time.time()
        delta_t: float = max(0.0, now - last_timestamp)
        return current_weight * math.exp(-self.decay_lambda * delta_t)

    # ── Utility ──────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"TDEWEngine(decay_lambda={self.decay_lambda}, "
            f"calculations={self.total_calculations})"
        )
