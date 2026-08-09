"""
src/stage_3_dbrg/__init__.py
=============================
Stage 3 — Dynamic Behavior Relationship Graph (DBRG)
     with Time-Decayed Edge Weighting (TDEW)

This package constructs a live, directed process→file interaction graph
from context-enriched eCAR events produced by Stage 2 (Lineage Analysis).

Each edge carries an exponentially time-decayed weight:
    W(e) = W_old · exp(−λ · Δt) + 1.0

A background garbage collector daemon passively decays and prunes stale
edges whose weight falls below a configurable threshold.

Exports
-------
TDEWEngine            — Pure-math TDEW weight calculator.
DBRGManager           — Thread-safe NetworkX DiGraph wrapper.
DBRGGarbageCollector  — Daemon thread for passive decay & pruning.
"""

__version__ = "1.0.0"
__stage__ = "Stage 3: Dynamic Behavior Relationship Graph (DBRG)"

from src.stage_3_dbrg.tdew_calculator import TDEWEngine
from src.stage_3_dbrg.dbrg_manager import DBRGManager
from src.stage_3_dbrg.garbage_collector import DBRGGarbageCollector

__all__ = ["TDEWEngine", "DBRGManager", "DBRGGarbageCollector"]
