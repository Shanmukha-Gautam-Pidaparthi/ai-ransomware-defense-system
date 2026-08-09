"""
src/stage_3_dbrg/garbage_collector.py
======================================
Stage 3 — DBRG Garbage Collector (Background Daemon Thread)

Periodically sweeps every edge in the DBRG, applies passive exponential
decay, and prunes edges whose weight has fallen below a configurable
threshold.

Passive Decay Formula (no new observation):
    W_passive = weight · exp(−λ · (now − last_seen))

Pruning Rule:
    If W_passive < prune_threshold → remove the edge.

If removing an edge leaves an orphan node (degree == 0), the node is
also removed to keep the graph compact.

Thread Lifecycle
----------------
- Subclasses ``threading.Thread`` with ``daemon=True``.
- ``start()`` begins the background sweep loop.
- ``stop()``  signals the internal event and joins the thread.
- The sweep loop sleeps for ``prune_interval`` seconds between cycles.
"""

import logging
import threading
import time
from typing import List, Tuple

from src.stage_3_dbrg.tdew_calculator import TDEWEngine

logger = logging.getLogger(__name__)


class DBRGGarbageCollector(threading.Thread):
    """
    Daemon thread that passively decays and prunes stale edges in the DBRG.

    Parameters
    ----------
    dbrg_manager : DBRGManager
        The graph manager whose ``graph`` and ``lock`` will be used.
    decay_lambda : float
        The λ parameter for passive decay (default 0.05).
    prune_threshold : float
        Edges with passively decayed weight below this are removed
        (default 0.01).
    prune_interval : float
        Seconds between garbage collection sweeps (default 10.0).

    Attributes
    ----------
    total_pruned_edges : int
        Cumulative count of edges removed across all sweeps.
    total_pruned_nodes : int
        Cumulative count of orphan nodes removed.
    sweep_count : int
        Number of completed GC sweep cycles.
    """

    def __init__(
        self,
        dbrg_manager,
        decay_lambda: float = 0.05,
        prune_threshold: float = 0.01,
        prune_interval: float = 10.0,
    ) -> None:
        super().__init__(name="DBRG-GarbageCollector", daemon=True)

        self._manager = dbrg_manager
        self._tdew = TDEWEngine(decay_lambda=decay_lambda)
        self._threshold: float = prune_threshold
        self._interval: float = prune_interval
        self._stop_event: threading.Event = threading.Event()

        # Statistics
        self.total_pruned_edges: int = 0
        self.total_pruned_nodes: int = 0
        self.sweep_count: int = 0

    # ── Thread Lifecycle ─────────────────────────────────────────────────

    def start(self) -> None:
        """Begin the background garbage collection loop."""
        self._stop_event.clear()
        super().start()
        logger.info(
            "[GC] Started  (interval=%.1fs, threshold=%.4f, λ=%.4f)",
            self._interval,
            self._threshold,
            self._tdew.decay_lambda,
        )

    def stop(self, timeout: float = 5.0) -> None:
        """
        Signal the GC thread to terminate and wait for it to finish.

        Parameters
        ----------
        timeout : float
            Max seconds to wait for the thread to join (default 5.0).
        """
        self._stop_event.set()
        if self.is_alive():
            self.join(timeout=timeout)
        logger.info(
            "[GC] Stopped  (sweeps=%d, edges_pruned=%d, nodes_pruned=%d)",
            self.sweep_count,
            self.total_pruned_edges,
            self.total_pruned_nodes,
        )

    # ── Main Loop ────────────────────────────────────────────────────────

    def run(self) -> None:
        """
        Background loop: sleep → acquire lock → sweep → release → repeat.
        """
        while not self._stop_event.is_set():
            # Sleep in small increments to respond quickly to stop()
            slept = 0.0
            while slept < self._interval and not self._stop_event.is_set():
                time.sleep(min(0.25, self._interval - slept))
                slept += 0.25

            if self._stop_event.is_set():
                break

            self._sweep()

    # ── Sweep Logic ──────────────────────────────────────────────────────

    def _sweep(self) -> None:
        """
        Execute one garbage collection cycle.

        Acquires the DBRG lock, iterates every edge, computes passive
        decay, and removes edges below the threshold.  Orphan nodes
        (process or file nodes with no remaining edges) are also pruned.
        """
        edges_to_remove: List[Tuple[str, str]] = []
        now: float = time.time()

        with self._manager.lock:
            graph = self._manager.graph

            # Phase 1: Identify stale edges
            for u, v, data in list(graph.edges(data=True)):
                weight: float = data.get("weight", 0.0)
                last_seen: float = data.get("last_seen", now)

                passive_weight: float = self._tdew.calculate_passive_decay(
                    weight, last_seen
                )

                if passive_weight < self._threshold:
                    edges_to_remove.append((u, v))

            # Phase 2: Remove stale edges
            for u, v in edges_to_remove:
                graph.remove_edge(u, v)

            # Phase 3: Remove orphan nodes (degree 0)
            orphans = [
                n for n in list(graph.nodes()) if graph.degree(n) == 0
            ]
            for orphan in orphans:
                graph.remove_node(orphan)

        # Update statistics
        pruned_edges = len(edges_to_remove)
        pruned_nodes = len(orphans) if edges_to_remove else 0
        self.total_pruned_edges += pruned_edges
        self.total_pruned_nodes += pruned_nodes
        self.sweep_count += 1

        if pruned_edges > 0 or pruned_nodes > 0:
            logger.info(
                "[GC] Sweep #%d: pruned %d edge(s), %d orphan node(s).  "
                "Remaining: %d nodes, %d edges.",
                self.sweep_count,
                pruned_edges,
                pruned_nodes,
                self._manager.get_node_count(),
                self._manager.get_edge_count(),
            )
        else:
            logger.debug(
                "[GC] Sweep #%d: no stale edges found.", self.sweep_count
            )

    # ── Utility ──────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"DBRGGarbageCollector(interval={self._interval}s, "
            f"threshold={self._threshold}, sweeps={self.sweep_count}, "
            f"pruned_edges={self.total_pruned_edges})"
        )
