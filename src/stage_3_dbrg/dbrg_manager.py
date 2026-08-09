"""
src/stage_3_dbrg/dbrg_manager.py
==================================
Stage 3 — Dynamic Behavior Relationship Graph (DBRG) Manager

Wraps a ``networkx.DiGraph`` with full thread safety to build and
maintain a live directed graph of process→file interactions.

Data Flow
---------
Stage 2 (LineageTracker / QueueJoiner) emits context-enriched eCAR JSON
events.  Each event contains:

    actorID   → "pid:<PID>"       (Process Node — source)
    objectID  → "file:<path>"     (File Node — target)
    pid       → integer PID
    operation → FILE_CREATE / FILE_MODIFY / FILE_DELETE / FILE_MOVE
    context   → {exe_path, sha256, ppid, parent_exe, cmdline, …}

``process_event()`` ingests one eCAR dict and:
  1. Creates/updates a Process node and a File node.
  2. Creates or updates the directed edge (Process → File).
  3. On NEW edges: initialises weight=1.0, last_seen=now, cut_cost=1.0.
  4. On EXISTING edges: recalculates weight via the TDEW formula.
"""

import logging
import threading
import time
import copy
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx

from src.stage_3_dbrg.tdew_calculator import TDEWEngine

logger = logging.getLogger(__name__)


class DBRGManager:
    """
    Thread-safe wrapper around ``networkx.DiGraph`` representing the
    Dynamic Behavior Relationship Graph (DBRG).

    Parameters
    ----------
    decay_lambda : float
        λ passed to the internal ``TDEWEngine`` (default 0.05).

    Attributes
    ----------
    graph : nx.DiGraph
        The internal directed graph.  Access ONLY while holding ``lock``.
    tdew : TDEWEngine
        The edge weight calculator.
    lock : threading.Lock
        Guards all mutations to ``graph``.
    events_processed : int
        Total eCAR events successfully ingested.
    """

    def __init__(self, decay_lambda: float = 0.05) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self.tdew: TDEWEngine = TDEWEngine(decay_lambda=decay_lambda)
        self.lock: threading.Lock = threading.Lock()
        self.events_processed: int = 0

    # ── Primary Ingestion Method ─────────────────────────────────────────

    def process_event(self, ecar_event: dict) -> None:
        """
        Ingest a single context-enriched eCAR event from Stage 2.

        Steps
        -----
        1. Extract ``actorID``/``pid`` for the Process (source) node.
        2. Extract ``objectID``/``image_path`` for the File (target) node.
        3. Acquire the graph lock.
        4. Add/update source and target nodes with metadata.
        5. If the directed edge exists → recalculate weight via TDEW.
        6. If the edge is new → initialise weight=1.0, last_seen=now,
           cut_cost=1.0.

        Parameters
        ----------
        ecar_event : dict
            A Stage 2 eCAR JSON event dict.  Expected keys:
            ``actorID``, ``objectID``, ``pid``, ``operation``, ``context``.
        """
        try:
            # ── 1. Parse Source (Process Node) ────────────────────────────
            actor_id: str = ecar_event.get("actorID", "pid:-1")
            pid: int = ecar_event.get("pid", -1)
            context: dict = ecar_event.get("context", {})
            exe_path: str = context.get("exe_path", "UNKNOWN")
            sha256: str = context.get("sha256", "UNKNOWN")
            ppid: int = context.get("ppid", -1)
            parent_exe: str = context.get("parent_exe", "UNKNOWN")
            operation: str = ecar_event.get("operation", "FILE_EVENT")

            # Use actorID as the canonical process node ID
            source_id: str = actor_id

            # ── 2. Parse Target (File Node) ──────────────────────────────
            object_id: str = ecar_event.get("objectID", "file:UNKNOWN")
            # Also check for image_path in context (Stage 2 may enrich)
            image_path: str = context.get("image_path", "")
            target_id: str = object_id if object_id else f"file:{image_path}"

            if not source_id or not target_id:
                logger.warning(
                    "[DBRGManager] Skipping event with missing source/target: "
                    "actorID=%s objectID=%s",
                    actor_id,
                    object_id,
                )
                return

            now: float = time.time()

            # ── 3–6. Thread-safe graph mutation ──────────────────────────
            with self.lock:
                # Add or update Process Node (source)
                if not self.graph.has_node(source_id):
                    self.graph.add_node(
                        source_id,
                        node_type="process",
                        pid=pid,
                        exe_path=exe_path,
                        sha256=sha256,
                        ppid=ppid,
                        parent_exe=parent_exe,
                        first_seen=now,
                        last_seen=now,
                    )
                else:
                    self.graph.nodes[source_id]["last_seen"] = now

                # Add or update File Node (target)
                if not self.graph.has_node(target_id):
                    self.graph.add_node(
                        target_id,
                        node_type="file",
                        file_path=object_id.replace("file:", "", 1),
                        first_seen=now,
                        last_seen=now,
                    )
                else:
                    self.graph.nodes[target_id]["last_seen"] = now

                # ── Edge: create or update ───────────────────────────────
                if self.graph.has_edge(source_id, target_id):
                    edge_data = self.graph[source_id][target_id]
                    old_weight: float = edge_data.get("weight", 1.0)
                    old_last_seen: float = edge_data.get("last_seen", now)

                    new_weight, ts = self.tdew.calculate_updated_weight(
                        old_weight, old_last_seen
                    )

                    edge_data["weight"] = new_weight
                    edge_data["last_seen"] = ts
                    edge_data["operation"] = operation
                    edge_data["event_count"] = (
                        edge_data.get("event_count", 1) + 1
                    )
                    # Update cut_cost proportionally to weight
                    edge_data["cut_cost"] = new_weight

                    logger.debug(
                        "[DBRGManager] Edge UPDATED %s→%s  "
                        "W: %.4f→%.4f  events=%d",
                        source_id,
                        target_id,
                        old_weight,
                        new_weight,
                        edge_data["event_count"],
                    )
                else:
                    self.graph.add_edge(
                        source_id,
                        target_id,
                        weight=1.0,
                        last_seen=now,
                        cut_cost=1.0,
                        operation=operation,
                        event_count=1,
                    )
                    logger.debug(
                        "[DBRGManager] Edge CREATED %s→%s  W=1.0",
                        source_id,
                        target_id,
                    )

                self.events_processed += 1

        except Exception as exc:
            logger.error(
                "[DBRGManager] Failed to process event: %s", exc, exc_info=True
            )

    # ── Query Helpers ────────────────────────────────────────────────────

    def get_edge_count(self) -> int:
        """Return the total number of directed edges in the DBRG."""
        with self.lock:
            return self.graph.number_of_edges()

    def get_node_count(self) -> int:
        """Return the total number of nodes (process + file) in the DBRG."""
        with self.lock:
            return self.graph.number_of_nodes()

    def get_edge_data(
        self, source: str, target: str
    ) -> Optional[Dict[str, Any]]:
        """
        Return a copy of the edge attribute dict for (source→target).

        Returns None if the edge does not exist.
        """
        with self.lock:
            if self.graph.has_edge(source, target):
                return dict(self.graph[source][target])
            return None

    def get_node_data(self, node_id: str) -> Optional[Dict[str, Any]]:
        """
        Return a copy of the node attribute dict.

        Returns None if the node does not exist.
        """
        with self.lock:
            if self.graph.has_node(node_id):
                return dict(self.graph.nodes[node_id])
            return None

    def get_graph_snapshot(self) -> nx.DiGraph:
        """
        Return a deep copy of the current DBRG graph.

        Safe for read-only analysis without holding the lock.
        """
        with self.lock:
            return copy.deepcopy(self.graph)

    def get_all_edges(self) -> List[Tuple[str, str, Dict[str, Any]]]:
        """Return a list of (source, target, attr_dict) for every edge."""
        with self.lock:
            return [
                (u, v, dict(d)) for u, v, d in self.graph.edges(data=True)
            ]

    # ── Utility ──────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"DBRGManager(nodes={self.get_node_count()}, "
            f"edges={self.get_edge_count()}, "
            f"events={self.events_processed})"
        )
