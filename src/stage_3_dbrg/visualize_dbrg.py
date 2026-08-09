"""
src/stage_3_dbrg/visualize_dbrg.py
====================================
Stage 3 — DBRG Graph Visualization

Generates a visual directed graph showing process→file relationships
with TDEW-weighted edges. Simulates both benign and ransomware-like
activity patterns for side-by-side comparison.

Usage:
    python3 src/stage_3_dbrg/visualize_dbrg.py
"""

import os
import sys
import time
import math

# Ensure project root is on path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import networkx as nx
import numpy as np

from src.stage_3_dbrg.dbrg_manager import DBRGManager


# ═══════════════════════════════════════════════════════════════════════════
# Helper: Build styled labels
# ═══════════════════════════════════════════════════════════════════════════

def _short_label(node_id: str) -> str:
    """Convert 'pid:1234' → 'PID 1234' or 'file:C:\\...\\doc.txt' → 'doc.txt'."""
    if node_id.startswith("pid:"):
        return f"PID {node_id[4:]}"
    elif node_id.startswith("file:"):
        path = node_id[5:]
        return os.path.basename(path)
    return node_id


def _get_exe_label(graph: nx.DiGraph, node_id: str) -> str:
    """Get a human-readable label combining PID and exe name."""
    data = graph.nodes.get(node_id, {})
    if data.get("node_type") == "process":
        exe = data.get("exe_path", "unknown")
        exe_name = os.path.basename(exe)
        pid = data.get("pid", "?")
        return f"{exe_name}\n(PID {pid})"
    elif data.get("node_type") == "file":
        fpath = data.get("file_path", node_id)
        return os.path.basename(fpath)
    return _short_label(node_id)


# ═══════════════════════════════════════════════════════════════════════════
# Scenario Builders
# ═══════════════════════════════════════════════════════════════════════════

def build_benign_scenario() -> DBRGManager:
    """Simulate normal desktop activity: explorer, notepad, vscode."""
    mgr = DBRGManager(decay_lambda=0.05)

    # Explorer opens a few files
    for f in ["report.docx", "budget.xlsx", "notes.txt"]:
        mgr.process_event({
            "actorID": "pid:1024",
            "objectID": f"file:C:\\Users\\nani\\Documents\\{f}",
            "pid": 1024,
            "operation": "FILE_CREATE",
            "context": {
                "exe_path": "C:\\Windows\\explorer.exe",
                "sha256": "expl_hash", "ppid": 4, "parent_exe": "System",
                "cmdline": [], "dest_path": None,
            },
        })

    # Notepad edits a single file (3 saves)
    for _ in range(3):
        mgr.process_event({
            "actorID": "pid:2048",
            "objectID": "file:C:\\Users\\nani\\Documents\\notes.txt",
            "pid": 2048,
            "operation": "FILE_MODIFY",
            "context": {
                "exe_path": "C:\\Windows\\notepad.exe",
                "sha256": "note_hash", "ppid": 1024, "parent_exe": "explorer.exe",
                "cmdline": [], "dest_path": None,
            },
        })

    # VS Code touches config
    mgr.process_event({
        "actorID": "pid:3072",
        "objectID": "file:C:\\Users\\nani\\project\\.vscode\\settings.json",
        "pid": 3072,
        "operation": "FILE_MODIFY",
        "context": {
            "exe_path": "C:\\Program Files\\VSCode\\code.exe",
            "sha256": "vsc_hash", "ppid": 1024, "parent_exe": "explorer.exe",
            "cmdline": [], "dest_path": None,
        },
    })

    return mgr


def build_ransomware_scenario() -> DBRGManager:
    """Simulate ransomware: one process rapidly encrypting many files."""
    mgr = DBRGManager(decay_lambda=0.05)

    # Malicious process — rapid burst on many files
    target_files = [
        "family_photos.jpg", "tax_return_2025.pdf", "passwords.kdbx",
        "thesis_final.docx", "project_backup.zip", "client_data.csv",
        "medical_records.pdf", "bank_statement.pdf", "resume.docx",
        "wedding_video.mp4", "source_code.tar.gz", "ssh_keys.pem",
    ]

    for f in target_files:
        # Each file gets READ then ENCRYPTED (MODIFY)
        for op in ["FILE_MODIFY", "FILE_MODIFY"]:
            mgr.process_event({
                "actorID": "pid:6666",
                "objectID": f"file:C:\\Users\\victim\\Documents\\{f}",
                "pid": 6666,
                "operation": op,
                "context": {
                    "exe_path": "C:\\Temp\\svchost_update.exe",
                    "sha256": "deadbeef_malicious",
                    "ppid": 4444,
                    "parent_exe": "C:\\Windows\\System32\\cmd.exe",
                    "cmdline": ["svchost_update.exe", "--encrypt", "--fast"],
                    "dest_path": None,
                },
            })

    # Also drops a ransom note
    mgr.process_event({
        "actorID": "pid:6666",
        "objectID": "file:C:\\Users\\victim\\Desktop\\READ_ME_NOW.txt",
        "pid": 6666,
        "operation": "FILE_CREATE",
        "context": {
            "exe_path": "C:\\Temp\\svchost_update.exe",
            "sha256": "deadbeef_malicious",
            "ppid": 4444,
            "parent_exe": "C:\\Windows\\System32\\cmd.exe",
            "cmdline": [], "dest_path": None,
        },
    })

    # A benign process also active (explorer browsing)
    mgr.process_event({
        "actorID": "pid:1024",
        "objectID": "file:C:\\Users\\victim\\Downloads\\legitimate.pdf",
        "pid": 1024,
        "operation": "FILE_CREATE",
        "context": {
            "exe_path": "C:\\Windows\\explorer.exe",
            "sha256": "expl_hash", "ppid": 4, "parent_exe": "System",
            "cmdline": [], "dest_path": None,
        },
    })

    return mgr


# ═══════════════════════════════════════════════════════════════════════════
# Graph Renderer
# ═══════════════════════════════════════════════════════════════════════════

def render_dbrg(
    mgr: DBRGManager,
    ax: plt.Axes,
    title: str,
    subtitle: str = "",
) -> None:
    """Render the DBRG onto a matplotlib Axes with styled nodes and edges."""
    graph = mgr.get_graph_snapshot()

    if graph.number_of_nodes() == 0:
        ax.text(0.5, 0.5, "Empty Graph", ha="center", va="center", fontsize=14)
        ax.set_title(title)
        return

    # ── Layout ───────────────────────────────────────────────────────────
    # Use spring layout with seed for reproducibility
    pos = nx.spring_layout(graph, k=2.5, iterations=80, seed=42)

    # ── Classify nodes ───────────────────────────────────────────────────
    process_nodes = [n for n, d in graph.nodes(data=True) if d.get("node_type") == "process"]
    file_nodes = [n for n, d in graph.nodes(data=True) if d.get("node_type") == "file"]

    # ── Node labels ──────────────────────────────────────────────────────
    labels = {n: _get_exe_label(graph, n) for n in graph.nodes()}

    # ── Edge weights for width & color ───────────────────────────────────
    edges = list(graph.edges(data=True))
    if edges:
        weights = [d.get("weight", 1.0) for _, _, d in edges]
        max_w = max(weights) if weights else 1.0
        min_w = min(weights) if weights else 1.0

        # Normalize widths: 1.5 to 8.0
        if max_w > min_w:
            edge_widths = [1.5 + 6.5 * ((w - min_w) / (max_w - min_w)) for w in weights]
        else:
            edge_widths = [2.5] * len(weights)

        # Color map: low weight = grey, high weight = red
        edge_colors = []
        for w in weights:
            ratio = (w - min_w) / (max_w - min_w) if max_w > min_w else 0.0
            # Interpolate from steel blue to crimson red
            r = 0.3 + 0.7 * ratio
            g = 0.5 * (1 - ratio)
            b = 0.7 * (1 - ratio)
            edge_colors.append((r, g, b, 0.8))
    else:
        edge_widths = []
        edge_colors = []

    # ── Draw ─────────────────────────────────────────────────────────────
    ax.set_facecolor("#0d1117")

    # Draw edges
    nx.draw_networkx_edges(
        graph, pos, ax=ax,
        edge_color=edge_colors,
        width=edge_widths,
        arrows=True,
        arrowstyle="-|>",
        arrowsize=18,
        connectionstyle="arc3,rad=0.08",
        min_source_margin=25,
        min_target_margin=25,
    )

    # Draw process nodes (hexagon-like via large markers)
    nx.draw_networkx_nodes(
        graph, pos, ax=ax,
        nodelist=process_nodes,
        node_color="#e74c3c",
        node_size=1800,
        node_shape="h",  # hexagon
        edgecolors="#ffffff",
        linewidths=2.0,
        alpha=0.95,
    )

    # Draw file nodes (circles)
    nx.draw_networkx_nodes(
        graph, pos, ax=ax,
        nodelist=file_nodes,
        node_color="#3498db",
        node_size=1200,
        node_shape="o",
        edgecolors="#ffffff",
        linewidths=1.5,
        alpha=0.9,
    )

    # Draw labels
    nx.draw_networkx_labels(
        graph, pos, ax=ax,
        labels=labels,
        font_size=7,
        font_color="#ffffff",
        font_weight="bold",
        font_family="monospace",
    )

    # Draw edge weight labels
    edge_labels = {}
    for u, v, d in edges:
        w = d.get("weight", 0)
        cnt = d.get("event_count", 1)
        edge_labels[(u, v)] = f"W={w:.1f}\n({cnt})"

    nx.draw_networkx_edge_labels(
        graph, pos, ax=ax,
        edge_labels=edge_labels,
        font_size=6,
        font_color="#aaaaaa",
        bbox=dict(boxstyle="round,pad=0.15", facecolor="#1a1a2e", edgecolor="none", alpha=0.7),
    )

    # ── Title & Stats ────────────────────────────────────────────────────
    ax.set_title(
        title,
        fontsize=16, fontweight="bold", color="#ffffff",
        pad=15,
    )

    stats_text = (
        f"Nodes: {graph.number_of_nodes()}  |  "
        f"Edges: {graph.number_of_edges()}  |  "
        f"Events: {mgr.events_processed}"
    )
    if subtitle:
        stats_text = f"{subtitle}\n{stats_text}"

    ax.text(
        0.5, -0.02, stats_text,
        transform=ax.transAxes, ha="center", va="top",
        fontsize=9, color="#888888", style="italic",
    )

    ax.axis("off")


# ═══════════════════════════════════════════════════════════════════════════
# Main — Generate the visualization
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("  Stage 3: DBRG Visualization Generator")
    print("=" * 60)

    # Build both scenarios
    print("\n[1/4] Building benign activity scenario...")
    benign_mgr = build_benign_scenario()
    print(f"       → {benign_mgr}")

    print("[2/4] Building ransomware burst scenario...")
    ransom_mgr = build_ransomware_scenario()
    print(f"       → {ransom_mgr}")

    # ── Render side-by-side ──────────────────────────────────────────────
    print("[3/4] Rendering graphs...")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(24, 12))
    fig.patch.set_facecolor("#0d1117")

    fig.suptitle(
        "Stage 3: Dynamic Behavior Relationship Graph (DBRG)\n"
        "Time-Decayed Edge Weighting · Process → File Interactions",
        fontsize=20, fontweight="bold", color="#ffffff",
        y=0.97,
    )

    render_dbrg(
        benign_mgr, ax1,
        title="[BENIGN] Normal Desktop Activity",
        subtitle="Low edge weights | Normal fan-out | Edges will decay naturally",
    )

    render_dbrg(
        ransom_mgr, ax2,
        title="[ALERT] Ransomware Burst Pattern",
        subtitle="High edge weights | Extreme fan-out from single process | ANOMALOUS",
    )

    # ── Legend ────────────────────────────────────────────────────────────
    legend_elements = [
        mpatches.Patch(facecolor="#e74c3c", edgecolor="#ffffff", label="Process Node"),
        mpatches.Patch(facecolor="#3498db", edgecolor="#ffffff", label="File Node"),
        mpatches.Patch(facecolor="#4a6fa5", edgecolor="none", label="Low TDEW Weight"),
        mpatches.Patch(facecolor="#c0392b", edgecolor="none", label="High TDEW Weight"),
    ]
    fig.legend(
        handles=legend_elements,
        loc="lower center",
        ncol=4,
        fontsize=11,
        facecolor="#1a1a2e",
        edgecolor="#333333",
        labelcolor="#ffffff",
        framealpha=0.9,
    )

    plt.tight_layout(rect=[0, 0.05, 1, 0.93])

    # ── Save ─────────────────────────────────────────────────────────────
    output_path = os.path.join(PROJECT_ROOT, "stage3_dbrg_graph.png")
    fig.savefig(output_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)

    print(f"[4/4] Graph saved to: {output_path}")

    # ── Print summary table ──────────────────────────────────────────────
    print("\n" + "─" * 60)
    print("  DBRG Graph Comparison Summary")
    print("─" * 60)
    print(f"  {'Metric':<30} {'Benign':>12} {'Ransomware':>12}")
    print(f"  {'─'*30} {'─'*12} {'─'*12}")
    print(f"  {'Process Nodes':<30} {len([n for n,d in benign_mgr.graph.nodes(data=True) if d.get('node_type')=='process']):>12} {len([n for n,d in ransom_mgr.graph.nodes(data=True) if d.get('node_type')=='process']):>12}")
    print(f"  {'File Nodes':<30} {len([n for n,d in benign_mgr.graph.nodes(data=True) if d.get('node_type')=='file']):>12} {len([n for n,d in ransom_mgr.graph.nodes(data=True) if d.get('node_type')=='file']):>12}")
    print(f"  {'Total Edges':<30} {benign_mgr.get_edge_count():>12} {ransom_mgr.get_edge_count():>12}")
    print(f"  {'Events Processed':<30} {benign_mgr.events_processed:>12} {ransom_mgr.events_processed:>12}")

    # Max edge weight
    benign_max_w = max((d.get("weight", 0) for _, _, d in benign_mgr.graph.edges(data=True)), default=0)
    ransom_max_w = max((d.get("weight", 0) for _, _, d in ransom_mgr.graph.edges(data=True)), default=0)
    print(f"  {'Max Edge Weight (TDEW)':<30} {benign_max_w:>12.2f} {ransom_max_w:>12.2f}")

    # Fan-out (max out-degree)
    benign_fan = max((d for _, d in benign_mgr.graph.out_degree()), default=0)
    ransom_fan = max((d for _, d in ransom_mgr.graph.out_degree()), default=0)
    print(f"  {'Max Process Fan-out':<30} {benign_fan:>12} {ransom_fan:>12}")
    print("─" * 60)
    print(f"\n  ⚡ Ransomware fan-out is {ransom_fan}x vs benign {benign_fan}x")
    print(f"  ⚡ Ransomware max TDEW weight: {ransom_max_w:.2f} vs benign: {benign_max_w:.2f}")
    print()


if __name__ == "__main__":
    main()
