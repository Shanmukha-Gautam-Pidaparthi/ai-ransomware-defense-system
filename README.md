# 🛡️ Real-Time Non-Destructive Ransomware Defense System

![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python)
![Stage 1 Status](https://img.shields.io/badge/Stage%201-PASSED%20(20%2F20)-brightgreen?style=for-the-badge&logo=pytest)
![Architecture](https://img.shields.io/badge/Architecture-12--Stage%20Pipeline-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

> **A Machine Learning & OS-Kernel Level Defense Pipeline for Real-Time Ransomware Interception, Behavioral Threat Modeling, and Zero-Data-Loss Rollback.**

---

## 📌 Executive Overview

The **AI Ransomware Defense System** is a 12-stage enterprise security solution designed to observe low-level operating system events, model behavioral relationships using exponential time-decay dynamics, score threat intent via multi-signal corroborated machine learning, and enforce kernel-level isolation with zero-data-loss write-ahead journaling rollback capabilities.

> [!NOTE]
> **Design Principle — Non-Destructive by Default:**  
> Unlike traditional antivirus software that abruptly terminates processes or causes data loss, this system observes, models, and scores behavior continuously without altering execution until a quantified, multi-signal risk threshold is crossed.

---

## 🏗️ End-to-End System Architecture Roadmap

The pipeline is organized into **11 sequential execution stages** plus a **12th evaluation phase**:

```text
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │                            STAGE 1: TELEMETRY COLLECTION                          │  <-- COMPLETED & VERIFIED
 │                Asynchronous File I/O Interception, Process Provenance             │
 └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                           │ (eCAR JSON Telemetry Stream in SQLite)
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │                      STAGE 2: PROCESS IDENTIFICATION & LINEAGE                    │  <-- UPCOMING NEXT
 │                 Provenance Tracing & Parent-Child Lineage Rarity (S_rel)          │
 └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                           │
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │                STAGE 3: DYNAMIC BEHAVIOR RELATIONSHIP GRAPH (DBRG)                │
 │                  Exponential Time-Decayed Edge Weighting (TDEW Engine)            │
 └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                           │
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │                  STAGES 4–5: FEATURE EXTRACTION & ANOMALY MODEL                   │
 │           4KB Byte Entropy, One-Class Learning (Isolation Forest / Density)       │
 └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                           │
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │              STAGES 6–7: THREAT FUSION & DYNAMIC TRUST EVOLUTION ENGINE           │
 │           Sigmoidal Intent Drift, Momentum Penalty, Risk Tiers (SAFE -> CRITICAL) │
 └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                           │
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │             STAGES 8–10: CONTAINMENT, JOURNALING & ZERO-DATA-LOSS ROLLBACK        │
 │              Synthetic Harness, SIGSTOP Kernel Freeze, Edmonds-Karp Min-Cut      │
 └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                           │
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │                  STAGES 11–12: SOC DASHBOARD & ABLATION EVALUATION                │
 │             WebSocket UI, Isolate & Restore / Authorize & Resume Controls         │
 └───────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚦 Project Implementation Status Matrix

| Stage | Module Name | Primary Role | Status | Hand-off Notes |
|---|---|---|---|---|
| **Stage 1** | **Telemetry Collection** | File I/O Interception, Process Provenance, eCAR Schema, SQLite Store | ✅ **Completed & Verified** | 20/20 Pytest Suite Passed. Streams events to `telemetry.db` |
| **Stage 2** | **Lineage Analysis** | Parent-Child Provenance Tracing & Lineage Rarity ($S_{\text{rel}}$) | ⏳ *Next Step* | Will consume `telemetry_events` table from `telemetry.db` |
| **Stage 3** | **DBRG Graph Engine** | NetworkX Directed Graph with TDEW Exponential Weight Decay | 📅 *Upcoming* | Reads process-file interaction pairs from Stage 1/2 |
| **Stage 4** | **Feature Extraction** | 4KB Multi-layer feature extraction & byte entropy profiling | 📅 *Upcoming* | Reads file modification byte streams |
| **Stage 5** | **Benign Profiling** | One-Class Anomaly Model (Isolation Forest baseline) | 📅 *Upcoming* | Uses `Dataset/RansomwareData.csv` & `Code/preprocessing.ipynb` |
| **Stage 6** | **Threat Fusion** | Sigmoidal Intent Drift Acceleration Engine | 📅 *Upcoming* | Combines entropy, graph distance, & lineage signals |
| **Stage 7** | **Trust State Engine** | Momentum Trust Decay Engine & Risk Tiers (SAFE/VERIFY/CRITICAL) | 📅 *Upcoming* | Controls transitions between risk states |
| **Stage 8** | **Synthetic Harness** | Sandboxed Attack Simulator | 📅 *Upcoming* | Uses `Code/mock_ransomware.ipynb` for red-team validation |
| **Stage 9** | **Kernel Containment** | SIGSTOP / `NtSuspendProcess` Freeze-Graph Min-Cut Engine | 📅 *Upcoming* | Edmonds-Karp minimum cut capacity optimization |
| **Stage 10** | **Journaling & Rollback**| Write-Ahead Journaling Vault & Zero-Data-Loss Selective Rollback | 📅 *Upcoming* | Block-level file backup vault & restore engine |
| **Stage 11** | **SOC Dashboard** | FastAPI WebSocket Backend & Interactive React Cytoscape UI | 📅 *Upcoming* | Analyst-in-the-loop manual override UI |
| **Stage 12** | **Evaluation Sweep** | Parameter Ablation & Red-Team Defense Preparation | 📅 *Upcoming* | Parameter tuning across $\lambda, \beta, \gamma$ constants |

---

## 🛡️ Stage 1 Implementation Detail (Completed)

Stage 1 serves as the **telemetry ingestion backbone** for the entire platform.

### Internal Stage 1 Data Flow Architecture

```text
[ File System Events ] ──> [ FileMonitor ] ──┐
                                             ├──> [ QueueJoiner ] ──> [ eCAR Formatter ] ──> [ DBWriter ] ──> [ telemetry.db ]
[ Process Lifecycle ] ──> [ ProcessMonitor ] ┘   (PID Joiner)         (JSON Schema)        (SQLite WAL)
```

### Sub-Module Specifications (`collector/`)

1. **`collector/file_monitor.py`**: Asynchronous file system observer (`watchdog` / `ReadDirectoryChangesW`) capturing `CREATE`, `MODIFY`, `DELETE`, and `MOVE` events. Features a **50ms sliding window deduplication filter** to eliminate Windows event spam.
2. **`collector/process_monitor.py`**: Background thread tracking process creation/termination and streaming **SHA-256 binary digests** with mtime caching to prevent CPU spikes.
3. **`collector/queue_joiner.py`**: Thread-safe queue pipeline implementing **3-tier PID resolution** (open handle scan $\rightarrow$ directory heuristic $\rightarrow$ `UNKNOWN` fallback) with live handle query fallback for newly spawned processes.
4. **`collector/ecar_formatter.py`**: Standardizes all events into MITRE extended Cyber Analytics Repository (eCAR) JSON schema (`actorID`, `objectID`, `pid`, `tid`, `principal`, `timestamp`, `operation`, `context`).
5. **`collector/db_writer.py`**: SQLite WAL persistence layer with **500-row batching** and dual indexing on `timestamp` and `pid`.
6. **`collector/main.py`**: Orchestrator entry point with Windows Administrator privilege verification (`IsUserAnAdmin()`) and graceful signal shutdown handling (`Ctrl+C`).

---

## 📁 Project Directory Structure

```text
H:/Final_year_project/ai-ransomware-defense-system/
├── collector/                # 🛡️ Stage 1 Ingestion Pipeline
│   ├── __init__.py           # Package marker (v1.0.0)
│   ├── file_monitor.py       # Watchdog observer (50ms event deduplication)
│   ├── process_monitor.py    # Process monitor & mtime SHA-256 hash cache
│   ├── queue_joiner.py       # Thread-safe queue & 3-tier PID resolver
│   ├── ecar_formatter.py     # MITRE eCAR JSON schema formatter
│   ├── db_writer.py          # SQLite WAL persistence layer (500-row batching)
│   └── main.py               # Main orchestrator & Admin privilege checker
├── tests/                    # 🧪 Automated Testing Package
│   ├── __init__.py           # Test package marker
│   └── test_stage1.py        # 20-test Pytest suite for Stage 1
├── Code/                     # 📓 Data Preprocessing & Attack Simulation Notebooks
│   ├── preprocessing.ipynb   # Model training & feature scaling (Stage 5 baseline)
│   ├── WatchDog.ipynb        # Prototype watchdog experiment
│   └── mock_ransomware.ipynb # Synthetic attack simulation script (Stage 8)
├── Dataset/                  # 📊 Dataset & Benchmark Metadata
│   ├── RansomwareData.csv    # RISS Behavioral Ransomware Dataset
│   └── Family Names ID.txt   # Malware family ID mapping reference
├── config.yaml               # ⚙️ Central System Configuration File
├── telemetry.db              # 💾 SQLite Event Database (WAL Mode)
└── README.md                 # 📖 Project Documentation
```

---

## 🚀 Quick Start & Developer Guide

### 1. Requirements & Setup
```bash
# Clone repository
git clone https://github.com/Kalyan-Burada/ai-ransomware-defense-system.git
cd ai-ransomware-defense-system

# Install dependencies
pip install watchdog psutil pyyaml pytest scikit-learn pandas numpy
```

### 2. Run Automated Stage 1 Test Suite
```bash
python -m pytest tests/test_stage1.py -v
```
> [!TIP]
> **Test Suite Note:**  
> All 20 unit and integration tests verify eCAR schema validity, PID resolution, deduplication, and SQLite WAL batching in ~20 seconds.

### 3. Launch Live Telemetry Collector (Run Terminal as Administrator)
```bash
python collector/main.py
```

### 4. Query `telemetry.db` for Stage 2 Development
Next developers building **Stage 2 (Lineage Analysis)** can query events directly from SQLite:
```python
import sqlite3

conn = sqlite3.connect('telemetry.db')
cur = conn.cursor()
recent_events = cur.execute(
    "SELECT timestamp, operation, pid, actor_id, object_id, raw_json "
    "FROM telemetry_events ORDER BY timestamp DESC LIMIT 10;"
).fetchall()

for evt in recent_events:
    print(evt)
```

---

## 🤝 Hand-off Guide for Next Steps (Stage 2+)

For team members continuing development:

1. **Stage 1 Hand-off Output:**
   * All raw OS file and process telemetry is continuously stored in `telemetry.db` $\rightarrow$ table `telemetry_events`.
   * Column `raw_json` contains full eCAR JSON context (`ppid`, `parent_exe`, `cmdline`, `sha256`, `exe_path`).
2. **Next Task (Stage 2: Lineage Analysis):**
   * Build `collector/process_context.py` to calculate parent-child spawning rarity scores ($S_{\text{rel}}$):
     $$S_{\text{rel}} = 1.0 - \frac{\text{Freq}(P_{\text{parent}} \rightarrow P_{\text{child}})}{\sum \text{Freq}(P_{\text{parent}} \rightarrow \text{All Children})}$$
   * Flag unseen execution chains (e.g. `winword.exe` $\rightarrow$ `powershell.exe`) with $S_{\text{rel}} = 1.0$.

---

## 📜 License

This project is open-source and available under the **MIT License**.
