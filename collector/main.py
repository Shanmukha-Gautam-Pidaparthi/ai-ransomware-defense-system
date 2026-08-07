"""
collector/main.py
==================
Stage 1 — Orchestrator / Entry Point

Wires all Stage 1 sub-components together into a single, runnable pipeline:

  [OS File Events]
       ↓ (watchdog Observer via ReadDirectoryChangesW)
  [FileMonitor]  →  raw_event_queue  →  [QueueJoiner]
                                              ↓ (PID resolve via psutil)
                                        [ecar_formatter.format_event]
                                              ↓
                                         [DBWriter]  →  telemetry.db
                                              ↓
                                        [ProcessMonitor] (background poll)

Usage:
    python collector/main.py                    # uses config.yaml in project root
    python collector/main.py --config my.yaml   # custom config path
    python collector/main.py --verbose          # DEBUG logging

Keyboard Interrupt (Ctrl+C) triggers a clean, ordered shutdown:
  1. FileMonitor.stop()   — stop watchdog observer
  2. QueueJoiner.stop()   — drain remaining events from queue
  3. DBWriter.stop()      — flush remaining events to SQLite
  4. ProcessMonitor.stop()— stop background polling thread
"""

import argparse
import logging
import os
import queue
import signal
import sys
import time
from pathlib import Path

import yaml

# ── Ensure project root is in sys.path when run directly ──────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from collector.file_monitor    import FileMonitor
from collector.process_monitor import ProcessMonitor
from collector.queue_joiner    import QueueJoiner
from collector.db_writer       import DBWriter

# ─── Defaults (used if config.yaml is absent) ─────────────────────────────────

_DEFAULT_CONFIG = {
    "monitor": {
        "paths":     ["~/Downloads", "~/Documents", "~/Desktop"],
        "recursive": True,
    },
    "process_monitor": {
        "poll_interval_sec": 1.0,
        "hash_timeout_sec":  2.0,
        "skip_system_pids":  True,
    },
    "queue": {
        "maxsize":          10000,
        "join_timeout_sec": 0.5,
    },
    "database": {
        "path":       "telemetry.db",
        "wal_mode":   True,
        "batch_size": 50,
    },
    "logging": {
        "level":   "INFO",
        "console": True,
        "file":    "logs/stage1.log",
    },
    "telemetry": {
        "ecar_version": "1.0",
    },
}


# ─── Logging Setup ─────────────────────────────────────────────────────────────

def _setup_logging(log_cfg: dict, verbose: bool = False) -> None:
    """Configure console + file logging based on config."""
    level_str = "DEBUG" if verbose else log_cfg.get("level", "INFO")
    level     = getattr(logging, level_str.upper(), logging.INFO)

    handlers = []

    if log_cfg.get("console", True):
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(level)
        fmt = logging.Formatter(
            "[%(asctime)s] [%(levelname)-7s] [%(threadName)s] %(message)s",
            datefmt="%H:%M:%S",
        )
        ch.setFormatter(fmt)
        handlers.append(ch)

    log_file = log_cfg.get("file", "logs/stage1.log")
    if log_file:
        log_dir = Path(log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(
            logging.Formatter(
                "[%(asctime)s] [%(levelname)-7s] [%(threadName)s] %(message)s"
            )
        )
        handlers.append(fh)

    logging.basicConfig(level=level, handlers=handlers, force=True)


# ─── Config Loader ─────────────────────────────────────────────────────────────

def _load_config(config_path: str) -> dict:
    """Load YAML config, merging with defaults for any missing keys."""
    cfg = dict(_DEFAULT_CONFIG)

    path = Path(config_path)
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            user_cfg = yaml.safe_load(fh) or {}
        # Deep-merge top-level sections
        for section, values in user_cfg.items():
            if isinstance(values, dict) and section in cfg:
                cfg[section].update(values)
            else:
                cfg[section] = values
        logging.info(f"Config loaded from: {path.resolve()}")
    else:
        logging.warning(f"Config file not found: {path}  — using defaults.")

    return cfg


# ─── Live Display Callback ──────────────────────────────────────────────────────

def _make_console_callback(logger: logging.Logger):
    """Return a callback function that prints eCAR events to the console."""
    def _cb(ecar_event: dict) -> None:
        pid  = ecar_event.get("pid", -1)
        op   = ecar_event.get("operation", "?")
        obj  = ecar_event.get("objectID", "?")
        sha  = ecar_event.get("context", {}).get("sha256", "?")[:12]
        ts   = ecar_event.get("timestamp", 0)
        pid_str = str(pid) if pid != -1 else "UNKNOWN"
        logger.info(
            f"[Stage 1] {op:<14} | PID={pid_str:<8} | SHA={sha}... | {obj}"
        )
    return _cb


# ─── Admin Check Helper ───────────────────────────────────────────────────────

def _is_admin() -> bool:
    """Return True if running with Administrator privileges on Windows."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False  # Non-Windows or fallback


# ─── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    # ── Argument parsing ─────────────────────────────────────────────────────
    parser = argparse.ArgumentParser(
        description="AI Ransomware Defense — Stage 1: Telemetry Collection"
    )
    parser.add_argument(
        "--config",
        default=str(_PROJECT_ROOT / "config.yaml"),
        help="Path to config.yaml (default: project root)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG logging",
    )
    args = parser.parse_args()

    # ── Load config ──────────────────────────────────────────────────────────
    cfg = _load_config(args.config)

    # ── Setup logging ────────────────────────────────────────────────────────
    _setup_logging(cfg.get("logging", {}), verbose=args.verbose)
    log = logging.getLogger(__name__)

    log.info("=" * 60)
    log.info("  AI Ransomware Defense System — Stage 1")
    log.info("  Telemetry Collection & File I/O Interception")
    log.info("=" * 60)

    # ── Admin Check Warning ──────────────────────────────────────────────────
    if sys.platform == "win32":
        if _is_admin():
            log.info("[Main] ✅ Running with Administrator privileges (Full OS visibility).")
        else:
            log.warning(
                "[Main] ⚠️  NOT RUNNING AS ADMINISTRATOR!\n"
                "       Windows handle scanning (Tier 1 PID resolution) will be limited to user-space processes.\n"
                "       For 100% full kernel visibility, run your terminal as Administrator."
            )

    # ── Resolve DB path relative to project root ──────────────────────────────
    db_path_raw = cfg["database"]["path"]
    db_path     = str(_PROJECT_ROOT / db_path_raw) if not Path(db_path_raw).is_absolute() else db_path_raw

    # ── Step 1: Initialize asynchronous thread-safe event queue Q ─────────────
    raw_queue: queue.Queue = queue.Queue(maxsize=cfg["queue"]["maxsize"])
    log.info(f"[Main] Event queue initialized (maxsize={cfg['queue']['maxsize']})")

    # ── Instantiate all components ────────────────────────────────────────────
    db_writer = DBWriter(
        db_path    = db_path,
        batch_size = cfg["database"]["batch_size"],
        wal_mode   = cfg["database"]["wal_mode"],
    )

    process_monitor = ProcessMonitor(
        poll_interval_sec = cfg["process_monitor"]["poll_interval_sec"],
        hash_timeout_sec  = cfg["process_monitor"]["hash_timeout_sec"],
        skip_system_pids  = cfg["process_monitor"]["skip_system_pids"],
    )

    file_monitor = FileMonitor(
        paths           = cfg["monitor"]["paths"],
        recursive       = cfg["monitor"]["recursive"],
        dedup_window_ms = cfg["monitor"].get("dedup_window_ms", 50),
    )

    queue_joiner = QueueJoiner(
        raw_queue        = raw_queue,
        process_monitor  = process_monitor,
        db_writer        = db_writer,
        join_timeout_sec = cfg["queue"]["join_timeout_sec"],
        ecar_ver         = cfg["telemetry"]["ecar_version"],
        on_event_callback = _make_console_callback(log),
    )

    # ── Graceful shutdown handler ──────────────────────────────────────────────
    def _shutdown(signum=None, frame=None) -> None:
        log.info("\n[Main] Shutdown signal received — stopping all components...")
        try:
            file_monitor.stop()
            log.info("[Main] FileMonitor stopped.")
        except Exception as exc:
            log.error(f"[Main] FileMonitor stop error: {exc}")
        try:
            queue_joiner.stop()
            log.info("[Main] QueueJoiner stopped.")
        except Exception as exc:
            log.error(f"[Main] QueueJoiner stop error: {exc}")
        try:
            db_writer.stop()
            log.info("[Main] DBWriter stopped.")
        except Exception as exc:
            log.error(f"[Main] DBWriter stop error: {exc}")
        try:
            process_monitor.stop()
            log.info("[Main] ProcessMonitor stopped.")
        except Exception as exc:
            log.error(f"[Main] ProcessMonitor stop error: {exc}")

        log.info(
            f"\n[Main] ✅ Stage 1 shutdown complete.\n"
            f"       Total events written : {db_writer.total_written}\n"
            f"       PID resolved         : {queue_joiner.total_joined}\n"
            f"       PID unknown          : {queue_joiner.total_unknown}\n"
            f"       DB path              : {db_path}\n"
        )
        sys.exit(0)

    # Register signal handlers for clean Ctrl+C on Windows and Linux
    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # ── Start components in dependency order ───────────────────────────────────
    try:
        # 1. DB (must be ready before QueueJoiner can write)
        db_writer.start()
        log.info(f"[Main] DBWriter started → {db_path}")

        # 2. Process monitor (must populate registry before QueueJoiner does PID joins)
        process_monitor.start()
        log.info("[Main] ProcessMonitor started.")

        # 3. Queue joiner (must be consuming before FileMonitor starts producing)
        queue_joiner.start()
        log.info("[Main] QueueJoiner started.")

        # 4. File monitor — Step 2: Register kernel file watchdogs
        file_monitor.start(raw_queue)
        log.info(
            f"[Main] FileMonitor started. Monitoring:\n"
            + "\n".join(f"       → {p}" for p in file_monitor.monitored_paths)
        )

        log.info(
            "\n[Main] 🛡️  Stage 1 ACTIVE — Monitoring file system events.\n"
            "       Press Ctrl+C to stop and flush all events.\n"
        )

        # ── Main keep-alive loop ───────────────────────────────────────────────
        while True:
            time.sleep(2)
            if not file_monitor.is_alive():
                log.error("[Main] FileMonitor observer died unexpectedly — restarting...")
                file_monitor.stop()
                file_monitor.start(raw_queue)

    except Exception as exc:
        log.error(f"[Main] Startup error: {exc}", exc_info=True)
        _shutdown()


if __name__ == "__main__":
    main()
