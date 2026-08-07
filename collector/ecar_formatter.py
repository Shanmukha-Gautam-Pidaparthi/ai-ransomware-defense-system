"""
collector/ecar_formatter.py
============================
Stage 1 — eCAR Model Formatting

Formats raw enriched event dicts into JSON structured per the extended
Cyber Analytics Repository (eCAR) model.

eCAR fields (per Architecture Doc, Stage 1 Minor Implementations):
  - actorID    : "pid:<PID>" — the process that performed the action
  - objectID   : "file:<absolute_path>" — the file object acted upon
  - pid        : integer process ID
  - tid        : integer thread ID of the watchdog handler
  - principal  : "DOMAIN\\username" of the process owner
  - timestamp  : Unix epoch milliseconds (high-resolution)
  - operation  : one of FILE_CREATE | FILE_MODIFY | FILE_DELETE | FILE_MOVE
  - context    : dict with exe_path, sha256, ppid, parent_exe, cmdline
  - ecar_ver   : schema version string (from config)

This module has NO external dependencies (pure Python stdlib + typing).
It is the canonical schema contract between Stage 1 and all downstream stages.
"""

import json
import time
import getpass
import socket
from typing import Optional, Dict, Any

# Map watchdog event type strings to canonical eCAR operation names
_OP_MAP: Dict[str, str] = {
    "created":  "FILE_CREATE",
    "modified": "FILE_MODIFY",
    "deleted":  "FILE_DELETE",
    "moved":    "FILE_MOVE",
}

# Fallback values used when a field cannot be resolved
_UNKNOWN_SHA256   = "UNKNOWN"
_UNKNOWN_PID      = -1
_UNKNOWN_EXE      = "UNKNOWN"
_UNKNOWN_PRINCIPAL = "UNKNOWN\\UNKNOWN"


def _get_principal() -> str:
    """Return DOMAIN\\username of the current user (best-effort)."""
    try:
        domain = socket.gethostname()
        user   = getpass.getuser()
        return f"{domain}\\{user}"
    except Exception:
        return _UNKNOWN_PRINCIPAL


def format_event(
    file_path: str,
    operation: str,
    timestamp_ms: int,
    tid: int,
    pid: int                  = _UNKNOWN_PID,
    exe_path: str             = _UNKNOWN_EXE,
    sha256: str               = _UNKNOWN_SHA256,
    ppid: int                 = _UNKNOWN_PID,
    parent_exe: str           = _UNKNOWN_EXE,
    cmdline: Optional[list]   = None,
    dest_path: Optional[str]  = None,   # for FILE_MOVE: the rename destination
    ecar_ver: str             = "1.0",
    principal: Optional[str]  = None,
) -> Dict[str, Any]:
    """
    Build and return a complete eCAR event dict.

    Parameters
    ----------
    file_path    : Absolute path of the affected file.
    operation    : Watchdog event type string (created/modified/deleted/moved).
    timestamp_ms : High-resolution Unix timestamp in milliseconds.
    tid          : Thread ID of the event-generating watchdog handler thread.
    pid          : PID of the process that caused the event (-1 if unknown).
    exe_path     : Full path of the process executable.
    sha256       : SHA-256 hex digest of the executable binary.
    ppid         : Parent PID.
    parent_exe   : Parent process executable path.
    cmdline      : Command-line args list.
    dest_path    : For renamed/moved files, the new destination path.
    ecar_ver     : eCAR schema version (from config.yaml).
    principal    : "DOMAIN\\user" string; auto-detected if None.

    Returns
    -------
    dict — the structured eCAR event ready for JSON serialisation.
    """
    canonical_op = _OP_MAP.get(operation.lower(), f"FILE_{operation.upper()}")
    resolved_principal = principal if principal else _get_principal()

    ecar_event: Dict[str, Any] = {
        # ── Core eCAR fields ──────────────────────────────────────────────
        "actorID":   f"pid:{pid}",
        "objectID":  f"file:{file_path}",
        "pid":       pid,
        "tid":       tid,
        "principal": resolved_principal,
        "timestamp": timestamp_ms,          # Unix ms — indexed in SQLite
        "operation": canonical_op,
        "ecar_ver":  ecar_ver,

        # ── Context properties map (Stage 2 consumes this) ────────────────
        "context": {
            "exe_path":   exe_path,
            "sha256":     sha256,
            "ppid":       ppid,
            "parent_exe": parent_exe,
            "cmdline":    cmdline or [],
            # FILE_MOVE only: the post-rename destination
            "dest_path":  dest_path,
        },
    }

    return ecar_event


def serialize(event: Dict[str, Any]) -> str:
    """
    Serialize an eCAR event dict to a compact JSON string.
    Used by db_writer before inserting into SQLite raw_json column.
    """
    return json.dumps(event, separators=(",", ":"), ensure_ascii=False)


def deserialize(raw_json: str) -> Dict[str, Any]:
    """
    Deserialize a raw JSON string back to an eCAR event dict.
    Used by downstream stages when reading from SQLite.
    """
    return json.loads(raw_json)


def now_ms() -> int:
    """Return the current high-resolution Unix timestamp in milliseconds."""
    return int(time.time() * 1000)
