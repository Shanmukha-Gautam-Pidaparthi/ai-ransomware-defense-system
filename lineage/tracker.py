import json
import sqlite3
import time
import os
import psutil
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

class LineageTracker:
    def __init__(self, db_path="telemetry.db", start_at_latest=False):
        self.raw_db_path = db_path
        self.db_path = self._resolve_db_path(db_path)
        self.process_cache = {}  # In-memory mapping: {pid: {"exe": exe_name, "ppid": ppid, "parent_exe": parent_exe}}
        self.last_processed_id = self._get_max_id() if start_at_latest else 0


    def _resolve_db_path(self, db_path: str) -> str:
        """Dynamically resolves db_path to absolute project root path if relative."""
        target = Path(db_path)
        if target.is_absolute():
            return str(target)
        
        candidates = [
            _PROJECT_ROOT / db_path,
            Path.cwd() / db_path,
            Path(__file__).resolve().parent / db_path,
        ]
        for cand in candidates:
            if cand.is_file():
                return str(cand.resolve())
        
        # Default to project root
        return str((_PROJECT_ROOT / db_path).resolve())

    def _get_max_id(self) -> int:
        """Fetches the highest current event ID in telemetry.db to skip historical events on live launch."""
        resolved = self._resolve_db_path(self.raw_db_path)
        if not Path(resolved).is_file():
            return 0
        try:
            conn = sqlite3.connect(resolved, timeout=5.0)
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(id) FROM telemetry_events")
            row = cursor.fetchone()
            conn.close()
            return row[0] if (row and row[0]) else 0
        except Exception:
            return 0

    def parse_ecar_context(self, raw_json):
        """Extracts lineage data and event details from Stage 1's eCAR JSON payload."""
        try:
            event = json.loads(raw_json)
            context = event.get("context", {})
            raw_obj = event.get("objectID", "")
            file_path = raw_obj[5:] if raw_obj.startswith("file:") else raw_obj
            return {
                "pid": event.get("pid"),
                "exe_path": context.get("exe_path", "UNKNOWN"),
                "ppid": context.get("ppid", -1),
                "parent_exe": context.get("parent_exe", "UNKNOWN"),
                "operation": event.get("operation", "FILE_EVENT"),
                "file_path": file_path,
            }
        except json.JSONDecodeError:
            return None

    def update_tree(self):
        """Polls telemetry.db for new events and updates the process tree."""
        # Re-verify DB path in case telemetry.db was created after initialization
        resolved = self._resolve_db_path(self.raw_db_path)
        if not Path(resolved).is_file():
            return []

        self.db_path = resolved
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            cursor = conn.cursor()
            
            # Fetch only new events based on the last processed ID
            cursor.execute(
                "SELECT id, raw_json FROM telemetry_events WHERE id > ? ORDER BY id ASC", 
                (self.last_processed_id,)
            )
            rows = cursor.fetchall()
            
            events_processed = []
            for row_id, raw_json in rows:
                self.last_processed_id = row_id
                process_info = self.parse_ecar_context(raw_json)
                
                if process_info:
                    raw_pid = process_info.get("pid")
                    pid = raw_pid if (raw_pid is not None and isinstance(raw_pid, int)) else -1
                    process_info["pid"] = pid
                    
                    is_new = (pid != -1 and pid not in self.process_cache)
                    if pid != -1:
                        self.process_cache[pid] = process_info
                    process_info["is_new_pid"] = is_new

                    # Attach full ancestor lineage chain if available
                    process_info["lineage_chain"] = self.get_lineage_chain(pid)
                    events_processed.append(process_info)
                        
            conn.close()
            return events_processed
        except sqlite3.OperationalError:
            # DB locked or initializing by Stage 1
            return []

    def get_lineage(self, pid):
        """Retrieves the process context mapping for a specific PID."""
        return self.process_cache.get(pid, None)

    def _walk_live_ancestors(self, start_pid: int, max_depth: int = 32) -> list:
        """
        Fallback for ancestors that never triggered their own file event, so
        they have no entry in process_cache/telemetry.db. Walks the LIVE OS
        process tree via psutil instead, starting at start_pid and going up.

        Only works if the ancestor process is STILL RUNNING at the moment
        Stage 2 processes the event. If an intermediate ancestor has already
        exited by then (a real race condition, inherent to any live-polling
        design -- not fixable from Stage 2 alone), the walk stops there.
        """
        chain = []
        try:
            pid = start_pid
            seen = set()
            depth = 0
            while pid and pid > 0 and pid not in seen and depth < max_depth:
                seen.add(pid)
                try:
                    proc = psutil.Process(pid)
                    exe = os.path.basename(proc.exe() or proc.name() or "UNKNOWN")
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    break
                chain.insert(0, exe)
                try:
                    pid = proc.ppid()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break
                depth += 1
        except Exception:
            pass
        return chain

    def get_lineage_chain(self, pid) -> list:
        """
        Recursively traces parent process execution provenance up the tree.
        Returns ancestor chain: [Root_Ancestor, ..., Parent_Process, Executing_Child]

        DB-derived process_cache only has entries for PIDs that themselves
        generated a file event. The moment the walk hits an ancestor pid that
        never wrote a file itself, it now falls back to a LIVE psutil walk
        (_walk_live_ancestors) instead of silently truncating the chain.
        """
        # If the PID is not in our cache, try a live psutil walk first
        # (helps with short-lived actors). Fall back to cached parent/child
        # strings if psutil cannot resolve the ancestry at this time.
        if not pid or pid == -1 or pid not in self.process_cache:
            if isinstance(pid, int) and pid > 0:
                live = self._walk_live_ancestors(pid)
                if live:
                    # Remove consecutive duplicate entries (e.g. same exe listed twice)
                    deduped = [v for i, v in enumerate(live) if i == 0 or v != live[i-1]]
                    return deduped

            info = self.process_cache.get(pid, {})
            parent_exe = info.get("parent_exe", "UNKNOWN")
            child_exe = info.get("exe_path", "UNKNOWN")
            p_base = os.path.basename(parent_exe)
            c_base = os.path.basename(child_exe)
            # Collapse consecutive duplicates
            if p_base == c_base:
                return [p_base]
            return [p_base, c_base]

        chain = []
        curr_pid = pid
        visited = set()

        while curr_pid and curr_pid != -1 and curr_pid not in visited:
            visited.add(curr_pid)
            info = self.process_cache.get(curr_pid)
            if not info:
                live_ancestors = self._walk_live_ancestors(curr_pid)
                chain = live_ancestors + chain
                break
            exe = os.path.basename(info.get("exe_path", "UNKNOWN"))
            chain.insert(0, exe)
            curr_pid = info.get("ppid", -1)

        if len(chain) == 1:
            child_info = self.process_cache.get(pid, {})
            parent_exe = os.path.basename(child_info.get("parent_exe", "UNKNOWN"))
            chain.insert(0, parent_exe)

        # Remove consecutive duplicate exe names to avoid repeated entries
        dedup_chain = [v for i, v in enumerate(chain) if i == 0 or v != chain[i-1]]
        return dedup_chain

