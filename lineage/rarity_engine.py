import os
from collections import defaultdict

class RarityEngine:
    def __init__(self):
        # Known safe parent-child relationships (Low S_rel Score)
        self.safe_transitions = {
            "userinit.exe": ["explorer.exe"],
            "winlogon.exe": ["userinit.exe", "services.exe", "lsass.exe"],
            "services.exe": ["svchost.exe", "searchindexer.exe"],
            "svchost.exe": [
                "windowsterminal.exe", "wt.exe", "whatsapp.root.exe",
                "msedgewebview2.exe", "onedrive.exe", "conhost.exe"
            ],
            "whatsapp.root.exe": ["msedgewebview2.exe"],
            "explorer.exe": [
                "powershell.exe", "cmd.exe", "pwsh.exe", "winword.exe", "excel.exe",
                "chrome.exe", "brave.exe", "msedge.exe", "notepad.exe",
                "python.exe", "pythonw.exe", "py.exe", "code.exe",
                "taskmgr.exe", "calc.exe", "windowsterminal.exe", "wt.exe",
                "antigravity.exe", "antigravity ide.exe", "onedrive.exe"
            ],
            "windowsterminal.exe": [
                "powershell.exe", "cmd.exe", "pwsh.exe", "python.exe", "pythonw.exe", "py.exe",
                "node.exe", "git.exe", "conhost.exe", "bash.exe", "wsl.exe"
            ],
            "wt.exe": [
                "powershell.exe", "cmd.exe", "pwsh.exe", "python.exe", "pythonw.exe", "py.exe",
                "node.exe", "git.exe", "conhost.exe", "bash.exe", "wsl.exe"
            ],
            "antigravity ide.exe": [
                "powershell.exe", "cmd.exe", "pwsh.exe", "python.exe", "pythonw.exe", "py.exe",
                "node.exe", "git.exe", "conhost.exe", "bash.exe"
            ],
            "antigravity.exe": [
                "powershell.exe", "cmd.exe", "pwsh.exe", "python.exe", "pythonw.exe", "py.exe",
                "node.exe", "git.exe", "conhost.exe", "bash.exe"
            ],
            "code.exe": ["powershell.exe", "cmd.exe", "pwsh.exe", "python.exe", "py.exe", "git.exe", "conhost.exe", "bash.exe"],
            "devenv.exe": ["powershell.exe", "cmd.exe", "pwsh.exe", "conhost.exe", "git.exe"],
            "idea64.exe": ["powershell.exe", "cmd.exe", "pwsh.exe", "conhost.exe", "git.exe"],
            "pycharm64.exe": ["powershell.exe", "cmd.exe", "pwsh.exe", "conhost.exe", "git.exe", "python.exe"],
            "cmd.exe": ["conhost.exe", "ping.exe", "python.exe", "py.exe", "node.exe", "git.exe", "powershell.exe", "pwsh.exe"],
            "powershell.exe": ["conhost.exe", "python.exe", "py.exe", "node.exe", "git.exe", "cmd.exe", "pwsh.exe"],
            "pwsh.exe": ["conhost.exe", "python.exe", "py.exe", "node.exe", "git.exe", "cmd.exe"],
        }
        
        # Highly suspicious parent-child relationships (High S_rel Score - LotL attacks)
        self.malicious_transitions = {
            "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
            "excel.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
            "powershell.exe": ["vssadmin.exe", "bitsadmin.exe", "certutil.exe"],
            "cmd.exe": ["vssadmin.exe", "wbadmin.exe", "bcdedit.exe"],
        }

        # Dynamic frequency map: parent -> {child: count}
        self.transition_counts = defaultdict(lambda: defaultdict(int))

    def _extract_filename(self, file_path: str) -> str:
        """Extracts just the executable name (e.g., 'powershell.exe')."""
        if not file_path or file_path == "UNKNOWN":
            return "UNKNOWN"
        return os.path.basename(file_path).lower()

    def calculate_s_rel(self, parent_exe_path: str, child_exe_path: str) -> float:
        """
        Calculates the Lineage Rarity Score (S_{rel}).
        Returns a float between 0.0 (Safe / Common) and 1.0 (Critical Anomaly).
        
        Architecture Formula:
          S_{rel} = 1.0 - [ Freq(P_parent -> P_child) / Sum(Freq(P_parent -> All Children)) ]
          Unseen transitions default to S_{rel} -> 1.0
        """
        parent = self._extract_filename(parent_exe_path)
        child = self._extract_filename(child_exe_path)

        if parent == "UNKNOWN" or child == "UNKNOWN":
            return 0.5  # Neutral score if lineage was dropped (PID=-1)

        # 1. Check if the transition is explicitly malicious (Living-off-the-Land Attack)
        if parent in self.malicious_transitions and child in self.malicious_transitions[parent]:
            return 1.0  # Maximum Anomaly Score

        # 2. Check for standard self-spawning (e.g., chrome.exe -> chrome.exe, brave.exe -> brave.exe)
        if parent == child:
            self.transition_counts[parent][child] += 1
            return 0.05

        # 3. Check if parent -> child is in known safe transitions list
        if parent in self.safe_transitions and child in self.safe_transitions[parent]:
            self.transition_counts[parent][child] += 1
            total = sum(self.transition_counts[parent].values())
            count = self.transition_counts[parent][child]
            ratio = count / max(total, 1)
            return round(max(0.05, 0.20 - (0.15 * ratio)), 2)

        # 4. Check if this unlisted transition was completely unseen prior to this event
        is_unseen = (count := self.transition_counts[parent][child]) == 0

        # Record historical frequency
        self.transition_counts[parent][child] += 1
        total = sum(self.transition_counts[parent].values())
        count = self.transition_counts[parent][child]

        if is_unseen and total == 1:
            return 0.85  # Initial elevated score for first observation of unlisted transition

        # Dynamic frequency ratio score
        freq_ratio = count / max(total, 1)
        s_rel = 1.0 - (freq_ratio * 0.8)

        return round(max(0.15, min(1.0, s_rel)), 2)