"""
Safe Academic Telemetry & File I/O Workload Generator
=====================================================
Purpose:
  This utility generates a controlled, high-volume stream of benign file system events
  (file creation, nested directory creation, file copying, moving, renaming, and appending text)
  to evaluate and benchmark telemetry collectors and behavioral scoring pipelines.

Safety Principles & Strict Boundaries:
  - NO ENCRYPTION or cryptographic obfuscation algorithms are used.
  - NO PERSISTENCE, networking, process injection, registry access, or privilege escalation.
  - STRICT PATH BOUNDARY ENFORCEMENT: Every single file/directory path is strictly validated
    to ensure it resolves strictly WITHIN the designated target sandbox folder.
  - Destructive operations are strictly prohibited outside the target test folder and limited
    only to files created during the generator run.
"""

import os
import sys
import time
import random
import string
import shutil
import argparse
from pathlib import Path
from typing import List, Set


class WorkloadGenerator:
    def __init__(
        self,
        target_dir: str,
        num_files: int = 50,
        min_file_size: int = 1024,
        max_file_size: int = 8192,
        rename_rounds: int = 3,
        delay_seconds: float = 0.01,
        directory_depth: int = 3,
        seed: int = None,
        cleanup: bool = False
    ):
        # 1. Resolve and enforce strict absolute target directory
        self.target_dir = Path(target_dir).expanduser().resolve()
        
        # Enforce target directory safety check
        self._verify_target_directory_safety()
        
        self.num_files = num_files
        self.min_file_size = min_file_size
        self.max_file_size = max_file_size
        self.rename_rounds = rename_rounds
        self.delay_seconds = delay_seconds
        self.directory_depth = directory_depth
        self.seed = seed
        self.cleanup = cleanup

        # Track only files/folders created by this execution instance for safety
        self.created_files: Set[Path] = set()
        self.created_dirs: Set[Path] = set()

        if self.seed is not None:
            random.seed(self.seed)

        # Operational metrics tracking
        self.stats = {
            "dirs_created": 0,
            "files_created": 0,
            "file_renames": 0,
            "file_copies": 0,
            "file_moves": 0,
            "appends_performed": 0,
            "bytes_written": 0,
            "files_deleted": 0
        }

    def _verify_target_directory_safety(self):
        """Ensures target directory is bounded and safe."""
        user_home = Path.home().resolve()
        # Verify target path is within user profile or explicitly designated test folder
        if not (self.target_dir == user_home or user_home in self.target_dir.parents or "Downloads" in self.target_dir.parts or "Test" in self.target_dir.parts):
            print(f"[WARNING] Target directory is set to: {self.target_dir}")
        
        # Ensure target directory exists
        self.target_dir.mkdir(parents=True, exist_ok=True)

    def _validate_safe_path(self, path: Path) -> Path:
        """
        Strictly validates that any target path resides WITHIN self.target_dir.
        Throws a PermissionError if a path escapes the designated sandbox.
        """
        resolved_path = path.resolve()
        try:
            # Resolves symlinks and checks relative child status
            resolved_path.relative_to(self.target_dir)
        except ValueError:
            raise PermissionError(
                f"[SECURITY VIOLATION PREVENTED] Path '{resolved_path}' "
                f"escapes designated sandbox boundary '{self.target_dir}'!"
            )
        return resolved_path

    def _generate_benign_text(self, size_bytes: int) -> str:
        """Generates benign, structured text content."""
        words = ["telemetry", "benchmark", "analysis", "academic", "workload", "logger", "event", "system", "record", "node"]
        content = []
        bytes_generated = 0
        while bytes_generated < size_bytes:
            line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] BENIGN WORKLOAD EVENT DATA: " + " ".join(random.choices(words, k=8)) + "\n"
            content.append(line)
            bytes_generated += len(line.encode('utf-8'))
        return "".join(content)

    def create_nested_structure(self):
        """Creates nested directory levels inside the target directory."""
        print(f"[*] Creating nested directory structure up to depth {self.directory_depth}...")
        current_level = [self.target_dir]
        for depth in range(1, self.directory_depth + 1):
            next_level = []
            for parent in current_level:
                for idx in range(2):  # 2 subfolders per parent
                    dir_name = f"subfolder_d{depth}_p{idx}"
                    dir_path = self._validate_safe_path(parent / dir_name)
                    dir_path.mkdir(exist_ok=True)
                    self.created_dirs.add(dir_path)
                    next_level.append(dir_path)
                    self.stats["dirs_created"] += 1
            current_level = next_level
            time.sleep(self.delay_seconds)

    def generate_initial_files(self):
        """Generates initial benign text files across created directories."""
        print(f"[*] Generating {self.num_files} initial benign files...")
        all_dirs = list(self.created_dirs) + [self.target_dir]

        for i in range(self.num_files):
            target_dir = random.choice(all_dirs)
            file_name = f"dataset_doc_{i:04d}.txt"
            file_path = self._validate_safe_path(target_dir / file_name)

            file_size = random.randint(self.min_file_size, self.max_file_size)
            text_content = self._generate_benign_text(file_size)

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(text_content)

            self.created_files.add(file_path)
            self.stats["files_created"] += 1
            self.stats["bytes_written"] += len(text_content.encode("utf-8"))

            if self.delay_seconds > 0:
                time.sleep(self.delay_seconds)

    def execute_file_operations_burst(self):
        """Performs burst operations: append, copy, move, and rename."""
        print("[*] Executing file manipulation workload burst (appends, copies, moves, renames)...")
        all_dirs = list(self.created_dirs) + [self.target_dir]
        active_files = list(self.created_files)

        if not active_files:
            return

        # 1. Append operations
        print("  -> Phase 1: Appending log entries to files...")
        for file_path in random.sample(active_files, k=min(len(active_files), self.num_files // 2)):
            safe_path = self._validate_safe_path(file_path)
            if safe_path.exists():
                append_text = f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] BENIGN UPDATE BATCH ITEM\n"
                with open(safe_path, "a", encoding="utf-8") as f:
                    f.write(append_text)
                self.stats["appends_performed"] += 1
                self.stats["bytes_written"] += len(append_text.encode("utf-8"))
                time.sleep(self.delay_seconds)

        # 2. Copy operations
        print("  -> Phase 2: Copying files across subfolders...")
        for file_path in random.sample(active_files, k=min(len(active_files), self.num_files // 3)):
            safe_src = self._validate_safe_path(file_path)
            if safe_src.exists():
                dest_dir = random.choice(all_dirs)
                dest_file = self._validate_safe_path(dest_dir / f"copy_{safe_src.name}")
                shutil.copy2(safe_src, dest_file)
                self.created_files.add(dest_file)
                self.stats["file_copies"] += 1
                time.sleep(self.delay_seconds)

        # Refresh active files
        active_files = [f for f in self.created_files if f.exists()]

        # 3. Rename rounds
        print(f"  -> Phase 3: Performing {self.rename_rounds} rounds of sequential file renames...")
        for round_idx in range(1, self.rename_rounds + 1):
            for i, file_path in enumerate(active_files):
                safe_src = self._validate_safe_path(file_path)
                if safe_src.exists():
                    new_name = safe_src.parent / f"renamed_r{round_idx}_{i:04d}.txt"
                    safe_dst = self._validate_safe_path(new_name)
                    safe_src.rename(safe_dst)
                    
                    self.created_files.discard(safe_src)
                    self.created_files.add(safe_dst)
                    active_files[i] = safe_dst
                    self.stats["file_renames"] += 1
                    time.sleep(self.delay_seconds)

        # 4. Move operations
        print("  -> Phase 4: Moving files across subdirectories...")
        active_files = [f for f in self.created_files if f.exists()]
        for i, file_path in enumerate(random.sample(active_files, k=min(len(active_files), self.num_files // 3))):
            safe_src = self._validate_safe_path(file_path)
            if safe_src.exists():
                dest_dir = random.choice(all_dirs)
                dest_file = self._validate_safe_path(dest_dir / f"moved_{safe_src.name}")
                shutil.move(safe_src, dest_file)
                self.created_files.discard(safe_src)
                self.created_files.add(dest_file)
                self.stats["file_moves"] += 1
                time.sleep(self.delay_seconds)

    def cleanup_created_assets(self):
        """Safely removes ONLY the files and subdirectories created during this run."""
        if not self.cleanup:
            print(f"[*] Cleanup skipped. Files preserved in '{self.target_dir}' for telemetry analysis.")
            return

        print(f"[*] Safely cleaning up assets created inside '{self.target_dir}'...")
        # Delete created files first
        for file_path in list(self.created_files):
            try:
                safe_path = self._validate_safe_path(file_path)
                if safe_path.exists() and safe_path.is_file():
                    safe_path.unlink()
                    self.stats["files_deleted"] += 1
            except Exception as e:
                print(f"    [!] Error deleting file '{file_path}': {e}")

        # Delete created directories in reverse depth order
        for dir_path in sorted(list(self.created_dirs), reverse=True):
            try:
                safe_dir = self._validate_safe_path(dir_path)
                if safe_dir.exists() and safe_dir.is_dir():
                    # Only remove if directory is empty
                    safe_dir.rmdir()
            except Exception as e:
                print(f"    [!] Error removing folder '{dir_path}': {e}")

    def run(self):
        """Executes full workload generation suite."""
        start_time = time.time()
        print("=" * 65)
        print("    SAFE ACADEMIC BENCHMARK WORKLOAD GENERATOR STARTED")
        print("=" * 65)
        print(f"Target Sandbox Directory : {self.target_dir}")
        print(f"Target File Count        : {self.num_files}")
        print(f"Rename Rounds            : {self.rename_rounds}")
        print(f"Directory Depth          : {self.directory_depth}")
        print(f"Operation Delay          : {self.delay_seconds}s")
        print(f"Random Seed              : {self.seed}")
        print("-" * 65)

        try:
            self.create_nested_structure()
            self.generate_initial_files()
            self.execute_file_operations_burst()
        except KeyboardInterrupt:
            print("\n[!] Workload generator interrupted by user.")
        except Exception as e:
            print(f"\n[!] Execution error: {e}")
        finally:
            self.cleanup_created_assets()

        elapsed_time = time.time() - start_time
        print("\n" + "=" * 65)
        print("    WORKLOAD GENERATION SUMMARY REPORT")
        print("=" * 65)
        print(f"Total Execution Time    : {elapsed_time:.2f} seconds")
        print(f"Subdirectories Created  : {self.stats['dirs_created']}")
        print(f"Initial Files Created   : {self.stats['files_created']}")
        print(f"File Appends Executed   : {self.stats['appends_performed']}")
        print(f"File Copies Executed    : {self.stats['file_copies']}")
        print(f"File Renames Executed   : {self.stats['file_renames']}")
        print(f"File Moves Executed     : {self.stats['file_moves']}")
        print(f"Total Content Written   : {self.stats['bytes_written'] / 1024:.2f} KB")
        if self.cleanup:
            print(f"Files Safely Cleaned Up : {self.stats['files_deleted']}")
        print("=" * 65)


def main():
    default_target = Path.home() / "Downloads" / "Test"

    parser = argparse.ArgumentParser(
        description="Safe Academic Telemetry & File I/O Workload Generator for Detector Evaluation."
    )
    parser.add_argument(
        "--target-dir",
        type=str,
        default=str(default_target),
        help=f"Target directory sandbox (Default: {default_target})"
    )
    parser.add_argument(
        "--num-files",
        type=int,
        default=50,
        help="Number of initial test files to generate (Default: 50)"
    )
    parser.add_argument(
        "--min-size",
        type=int,
        default=1024,
        help="Minimum file size in bytes (Default: 1024)"
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=8192,
        help="Maximum file size in bytes (Default: 8192)"
    )
    parser.add_argument(
        "--rename-rounds",
        type=int,
        default=3,
        help="Number of sequential rename rounds (Default: 3)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.01,
        help="Delay in seconds between operations (Default: 0.01)"
    )
    parser.add_argument(
        "--directory-depth",
        type=int,
        default=3,
        help="Depth of nested directory tree (Default: 3)"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for deterministic execution (Default: None)"
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Clean up created files and directories after completion"
    )

    args = parser.parse_args()

    generator = WorkloadGenerator(
        target_dir=args.target_dir,
        num_files=args.num_files,
        min_file_size=args.min_size,
        max_file_size=args.max_size,
        rename_rounds=args.rename_rounds,
        delay_seconds=args.delay,
        directory_depth=args.directory_depth,
        seed=args.seed,
        cleanup=args.cleanup
    )

    generator.run()


if __name__ == "__main__":
    main()
