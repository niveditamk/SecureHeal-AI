"""Git-based patch management for SecureHeal-AI.

Handles creation of Git branches, diff generation, patch application,
and rollback to original code. Integrates with the repair and governance
agents to ensure safe code modifications.
"""

from __future__ import annotations

import difflib
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("secureheal.gitops.patch_manager")


class PatchResult:
    """Result of a patch operation."""
    def __init__(
        self,
        success: bool,
        message: str,
        rollback_id: Optional[str] = None,
        diff_path: Optional[str] = None,
        original_backup: Optional[str] = None,
    ):
        self.success = success
        self.message = message
        self.rollback_id = rollback_id
        self.diff_path = diff_path
        self.original_backup = original_backup

    def __repr__(self):
        return f"PatchResult(success={self.success}, message='{self.message}'"


class PatchManager:
    """Manages Git-based patch application and rollback for SecureHeal-AI."""

    def __init__(self, repo_path: str = "."):
        """Initialize the PatchManager.

        Args:
            repo_path: Path to the Git repository root
        """
        self.repo_path = str(Path(repo_path).resolve())
        self.repo = None
        self._initialize_repo()

    def _initialize_repo(self) -> None:
        """Initialize or validate the Git repository."""
        try:
            # Verify it's a Git repo
            result = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                self.repo_path = str(Path(subprocess.check_output(
                    ["git", "rev-parse", "--git-dir"],
                    cwd=self.repo_path,
                    timeout=10,
                ).decode().strip()).parent)
                logger.info("Git repository initialized at %s", self.repo_path)
            else:
                logger.warning("Not a Git repository at %s", self.repo_path)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning("Git not available: %s", e)
            self.repo_path = str(Path(self.repo_path).resolve())

    def create_backup(self, description: str = "pre_patch_backup") -> Optional[str]:
        """Create a backup of the current code state.

        Args:
            description: Description/label for the backup point

        Returns:
            Path to the backup directory, or None if Git not available
        """
        try:
            # Create a rollback point via the RollbackManager
            from secureheal.governance.rollback import RollbackManager
            rm = RollbackManager()
            point = rm.create_rollback_point(
                service_name="unknown",
                patch_id=description,
            )
            backup_id = point["rollback_id"]
            logger.info("Created rollback backup point: %s", backup_id)
            return backup_id
        except Exception as e:
            logger.warning("Could not create git backup: %s", e)
            # Fallback: create a simple file backup
            try:
                backup_dir = Path(self.repo_path) / ".secureheal" / "backups"
                backup_dir.mkdir(parents=True, exist_ok=True)
                import shutil
                # Copy all Python files
                for py_file in Path(self.repo_path).rglob("*.py"):
                    if ".secureheal" not in str(py_file):
                        dest = backup_dir / py_file.relative_to(self.repo_path)
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(py_file, dest)
                logger.info("Created file-based backup at %s", backup_dir)
                return str(backup_dir)
            except Exception as e2:
                logger.error("Failed to create any backup: %s", e2)
                return None

    def generate_diff(
        self,
        original_code: str,
        patched_code: str,
        file_path: str,
    ) -> Optional[str]:
        """Generate a unified diff between original and patched code.

        Args:
            original_code: The vulnerable code snippet
            patched_code: The corrected code snippet
            file_path: The file being patched (relative to repo root)

        Returns:
            Unified diff string, or None if git not available
        """
        try:
            original_lines = original_code.splitlines(keepends=True)
            patched_lines = patched_code.splitlines(keepends=True)

            diff = list(
                difflib.unified_diff(
                    original_lines,
                    patched_lines,
                    fromfile=f"a/{file_path}",
                    tofile=f"b/{file_path}",
                    lineterm="",
                )
            )
            return "".join(diff)
        except Exception as e:
            logger.error("Failed to generate diff: %s", e)
            return None

    def create_patch_branch(
        self,
        branch_name: str,
        base_branch: str = "main",
    ) -> Tuple[Optional[str], Optional[str]]:
        """Create a new Git branch for patch development.

        Args:
            branch_name: Name for the new patch branch
            base_branch: Branch to base the patch on (default: main)

        Returns:
            Tuple of (branch_name, error_message)
            - If successful: (branch_name, None)
            - If failed: (None, error_message)
        """
        try:
            # Check if branch already exists
            result = subprocess.run(
                ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch_name}"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                # Branch exists, return existing name
                logger.info("Branch %s already exists", branch_name)
                return (branch_name, None)

            # Create and checkout the new branch
            result = subprocess.run(
                ["git", "checkout", "-b", branch_name, f"{base_branch}"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                error_msg = f"Failed to create branch {branch_name}: {result.stderr}" if result.stderr else "Failed to create branch " + branch_name
                logger.error(error_msg)
                return (None, error_msg)

            logger.info("Created and checkout branch: %s", branch_name)
            return (branch_name, None)

        except subprocess.TimeoutExpired:
            logger.error("Git command timed out while creating branch")
            return (None, "Git command timed out")
        except FileNotFoundError:
            logger.warning("Git not available - cannot create branch")
            return (None, "Git not available")
        except Exception as e:
            logger.exception("Unexpected error creating patch branch")
            return (None, str(e))

    def apply_patch(
        self,
        file_path: str,
        original_code: str,
        patched_code: str,
    ) -> PatchResult:
        """Apply a patch to the specified file.

        Creates a backup first, then writes the patched code.

        Args:
            file_path: Path to the file relative to repo root
            original_code: The vulnerable code (for backup/diff purposes)
            patched_code: The corrected code to write

        Returns:
            PatchResult with success/failure status
        """
        diff_path = None
        original_backup = None

        try:
            # Full path
            full_path = Path(self.repo_path) / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)

            # Create backup of original
            original_backup = self.create_backup(f"patch_{file_path}")
            if original_backup is None:
                logger.warning("Could not create backup for %s", file_path)

            # Generate diff
            diff = self.generate_diff(original_code, patched_code, file_path)
            if diff:
                diff_path = str(Path(self.repo_path) / f".secureheal{diff_path.replace(self.repo_path, '')}")
                # Save diff to storage
                diff_file = Path(self.repo_path) / ".secureheal" / f"diff_{Path(file_path).name}"
                diff_file.parent.mkdir(parents=True, exist_ok=True)
                diff_file.write_text(diff)
                logger.debug("Saved diff to %s", diff_file)

            # Write the patched code
            if full_path.exists():
                # Read existing file content to maintain context
                existing = full_path.read_text(encoding="utf-8")
                # Replace the vulnerable section
                # Simple replacement: find original_code in file and replace
                if original_code in existing:
                    new_content = existing.replace(original_code, patched_code, 1)
                    full_path.write_text(new_content, encoding="utf-8")
                    logger.info("Applied patch to %s", file_path)
                else:
                    # If exact match not found, append or replace last section
                    logger.warning(
                        "Original code not found in %s - appending patch",
                        file_path,
                    )
                    new_content = existing.rstrip() + "\n\n" + patched_code
                    full_path.write_text(new_content, encoding="utf-8")

            # Stage the change
            subprocess.run(
                ["git", "add", file_path],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=10,
            )

            # Commit the change
            commit_result = subprocess.run(
                ["git", "commit", "-m", "SecureHeal-AI: automated security patch"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if commit_result.returncode != 0:
                # Rollback the commit if it failed
                subprocess.run(
                    ["git", "reset", "HEAD~1", "--soft"],
                    cwd=self.repo_path,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                logger.error("Failed to commit patch: %s", commit_result.stderr)
                return PatchResult(
                    success=False,
                    message=f"Failed to commit patch: {commit_result.stderr}",
                )

            # Create a rollback point
            from secureheal.governance.rollback import RollbackManager
            rm = RollbackManager()
            rm.create_rollback_point(
                service_name=file_path,
                patch_id=f"patch_{Path(file_path).name}",
            )

            logger.info("Patch successfully applied to %s", file_path)
            return PatchResult(
                success=True,
                message="Patch applied successfully",
                rollback_id=f"rollback_{Path(file_path).name}",
                diff_path=str(diff_file) if diff else None,
                original_backup=original_backup,
            )

        except Exception as e:
            logger.exception("Error applying patch to %s", file_path)
            # Attempt rollback on error
            try:
                # Reset any staged changes
                subprocess.run(
                    ["git", "reset", "HEAD"],
                    cwd=self.repo_path,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            except Exception:
                pass
            return PatchResult(
                success=False,
                message=f"Error applying patch: {str(e)}",
            )

    def rollback_to_backup(self, rollback_id: str) -> bool:
        """Revert to a previous backup point.

        Args:
            rollback_id: The rollback point ID to revert to

        Returns:
            True if rollback successful, False otherwise
        """
        try:
            # Use the RollbackManager
            from secureheal.governance.rollback import RollbackManager
            rm = RollbackManager()
            result = rm.execute_rollback(rollback_id)

            if result["success"]:
                logger.info("Rollback successful: %s", rollback_id)
                return True
            else:
                logger.warning("Rollback failed: %s - %s", rollback_id, result.get("error"))
                # Try git reset as fallback
                subprocess.run(
                    ["git", "reset", "HEAD~1", "--hard"],
                    cwd=self.repo_path,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return False

        except Exception as e:
            logger.exception("Error during rollback to %s", rollback_id)
            return False

    def get_current_diff(self, file_path: str) -> Optional[str]:
        """Get the current Git diff for a file.

        Args:
            file_path: Path to the file

        Returns:
            Git diff string, or None
        """
        try:
            result = subprocess.run(
                ["git", "diff", file_path],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout
            return None
        except Exception as e:
            logger.warning("Could not get diff for %s: %s", file_path, e)
            return None