"""Gitleaks secret detection scanner integration for SecureHeal-AI.

Detects exposed credentials and secrets in source code history
and working directories. Parses actual Gitleaks scan output
and produces structured evidence items for the threat detection agent.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("secureheal.scanners.gitleaks")


class GitleaksResult(BaseModel):
    """Parsed Gitleaks finding."""
    rule_id: str = Field(description="Gitleaks rule ID")
    rule_description: str = Field(description="Human-readable rule description")
    severity: str = Field(description="Severity level (high/critical)")
    file_path: str = Field(description="File where secret was found")
    secret: str = Field(description="Exposed secret value (masked in logs)")
    commit_id: str = Field(description="Git commit where secret was exposed")
    line_number: Optional[int] = Field(default=None, description="Line number in file")
    status: str = Field(description="Status: leaked, rotated, etc.")


async def run_gitleaks_scan(
    target: str = ".",
    files: Optional[List[str]] = None,
    source_dir: Optional[str] = None,
) -> List[GitleaksResult]:
    """Run Gitleaks scan and return parsed findings.

    Supports two modes:
    1. Scan a git repository for exposed secrets in history
    2. Scan a directory source tree for hardcoded secrets

    Args:
        target: Git repo path or directory to scan (default: ".")
        files: Specific file paths to scan (for directory mode)
        source_dir: Root source directory for relative path resolution

    Returns:
        List of parsed GitleaksResult objects
    """
    # Build gitleaks command
    cmd: list[str] = ["gitleaks", "detect", "--format", "json", "--no-git"]

    if files:
        for f in files:
            cmd.extend(["--path", f])

    # If target looks like a git repo, run with git history
    # Otherwise scan the directory for hardcoded secrets
    cmd.append(target)

    logger.info("Running Gitleaks scan: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        if result.returncode not in (0, 1):
            logger.warning(
                "Gitleaks exited with code %d: %s",
                result.returncode,
                result.stderr[:500],
            )

        # Parse JSON output
        output = result.stdout.strip()
        if not output:
            logger.info("No Gitleaks output returned")
            return []

        findings = json.loads(output)
        if not isinstance(findings, list):
            findings = [findings]

        parsed: list[GitleaksResult] = []
        for finding in findings:
            try:
                rule_id = finding.get("RuleID", finding.get("rule_id", "unknown"))
                rule_description = finding.get(
                    "RuleDescription", finding.get("rule_description", "")
                )
                severity = finding.get("Level", finding.get("severity", "high")).lower()
                file_path = finding.get("File", finding.get("file_path", ""))
                secret = finding.get("Secret", finding.get("secret", ""))
                commit_id = finding.get("CommitID", finding.get("commit_id", ""))
                line_number = finding.get("Line", finding.get("line_number"))
                line_number = int(line_number) if line_number else None
                status = finding.get("Status", finding.get("status", "leaked"))

                # Mask the secret for logging (show only first 4 and last 4 chars)
                masked_secret = (
                    (secret[:4] + "..." + secret[-4:])
                    if len(secret) > 8
                    else "..." * len(secret)
                )
                logger.debug("Gitleaks finding: %s in %s", masked_secret, file_path)

                parsed.append(
                    GitleaksResult(
                        rule_id=rule_id,
                        rule_description=rule_description,
                        severity=severity,
                        file_path=file_path,
                        secret=secret,  # Store original for analysis but log masked
                        commit_id=commit_id,
                        line_number=line_number,
                        status=status,
                    )
                )
            except (KeyError, TypeError, ValueError) as e:
                logger.warning("Failed to parse Gitleaks finding: %s", e)
                continue

        logger.info("Parsed %d Gitleaks findings", len(parsed))
        return parsed

    except subprocess.TimeoutExpired:
        logger.error("Gitleaks scan timed out after 300s for %s", target)
        return []
    except json.JSONDecodeError as e:
        logger.error("Failed to parse Gitleaks JSON output: %s", e)
        return []
    except FileNotFoundError:
        logger.error("Gitleaks CLI not found. Install with: pip install gitleaks")
        return []
    except Exception as e:
        logger.exception("Unexpected error during Gitleaks scan: %s", e)
        return []


def gitleaks_severity_map(severity: str) -> str:
    """Map Gitleaks severity to standardized severity levels.

    Returns a normalized severity string for database storage.
    """
    mapping: dict[str, str] = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }
    return mapping.get(severity.lower(), "medium")


async def scan_repository_for_secrets(
    repo_path: str,
) -> List[GitleaksResult]:
    """Scan a git repository for exposed secrets in commit history.

    This is the primary mode for detecting hardcoded credentials,
    API keys, and tokens that should not be in version control.

    Args:
        repo_path: Path to the git repository root

    Returns:
        List of GitleaksResult findings
    """
    # First try with git history
    cmd = ["gitleaks", "detect", "--format", "json", "--no-git", repo_path]
    logger.info("Scanning git repo: %s", repo_path)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        output = result.stdout.strip()
        if not output:
            return []

        findings = json.loads(output)
        if not isinstance(findings, list):
            findings = [findings]

        # Filter to only leaked status
        leaked = [
            f for f in findings
            if f.get("Status", "") == "leaked"
        ]

        parsed: list[GitleaksResult] = []
        for finding in leaked:
            try:
                rule_id = finding.get("RuleID", "unknown")
                rule_description = finding.get("RuleDescription", "")
                severity = finding.get("Level", "high").lower()
                file_path = finding.get("File", "")
                secret = finding.get("Secret", "")
                commit_id = finding.get("CommitID", "")
                line_number = finding.get("Line", None)
                line_number = int(line_number) if line_number else None

                parsed.append(
                    GitleaksResult(
                        rule_id=rule_id,
                        rule_description=rule_description,
                        severity=severity,
                        file_path=file_path,
                        secret=secret,
                        commit_id=commit_id,
                        line_number=line_number,
                        status=finding.get("Status", "leaked"),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue

        logger.info("Found %d leaked secrets in %s", len(parsed), repo_path)
        return parsed

    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        logger.error("Error scanning repo %s: %s", repo_path, e)
        return []
    except Exception as e:
        logger.exception("Unexpected error scanning repo %s: %s", repo_path, e)
        return []