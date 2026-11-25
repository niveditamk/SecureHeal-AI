"""Semgrep security scanner integration for SecureHeal-AI.

Executes actual Semgrep scans on Java and Python source code,
parses JSON output, and extracts CWE, severity, file, line number
and rule ID for storage in the evidence system.
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("secureheal.scanners.semgrep")


class SemgrepResult(BaseModel):
    """Parsed Semgrep finding."""
    rule_id: str = Field(description="Semgrep check ID or rule ID")
    message: str = Field(description="Human-readable finding description")
    severity: str = Field(description="Semgrep severity level")
    path: str = Field(description="File path where finding occurs")
    start_line: int = Field(description="Starting line number (1-indexed)")
    end_line: int = Field(description="Ending line number (1-indexed)")
    cwe_id: Optional[str] = Field(default=None, description="CWE identifier if available")
    category: Optional[str] = Field(default=None, description="Rule category if available")


async def run_semgrep_scan(
    target_path: str,
    config: str = "auto",
    rules: Optional[List[str]] = None,
    ignore_file: Optional[str] = None,
) -> List[SemgrepResult]:
    """Run Semgrep scan on a target path and return parsed findings.

    Args:
        target_path: Path to scan (file, directory, or archive)
        config: Semgrep config string, "auto" uses language-detected defaults
        rules: Specific rule IDs to run (None = auto-detect)
        ignore_file: Path to .semgrepignore file

    Returns:
        List of parsed SemgrepResult objects
    """
    # Build the semgrep command
    cmd: list[str] = ["semgrep", "scan", "--json", "--no-git-ignore"]

    if config and config != "auto":
        cmd.extend(["--config", config])

    if rules:
        for rule in rules:
            cmd.extend(["--rule", rule])

    if ignore_file and Path(ignore_file).exists():
        cmd.extend(["--ignore", str(Path(ignore_file).resolve())])

    cmd.append(target_path)

    logger.info("Running Semgrep scan: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        if result.returncode not in (0, 1):  # Semgrep returns 1 when findings found
            logger.warning(
                "Semgrep exited with code %d: %s",
                result.returncode,
                result.stderr[:500],
            )

        # Parse JSON output
        output = result.stdout.strip()
        if not output:
            logger.info("No Semgrep output returned")
            return []

        findings = json.loads(output)
        if not isinstance(findings, list):
            findings = [findings]

        parsed: list[SemgrepResult] = []
        for finding in findings:
            try:
                # Normalize Semgrep JSON output format
                rule_id = finding.get("check_id", finding.get("rule_id", "unknown"))
                message = finding.get("extra", {}).get("message", "")
                severity = finding.get("severity", "medium").lower()
                path = finding.get("path", "")
                start_line = finding.get("start", {}).get("line", 1)
                end_line = finding.get("end", {}).get("line", 1)

                # Extract CWE if present
                cwe_id = None
                cwe_identifiers = finding.get("cwe_id", "")
                if cwe_identifiers:
                    cwe_id = str(cwe_identifiers)

                category = None
                if "category" in finding:
                    category = finding["category"]

                parsed.append(
                    SemgrepResult(
                        rule_id=rule_id,
                        message=message,
                        severity=severity,
                        path=path,
                        start_line=start_line,
                        end_line=end_line,
                        cwe_id=cwe_id,
                        category=category,
                    )
                )
            except (KeyError, TypeError, ValueError) as e:
                logger.warning("Failed to parse Semgrep finding: %s", e)
                continue

        logger.info("Parsed %d Semgrep findings from %s", len(parsed), target_path)
        return parsed

    except subprocess.TimeoutExpired:
        logger.error("Semgrep scan timed out after 300s for %s", target_path)
        return []
    except json.JSONDecodeError as e:
        logger.error("Failed to parse Semgrep JSON output: %s", e)
        logger.debug("Raw output: %s", output[:500] if "output" in dir() else "N/A")
        return []
    except FileNotFoundError:
        logger.error("Semgrep CLI not found. Install with: pip install semgrep")
        return []
    except Exception as e:
        logger.exception("Unexpected error during Semgrep scan: %s", e)
        return []


def semgrep_cwe_map(severity: str) -> str:
    """Map Semgrep severity to CWE-relevant severity level.

    Returns a normalized severity string that can be stored
    in the evidence database.
    """
    mapping: dict[str, str] = {
        "ERROR": "critical",
        "WARNING": "high",
        "NOTE": "medium",
        "INFO": "low",
    }
    return mapping.get(severity.upper(), "medium")


def scan_python_file(filepath: str) -> list[SemgrepResult]:
    """Convenience function to scan a single Python file.

    Args:
        filepath: Path to Python file to scan

    Returns:
        List of SemgrepResult findings
    """
    return asyncio.run(run_semgrep_scan(filepath))


scan_js_pin = scan_python_file  # Alias for consistency


async def scan_directory(
    directory: str,
    rules: Optional[list[str]] = None,
) -> list[SemgrepResult]:
    """Scan an entire directory with Semgrep.

    Args:
        directory: Path to directory containing source code
        rules: Optional specific rule IDs to target

    Returns:
        All findings from the directory scan
    """
    return await run_semgrep_scan(directory, rules=rules)