"""Evidence collector — gathers logs, source code, dependencies, and scan results."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from secureheal.evidence.models import EvidenceItem, EvidenceSource, IncidentReport, TelemetryData

logger = logging.getLogger("secureheal.evidence")

# Patterns that indicate security-relevant log entries
SECURITY_LOG_PATTERNS = [
    (r"(?i)sql\s*(syntax\s*)?error", "sql_error"),
    (r"(?i)(authentication|auth)\s*(failed|failure|denied)", "auth_failure"),
    (r"(?i)(unauthorized|403\s*forbidden)", "auth_failure"),
    (r"(?i)(injection|inject)", "injection_attempt"),
    (r"(?i)(stack\s*trace|traceback|exception)", "exception"),
    (r"(?i)(path\s*traversal|\.\.\/|\.\.\\\\)", "path_traversal"),
    (r"(?i)(command\s*(injection|execution)|os\.system|subprocess)", "command_injection"),
    (r"(?i)(deserializ|pickle|unpickle|ObjectInputStream)", "deserialization"),
    (r"(?i)(ssrf|server.side.request)", "ssrf_attempt"),
    (r"(?i)(xss|cross.site.script|<script)", "xss_attempt"),
    (r"(?i)(password|secret|token|api.key)\s*[:=]", "credential_exposure"),
    (r"HTTP/\d\.\d\"\s*(4\d{2}|5\d{2})", "error_status_code"),
]


class EvidenceCollector:
    """Collects and normalizes evidence from multiple sources."""

    def collect_from_logs(self, log_path: str) -> list[EvidenceItem]:
        """Parse log files for security-relevant entries."""
        items: list[EvidenceItem] = []
        path = Path(log_path)

        if not path.exists():
            logger.warning("Log path does not exist: %s", log_path)
            return items

        content = path.read_text(encoding="utf-8", errors="replace")
        for line_num, line in enumerate(content.splitlines(), start=1):
            for pattern, evidence_type in SECURITY_LOG_PATTERNS:
                if re.search(pattern, line):
                    items.append(
                        EvidenceItem(
                            source=EvidenceSource.LOG,
                            type=evidence_type,
                            content={
                                "line_number": line_num,
                                "raw_line": line.strip(),
                                "file": str(path),
                            },
                            severity=self._severity_from_type(evidence_type),
                        )
                    )
                    break  # One match per line is enough

        logger.info("Collected %d security-relevant log entries from %s", len(items), log_path)
        return items

    def collect_from_source(
        self, source_dir: str, target_files: list[str] | None = None
    ) -> list[EvidenceItem]:
        """Read source code files and create evidence items."""
        items: list[EvidenceItem] = []
        base = Path(source_dir)

        if target_files:
            files = [base / f for f in target_files]
        else:
            files = list(base.rglob("*.py")) + list(base.rglob("*.java"))

        for fpath in files:
            if not fpath.exists():
                continue
            content = fpath.read_text(encoding="utf-8", errors="replace")
            items.append(
                EvidenceItem(
                    source=EvidenceSource.SOURCE_CODE,
                    type="source_file",
                    content={
                        "file_path": str(fpath.relative_to(base)),
                        "content": content,
                        "language": "java" if fpath.suffix == ".java" else "python",
                        "lines": len(content.splitlines()),
                    },
                )
            )

        logger.info("Collected %d source files from %s", len(items), source_dir)
        return items

    def collect_from_dependencies(self, manifest_path: str) -> list[EvidenceItem]:
        """Parse pom.xml or requirements.txt for dependency info."""
        items: list[EvidenceItem] = []
        path = Path(manifest_path)

        if not path.exists():
            logger.warning("Manifest path does not exist: %s", manifest_path)
            return items

        content = path.read_text(encoding="utf-8", errors="replace")

        if path.name == "requirements.txt":
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = re.split(r"[>=<~!]+", line, maxsplit=1)
                    name = parts[0].strip()
                    version = parts[1].strip() if len(parts) > 1 else "unspecified"
                    items.append(
                        EvidenceItem(
                            source=EvidenceSource.DEPENDENCY,
                            type="python_dependency",
                            content={"name": name, "version": version, "file": str(path)},
                        )
                    )
        elif path.name == "pom.xml":
            # Simple regex extraction for Maven dependencies
            dep_pattern = re.compile(
                r"<dependency>\s*"
                r"<groupId>(.*?)</groupId>\s*"
                r"<artifactId>(.*?)</artifactId>\s*"
                r"(?:<version>(.*?)</version>)?",
                re.DOTALL,
            )
            for match in dep_pattern.finditer(content):
                items.append(
                    EvidenceItem(
                        source=EvidenceSource.DEPENDENCY,
                        type="java_dependency",
                        content={
                            "group_id": match.group(1),
                            "artifact_id": match.group(2),
                            "version": match.group(3) or "managed",
                            "file": str(path),
                        },
                    )
                )

        logger.info("Collected %d dependencies from %s", len(items), manifest_path)
        return items

    def collect_from_scan_results(self, scan_output: dict) -> list[EvidenceItem]:
        """Normalize scanner output (Semgrep / ZAP format) into evidence items."""
        items: list[EvidenceItem] = []

        # Semgrep-style results
        for result in scan_output.get("results", []):
            items.append(
                EvidenceItem(
                    source=EvidenceSource.SCAN_RESULT,
                    type="static_analysis_finding",
                    content={
                        "rule_id": result.get("check_id", ""),
                        "message": result.get("extra", {}).get("message", ""),
                        "file": result.get("path", ""),
                        "line_start": result.get("start", {}).get("line", 0),
                        "line_end": result.get("end", {}).get("line", 0),
                        "severity": result.get("extra", {}).get("severity", "WARNING"),
                        "snippet": result.get("extra", {}).get("lines", ""),
                    },
                    severity=result.get("extra", {}).get("severity", "medium").lower(),
                )
            )

        # ZAP-style alerts
        for alert in scan_output.get("alerts", []):
            items.append(
                EvidenceItem(
                    source=EvidenceSource.SCAN_RESULT,
                    type="api_security_finding",
                    content={
                        "alert_name": alert.get("name", ""),
                        "risk": alert.get("risk", ""),
                        "confidence": alert.get("confidence", ""),
                        "url": alert.get("url", ""),
                        "description": alert.get("description", ""),
                        "solution": alert.get("solution", ""),
                        "cwe_id": alert.get("cweid", ""),
                    },
                    severity=alert.get("risk", "medium").lower(),
                )
            )

        logger.info("Collected %d scan findings", len(items))
        return items

    def build_incident_report(
        self,
        service_name: str,
        language: str,
        classification: str,
        evidence_items: list[EvidenceItem],
        telemetry: TelemetryData | None = None,
    ) -> IncidentReport:
        """Assemble all evidence into a structured incident report."""
        return IncidentReport(
            service_name=service_name,
            language=language,
            classification=classification,
            evidence_items=evidence_items,
            telemetry=telemetry or TelemetryData(),
        )

    @staticmethod
    def _severity_from_type(evidence_type: str) -> str:
        severity_map = {
            "sql_error": "high",
            "auth_failure": "high",
            "injection_attempt": "critical",
            "exception": "medium",
            "path_traversal": "high",
            "command_injection": "critical",
            "deserialization": "critical",
            "ssrf_attempt": "high",
            "xss_attempt": "high",
            "credential_exposure": "critical",
            "error_status_code": "low",
        }
        return severity_map.get(evidence_type, "info")
