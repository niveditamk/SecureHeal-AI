"""Evidence correlator — maps runtime events to source code and dependencies."""

from __future__ import annotations

import logging
import re

from secureheal.evidence.models import EvidenceItem

logger = logging.getLogger("secureheal.analysis.correlation")


class EvidenceCorrelator:
    """Correlates evidence across runtime, source code, and dependency layers."""

    def correlate_runtime_to_source(
        self, traces: list[dict], source_evidence: list[EvidenceItem]
    ) -> list[dict]:
        """Map runtime events (traces, errors) to source code locations."""
        correlations: list[dict] = []

        for trace in traces:
            if not trace.get("has_error"):
                continue

            # Try to match error details to source files
            error_events = [e for e in trace.get("events", []) if "exception" in e.get("name", "").lower()]
            for event in error_events:
                stack = event.get("attributes", {}).get("exception.stacktrace", "")
                for src in source_evidence:
                    file_path = src.content.get("file_path", "")
                    if file_path and file_path in stack:
                        # Extract line number from stack trace
                        line_match = re.search(rf"{re.escape(file_path)}.*?(?:line\s+|:)(\d+)", stack)
                        correlations.append({
                            "trace_id": trace["trace_id"],
                            "source_file": file_path,
                            "line_number": int(line_match.group(1)) if line_match else None,
                            "error_type": event.get("attributes", {}).get("exception.type", ""),
                            "confidence": 0.9 if line_match else 0.6,
                        })

        logger.info("Found %d runtime-to-source correlations", len(correlations))
        return correlations

    def correlate_api_to_code(
        self, api_events: list[dict], source_files: list[EvidenceItem]
    ) -> dict:
        """Map API endpoints to their handler functions in source code."""
        endpoint_map: dict[str, dict] = {}

        # Common patterns for route definitions
        route_patterns = {
            "python": [
                r'@app\.(get|post|put|delete|patch)\(\s*["\']([^"\']+)',
                r'@router\.(get|post|put|delete|patch)\(\s*["\']([^"\']+)',
            ],
            "java": [
                r'@(Get|Post|Put|Delete|Patch)Mapping\(\s*(?:value\s*=\s*)?["\']?([^"\')\s]+)',
                r'@RequestMapping\(\s*(?:value\s*=\s*)?["\']?([^"\')\s]+)',
            ],
        }

        for src in source_files:
            content = src.content.get("content", "")
            language = src.content.get("language", "python")
            file_path = src.content.get("file_path", "")
            patterns = route_patterns.get(language, [])

            for pattern in patterns:
                for match in re.finditer(pattern, content):
                    method = match.group(1).upper() if len(match.groups()) >= 2 else "GET"
                    route = match.group(2) if len(match.groups()) >= 2 else match.group(1)
                    endpoint_map[route] = {
                        "file": file_path,
                        "method": method,
                        "line": content[: match.start()].count("\n") + 1,
                    }

        return endpoint_map

    def find_dependency_links(
        self, dependency_evidence: list[EvidenceItem], vulnerability_report: dict
    ) -> list[dict]:
        """Link vulnerable dependencies to the code that uses them."""
        links: list[dict] = []
        cwe_id = vulnerability_report.get("cwe_id", "")

        # Known vulnerable patterns per CWE
        vulnerable_deps = {
            "CWE-502": {"python": ["pickle", "yaml", "shelve"], "java": ["ObjectInputStream"]},
            "CWE-89": {"python": ["sqlite3", "psycopg2"], "java": ["jdbc", "Statement"]},
        }

        for dep in dependency_evidence:
            dep_name = dep.content.get("name", "").lower()
            dep_artifact = dep.content.get("artifact_id", "").lower()

            patterns = vulnerable_deps.get(cwe_id, {})
            for lang, deps in patterns.items():
                for vdep in deps:
                    if vdep.lower() in dep_name or vdep.lower() in dep_artifact:
                        links.append({
                            "dependency": dep_name or dep_artifact,
                            "version": dep.content.get("version", "unknown"),
                            "cwe_id": cwe_id,
                            "risk": "Dependency may be used in a vulnerable pattern",
                        })

        return links

    def build_correlation_matrix(self, all_correlations: list[dict]) -> dict:
        """Build a summary matrix of all evidence correlations."""
        matrix: dict[str, dict] = {}

        for corr in all_correlations:
            source_file = corr.get("source_file", corr.get("file", "unknown"))
            if source_file not in matrix:
                matrix[source_file] = {
                    "runtime_links": 0,
                    "api_links": 0,
                    "dependency_links": 0,
                    "total_confidence": 0.0,
                    "details": [],
                }

            if "trace_id" in corr:
                matrix[source_file]["runtime_links"] += 1
            elif "method" in corr:
                matrix[source_file]["api_links"] += 1
            elif "dependency" in corr:
                matrix[source_file]["dependency_links"] += 1

            matrix[source_file]["total_confidence"] += corr.get("confidence", 0.5)
            matrix[source_file]["details"].append(corr)

        return matrix
