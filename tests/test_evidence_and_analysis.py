"""Tests for the evidence collection and analysis modules."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from secureheal.evidence.models import EvidenceItem, EvidenceSource, IncidentReport, TelemetryData
from secureheal.evidence.collector import EvidenceCollector
from secureheal.analysis.causal import CausalAnalyzer
from secureheal.repair.constraints import SecurityConstraints
from secureheal.verification.security import SecurityVerifier


class TestEvidenceModels:
    """Test Pydantic evidence models."""

    def test_evidence_item_creation(self):
        item = EvidenceItem(
            source=EvidenceSource.LOG,
            type="sql_error",
            content={"raw_line": "SQL error near DROP"},
            service_name="test-service",
            severity="high",
        )
        assert item.source == EvidenceSource.LOG
        assert item.severity == "high"
        assert item.id  # auto-generated UUID

    def test_incident_report(self):
        report = IncidentReport(
            service_name="python-fastapi",
            language="python",
            classification="sql_injection",
        )
        assert report.service_name == "python-fastapi"
        assert report.language == "python"
        assert len(report.evidence_items) == 0


class TestEvidenceCollector:
    """Test the evidence collector."""

    def test_collect_from_logs(self, tmp_path):
        log_file = tmp_path / "test.log"
        log_file.write_text(
            "[2026-10-15] ERROR SQL syntax error near DROP\n"
            "[2026-10-15] INFO Normal request processed\n"
            "[2026-10-15] WARN Authentication failed for user admin\n"
            "[2026-10-15] INFO Another normal line\n"
        )
        collector = EvidenceCollector()
        items = collector.collect_from_logs(str(log_file))
        assert len(items) >= 2  # SQL error + auth failure

    def test_collect_from_source(self, tmp_path):
        src_file = tmp_path / "app.py"
        src_file.write_text("def hello():\n    return 'world'\n")
        collector = EvidenceCollector()
        items = collector.collect_from_source(str(tmp_path))
        assert len(items) == 1
        assert items[0].source == EvidenceSource.SOURCE_CODE

    def test_collect_from_requirements(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("fastapi>=0.115\nuvicorn[standard]\nhttpx\n")
        collector = EvidenceCollector()
        items = collector.collect_from_dependencies(str(req_file))
        assert len(items) == 3

    def test_collect_from_scan_results(self):
        scan_output = {
            "results": [
                {
                    "check_id": "python.lang.security.sql-injection",
                    "path": "app/main.py",
                    "start": {"line": 72},
                    "end": {"line": 72},
                    "extra": {
                        "message": "Possible SQL injection",
                        "severity": "ERROR",
                        "lines": "sql = f\"SELECT * FROM users WHERE name = '{query}'\"",
                    },
                }
            ]
        }
        collector = EvidenceCollector()
        items = collector.collect_from_scan_results(scan_output)
        assert len(items) == 1
        assert items[0].source == EvidenceSource.SCAN_RESULT


class TestCausalAnalyzer:
    """Test the causal analysis module."""

    def test_build_evidence_graph(self):
        items = [
            EvidenceItem(
                source=EvidenceSource.LOG, type="sql_error",
                content={"file": "app/main.py"}, severity="high",
            ),
            EvidenceItem(
                source=EvidenceSource.SOURCE_CODE, type="source_file",
                content={"file_path": "app/main.py"}, severity="medium",
            ),
        ]
        analyzer = CausalAnalyzer()
        graph = analyzer.build_evidence_graph(items)
        assert len(graph["nodes"]) == 2

    def test_generate_hypotheses(self):
        graph = {"nodes": [{"id": "1", "severity": "high"}], "edges": []}
        threat_report = {"cwe_id": "CWE-89", "threat_type": "SQL Injection"}
        analyzer = CausalAnalyzer()
        hypotheses = analyzer.generate_hypotheses(graph, threat_report)
        assert len(hypotheses) >= 1
        assert hypotheses[0]["confidence"] > 0


class TestSecurityConstraints:
    """Test the CWE-specific constraint system."""

    def test_constraints_for_known_cwe(self):
        sc = SecurityConstraints()
        constraints = sc.get_constraints_for_cwe("CWE-89")
        assert any("parameterized" in c.lower() for c in constraints)

    def test_constraints_for_unknown_cwe(self):
        sc = SecurityConstraints()
        constraints = sc.get_constraints_for_cwe("CWE-9999")
        assert len(constraints) >= 3  # At least generic + universal constraints


class TestSecurityVerifier:
    """Test the security verification module."""

    def test_detect_dangerous_patterns(self):
        verifier = SecurityVerifier()
        result = verifier.run_static_analysis(
            "data = pickle.loads(user_input)",
            "python",
        )
        assert not result["security_pass"]
        assert result["findings_count"] >= 1

    def test_safe_code_passes(self):
        verifier = SecurityVerifier()
        result = verifier.run_static_analysis(
            "data = json.loads(user_input)",
            "python",
        )
        assert result["security_pass"]

    def test_check_new_vulnerabilities(self):
        verifier = SecurityVerifier()
        original = "data = pickle.loads(user_input)"
        patched = "data = json.loads(user_input)"
        result = verifier.check_new_vulnerabilities(original, patched)
        assert result["security_pass"]
        assert result["net_improvement"] > 0

    def test_validate_sqli_fix(self):
        verifier = SecurityVerifier()
        patch = {
            "original_code": "sql = f\"SELECT * FROM users WHERE name = '{query}'\"",
            "patched_code": "cursor.execute('SELECT * FROM users WHERE name = ?', (query,))",
        }
        result = verifier.validate_cwe_fix(patch, "CWE-89")
        assert result["cwe_fixed"]
