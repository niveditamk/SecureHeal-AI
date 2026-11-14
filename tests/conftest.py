"""Shared pytest fixtures for SecureHeal-AI tests."""

from __future__ import annotations

import os
import tempfile

import pytest


@pytest.fixture
def sample_state() -> dict:
    """Return a minimal valid SecureHealState dict."""
    return {
        "incident_id": "test-001",
        "service_name": "python-fastapi-target",
        "language": "python",
        "incident_classification": "sql_injection",
        "evidence": [],
        "threat_report": None,
        "root_cause": None,
        "context_map": None,
        "repair_constraints": [],
        "candidate_patches": [],
        "verification_results": [],
        "approved_patch": None,
        "deployment_status": "pending",
        "workflow_log": [],
        "current_phase": "init",
        "error": None,
        "retry_count": 0,
    }


@pytest.fixture
def vulnerable_python_code() -> str:
    """Return a sample vulnerable Python code snippet (CWE-89)."""
    return '''
import sqlite3

def search_users(query):
    conn = sqlite3.connect("test.db")
    sql = f"SELECT * FROM users WHERE name LIKE '%{query}%'"
    return conn.execute(sql).fetchall()
'''


@pytest.fixture
def fixed_python_code() -> str:
    """Return the secure version of the vulnerable code (CWE-89 fixed)."""
    return '''
import sqlite3

def search_users(query):
    conn = sqlite3.connect("test.db")
    sql = "SELECT * FROM users WHERE name LIKE ?"
    return conn.execute(sql, (f"%{query}%",)).fetchall()
'''


@pytest.fixture
def sample_threat_report() -> dict:
    """Return a realistic threat detection report."""
    return {
        "incident_id": "test-001",
        "threat_type": "SQL Injection",
        "cwe_id": "CWE-89",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "affected_endpoint": "/api/users/search",
        "attack_vector": "HTTP POST body — 'query' parameter",
        "indicators": [
            "Unparameterized SQL query with f-string interpolation",
            "Direct user input in WHERE clause",
            "No input validation or sanitization",
        ],
    }


@pytest.fixture
def sample_root_cause() -> dict:
    """Return a causal root-cause analysis result."""
    return {
        "incident_id": "test-001",
        "hypothesis": "User-controlled input is concatenated into a raw SQL query via f-string, "
                      "allowing arbitrary SQL injection through the 'query' parameter.",
        "causal_chain": [
            "User submits malicious input via POST /api/users/search",
            "FastAPI deserializes 'query' field from request body",
            "search_users() interpolates query directly into SQL via f-string",
            "sqlite3.execute() runs the tainted query verbatim",
            "Attacker gains read access to all database rows",
        ],
        "root_file": "target_services/python_fastapi/app/main.py",
        "root_line": 72,
        "confidence": 0.92,
    }


@pytest.fixture
def sample_candidate_patch() -> dict:
    """Return a candidate repair patch."""
    return {
        "patch_id": "patch-001",
        "incident_id": "test-001",
        "cwe_id": "CWE-89",
        "file_path": "target_services/python_fastapi/app/main.py",
        "original_code": 'sql = f"SELECT id, username, email, role FROM users WHERE {req.field} LIKE \'%{req.query}%\'"',
        "patched_code": 'sql = "SELECT id, username, email, role FROM users WHERE username LIKE ?"\n'
                        '        cursor = conn.execute(sql, (f"%{req.query}%",))',
        "explanation": "Replace f-string SQL interpolation with parameterized query using ? placeholder.",
        "constraints_met": ["no_string_formatting_in_sql", "use_parameterized_queries"],
    }


@pytest.fixture
def tmp_workspace(tmp_path):
    """Create a temporary workspace directory with sample files."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("# sample app\nprint('hello')\n")
    (src / "requirements.txt").write_text("fastapi\nuvicorn\n")
    return tmp_path
