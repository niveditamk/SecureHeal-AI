"""Tests for the SecureHeal-AI orchestrator state and graph.

The graph module depends on langgraph which loads ormsgpack (a native DLL).
On some Windows environments Application Control policies block that DLL,
so we guard the import and skip the affected tests gracefully.
"""

from __future__ import annotations

import pytest

# --- Safe import: state module has no native deps ---
from secureheal.orchestrator.state import SecureHealState

# --- Guarded import: graph depends on langgraph → ormsgpack DLL ---
try:
    from secureheal.orchestrator.graph import (
        build_graph,
        should_continue_after_threats,
        should_continue_after_repairs,
        should_continue_after_verification,
    )
    _GRAPH_AVAILABLE = True
except (ImportError, OSError) as _err:
    _GRAPH_AVAILABLE = False
    _graph_skip_reason = f"langgraph/ormsgpack import failed: {_err}"

_requires_graph = pytest.mark.skipif(
    not _GRAPH_AVAILABLE,
    reason=_graph_skip_reason if not _GRAPH_AVAILABLE else "",
)


class TestSecureHealState:
    """Verify the state TypedDict structure."""

    def test_empty_state(self):
        state: SecureHealState = {
            "incident_id": "test-001",
            "service_name": "test-service",
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
        assert state["incident_id"] == "test-001"
        assert state["language"] == "python"
        assert state["deployment_status"] == "pending"

    def test_state_fields_are_complete(self):
        """Verify all expected keys exist in a fully-populated state."""
        expected_keys = {
            "incident_id", "service_name", "language", "incident_classification",
            "evidence", "threat_report", "root_cause", "context_map",
            "repair_constraints", "candidate_patches", "verification_results",
            "approved_patch", "deployment_status", "workflow_log",
            "current_phase", "error", "retry_count",
        }
        state: SecureHealState = {k: None for k in expected_keys}
        assert set(state.keys()) == expected_keys


@_requires_graph
class TestConditionalEdges:
    """Test the conditional routing logic in the graph."""

    def test_no_threats_ends_pipeline(self):
        state: SecureHealState = {"threat_report": None}
        assert should_continue_after_threats(state) == "end"

    def test_threats_found_continues(self):
        state: SecureHealState = {"threat_report": {"threat_type": "SQL Injection"}}
        assert should_continue_after_threats(state) == "analyze_root_cause"

    def test_no_patches_ends_pipeline(self):
        state: SecureHealState = {"candidate_patches": []}
        assert should_continue_after_repairs(state) == "end"

    def test_patches_generated_continues(self):
        state: SecureHealState = {"candidate_patches": [{"file_path": "test.py"}]}
        assert should_continue_after_repairs(state) == "verify_patches"

    def test_verification_passes_continues_to_governance(self):
        state: SecureHealState = {
            "verification_results": [
                {"functional_pass": True, "security_pass": True, "regression_pass": True}
            ],
            "retry_count": 0,
        }
        assert should_continue_after_verification(state) == "governance_review"

    def test_verification_fails_retries(self):
        state: SecureHealState = {
            "verification_results": [
                {"functional_pass": False, "security_pass": True, "regression_pass": True}
            ],
            "retry_count": 0,
        }
        assert should_continue_after_verification(state) == "retry_repairs"

    def test_verification_fails_max_retries_ends(self):
        state: SecureHealState = {
            "verification_results": [
                {"functional_pass": False, "security_pass": False, "regression_pass": False}
            ],
            "retry_count": 3,
        }
        assert should_continue_after_verification(state) == "end"


@_requires_graph
class TestGraphBuild:
    """Test that the graph builds and compiles correctly."""

    def test_graph_compiles(self):
        graph = build_graph()
        compiled = graph.compile()
        assert compiled is not None
