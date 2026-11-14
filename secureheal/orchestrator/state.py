"""Typed shared state for the LangGraph multi-agent orchestrator."""

from __future__ import annotations

from typing import Literal, TypedDict


class SecureHealState(TypedDict, total=False):
    """Shared state passed through the LangGraph pipeline.

    Each agent reads and updates the fields relevant to its role.
    """

    # --- Incident Identity ---
    incident_id: str
    service_name: str
    language: Literal["java", "python"]
    incident_classification: str  # e.g. 'sql_injection', 'xss', etc.

    # --- Evidence Layer ---
    evidence: list[dict]  # collected evidence items

    # --- Agent 1 output ---
    threat_report: dict | None  # threat_type, cwe_id, severity, indicators, …

    # --- Agent 2 output ---
    root_cause: dict | None  # hypothesis, confidence, evidence_ids, alternatives

    # --- Agent 3 output ---
    context_map: dict | None  # affected_files, vulnerable_functions, api_map, deps

    # --- Agent 4 inputs/outputs ---
    repair_constraints: list[str]  # security & functional constraints for repair
    candidate_patches: list[dict]  # generated patches

    # --- Agent 5 output ---
    verification_results: list[dict]  # test/scan results per patch

    # --- Agent 6 output ---
    approved_patch: dict | None  # the recommended/approved patch
    deployment_status: str  # pending | approved | deployed | rolled_back | rejected

    # --- Orchestrator bookkeeping ---
    workflow_log: list[dict]  # audit trail of agent actions
    current_phase: str
    error: str | None
    retry_count: int
