"""LangGraph workflow definition — the central multi-agent orchestrator."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from langgraph.graph import END, StateGraph

from secureheal.orchestrator.state import SecureHealState

logger = logging.getLogger("secureheal.orchestrator")


# ---------------------------------------------------------------------------
# Node functions — each delegates to the appropriate agent
# ---------------------------------------------------------------------------

async def collect_evidence(state: SecureHealState) -> dict:
    """Phase 1: Collect logs, traces, API events, source code and dependency info."""
    from secureheal.agents.threat_detection import ThreatDetectionAgent  # avoid circular

    logger.info("[Phase 1] Collecting evidence for incident %s", state.get("incident_id"))
    # Evidence is pre-populated before the pipeline starts; this node normalizes it.
    return {
        "current_phase": "evidence_collection",
        "workflow_log": state.get("workflow_log", [])
        + [
            {
                "phase": "evidence_collection",
                "agent": "orchestrator",
                "action": "Evidence collection started",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ],
    }


async def detect_threats(state: SecureHealState) -> dict:
    """Phase 2: Identify suspicious activity and vulnerability indicators."""
    from secureheal.agents.threat_detection import ThreatDetectionAgent

    logger.info("[Phase 2] Running threat detection …")
    agent = ThreatDetectionAgent()
    return await agent.execute(state)


async def analyze_root_cause(state: SecureHealState) -> dict:
    """Phase 3: Form and assess causal hypotheses."""
    from secureheal.agents.root_cause import RootCauseAgent

    logger.info("[Phase 3] Analyzing root cause …")
    agent = RootCauseAgent()
    return await agent.execute(state)


async def gather_context(state: SecureHealState) -> dict:
    """Phase 4: Analyze code structure, API relationships and dependencies."""
    from secureheal.agents.context_intelligence import ContextIntelligenceAgent

    logger.info("[Phase 4] Gathering context intelligence …")
    agent = ContextIntelligenceAgent()
    return await agent.execute(state)


async def generate_repairs(state: SecureHealState) -> dict:
    """Phase 5: Generate candidate patches."""
    from secureheal.agents.repair_generation import RepairGenerationAgent

    logger.info("[Phase 5] Generating repair candidates …")
    agent = RepairGenerationAgent()
    return await agent.execute(state)


async def verify_patches(state: SecureHealState) -> dict:
    """Phase 6: Independently verify candidate patches."""
    from secureheal.agents.patch_verification import PatchVerificationAgent

    logger.info("[Phase 6] Verifying patches …")
    agent = PatchVerificationAgent()
    return await agent.execute(state)


async def governance_review(state: SecureHealState) -> dict:
    """Phase 7: Prepare human approval package."""
    from secureheal.agents.recovery_governance import RecoveryGovernanceAgent

    logger.info("[Phase 7] Governance review …")
    agent = RecoveryGovernanceAgent()
    return await agent.execute(state)


# ---------------------------------------------------------------------------
# Conditional edge logic
# ---------------------------------------------------------------------------

def should_continue_after_threats(state: SecureHealState) -> str:
    """If no threats detected, end the pipeline."""
    if not state.get("threat_report"):
        logger.info("No threats detected — ending pipeline.")
        return "end"
    return "analyze_root_cause"


def should_continue_after_repairs(state: SecureHealState) -> str:
    """If no patches generated, end the pipeline."""
    if not state.get("candidate_patches"):
        logger.info("No candidate patches generated — ending pipeline.")
        return "end"
    return "verify_patches"


def should_continue_after_verification(state: SecureHealState) -> str:
    """If verification fails, retry repair up to MAX_RETRIES times."""
    results = state.get("verification_results", [])
    any_passed = any(
        r.get("functional_pass") and r.get("security_pass") and r.get("regression_pass")
        for r in results
    )
    if any_passed:
        return "governance_review"

    retry_count = state.get("retry_count", 0)
    if retry_count < 3:
        logger.info("Verification failed — retrying repair (attempt %d/3).", retry_count + 1)
        return "retry_repairs"
    logger.warning("Verification failed after 3 retries — ending pipeline.")
    return "end"


# ---------------------------------------------------------------------------
# Build the graph
# ---------------------------------------------------------------------------

def build_graph() -> StateGraph:
    """Construct and return the compiled LangGraph workflow."""
    graph = StateGraph(SecureHealState)

    # Add nodes
    graph.add_node("collect_evidence", collect_evidence)
    graph.add_node("detect_threats", detect_threats)
    graph.add_node("analyze_root_cause", analyze_root_cause)
    graph.add_node("gather_context", gather_context)
    graph.add_node("generate_repairs", generate_repairs)
    graph.add_node("verify_patches", verify_patches)
    graph.add_node("governance_review", governance_review)

    # Set entry point
    graph.set_entry_point("collect_evidence")

    # Linear edges
    graph.add_edge("collect_evidence", "detect_threats")

    # Conditional: after threat detection
    graph.add_conditional_edges(
        "detect_threats",
        should_continue_after_threats,
        {"analyze_root_cause": "analyze_root_cause", "end": END},
    )

    graph.add_edge("analyze_root_cause", "gather_context")
    graph.add_edge("gather_context", "generate_repairs")

    # Conditional: after repair generation
    graph.add_conditional_edges(
        "generate_repairs",
        should_continue_after_repairs,
        {"verify_patches": "verify_patches", "end": END},
    )

    # Conditional: after verification
    graph.add_conditional_edges(
        "verify_patches",
        should_continue_after_verification,
        {
            "governance_review": "governance_review",
            "retry_repairs": "generate_repairs",
            "end": END,
        },
    )

    graph.add_edge("governance_review", END)

    return graph


# Compiled graph instance
workflow = build_graph().compile()


async def run_pipeline(
    incident_id: str,
    service_name: str,
    language: str,
    evidence: list[dict] | None = None,
    classification: str = "unknown",
) -> SecureHealState:
    """Run the full SecureHeal-AI pipeline for a given incident.

    Returns the final state with all agent outputs.
    """
    initial_state: SecureHealState = {
        "incident_id": incident_id,
        "service_name": service_name,
        "language": language,
        "incident_classification": classification,
        "evidence": evidence or [],
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

    logger.info("Starting SecureHeal-AI pipeline for incident %s", incident_id)
    result = await workflow.ainvoke(initial_state)
    logger.info("Pipeline completed for incident %s — status: %s", incident_id, result.get("deployment_status"))
    return result
