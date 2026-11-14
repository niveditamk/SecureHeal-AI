"""Agent 6 — Recovery Governance.

Prepares the human approval package: selects the best verified patch,
generates a risk summary, deployment recommendation, and rollback plan.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from langchain_core.messages import HumanMessage, SystemMessage

from secureheal.agents.base import BaseAgent
from secureheal.orchestrator.state import SecureHealState

SYSTEM_PROMPT = """\
You are a recovery governance specialist within SecureHeal-AI.

Your role is to prepare a complete human approval package. You must:

1. Select the BEST candidate patch based on verification results.
2. Generate a **risk summary** — what could go wrong if this patch is deployed.
3. Provide a **deployment recommendation** — staged rollout strategy.
4. Create a **rollback plan** — step-by-step instructions to revert if needed.
5. Compile an **audit record** — complete trail of investigation and repair.

The human reviewer will use your package to make the final approval decision.
A patch is deployed ONLY after explicit human approval.

Respond with a JSON object:
{
  "selected_patch_index": 0,
  "risk_summary": {
    "risk_level": "low" | "medium" | "high",
    "risks": ["...", "..."],
    "mitigations": ["...", "..."]
  },
  "deployment_recommendation": {
    "strategy": "staged_rollout",
    "stages": [
      {"name": "canary", "traffic_percentage": 5, "duration": "1h", "monitoring": "..."},
      {"name": "partial", "traffic_percentage": 25, "duration": "4h", "monitoring": "..."},
      {"name": "full", "traffic_percentage": 100, "duration": "ongoing", "monitoring": "..."}
    ]
  },
  "rollback_plan": {
    "trigger_conditions": ["...", "..."],
    "steps": ["...", "..."],
    "estimated_rollback_time": "< 5 minutes",
    "verification_after_rollback": "..."
  },
  "audit_summary": "..."
}
"""


class RecoveryGovernanceAgent(BaseAgent):
    """Prepares the human approval package and governs recovery."""

    name = "recovery_governance"
    role = "Recovery Governance Agent"

    async def execute(self, state: SecureHealState) -> dict:
        patches = state.get("candidate_patches", [])
        verification = state.get("verification_results", [])

        if not patches or not verification:
            return {
                "approved_patch": None,
                "deployment_status": "rejected",
                "current_phase": "governance_review",
                "workflow_log": self.log_action(state, "No verified patches — cannot proceed"),
            }

        # Find patches that passed all checks
        passed_indices = [
            r.get("patch_index", i)
            for i, r in enumerate(verification)
            if r.get("functional_pass") and r.get("security_pass") and r.get("regression_pass")
        ]

        if not passed_indices:
            return {
                "approved_patch": None,
                "deployment_status": "rejected",
                "current_phase": "governance_review",
                "workflow_log": self.log_action(state, "No patches passed verification"),
            }

        llm = self.get_llm()

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(
                content=(
                    f"## Verified Patches (indices that passed: {passed_indices})\n"
                    f"{json.dumps(patches, indent=2, default=str)}\n\n"
                    f"## Verification Results\n{json.dumps(verification, indent=2, default=str)}\n\n"
                    f"## Threat Report\n{json.dumps(state.get('threat_report', {}), indent=2, default=str)}\n\n"
                    f"## Root Cause\n{json.dumps(state.get('root_cause', {}), indent=2, default=str)}\n\n"
                    f"## Service: {state.get('service_name')}\n"
                )
            ),
        ]

        response = await llm.ainvoke(messages)
        try:
            governance_package = json.loads(response.content)
        except json.JSONDecodeError:
            governance_package = {
                "selected_patch_index": passed_indices[0] if passed_indices else 0,
                "risk_summary": {"risk_level": "medium", "risks": [], "mitigations": []},
                "deployment_recommendation": {"strategy": "manual_review_required"},
                "rollback_plan": {"steps": ["Revert to previous version"]},
                "audit_summary": response.content,
            }

        # Build the approved patch record
        selected_idx = governance_package.get("selected_patch_index", 0)
        selected_patch = patches[selected_idx] if selected_idx < len(patches) else patches[0]

        approved_patch = {
            **selected_patch,
            "governance": governance_package,
            "status": "pending_approval",
            "prepared_at": datetime.now(timezone.utc).isoformat(),
        }

        return {
            "approved_patch": approved_patch,
            "deployment_status": "pending_approval",
            "current_phase": "governance_review",
            "workflow_log": self.log_action(
                state,
                "Governance review completed — awaiting human approval",
                {"selected_patch_index": selected_idx, "risk_level": governance_package.get("risk_summary", {}).get("risk_level")},
            ),
        }
