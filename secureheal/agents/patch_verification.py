"""Agent 5 — Patch Verification.

Independently verifies candidate patches through functional, security,
and regression checks.  Does NOT rely on the repair agent's self-assessment.
"""

from __future__ import annotations

import json

from langchain_core.messages import HumanMessage, SystemMessage

from secureheal.agents.base import BaseAgent
from secureheal.orchestrator.state import SecureHealState

SYSTEM_PROMPT = """\
You are an independent patch verification specialist within SecureHeal-AI.

Your role is to INDEPENDENTLY verify candidate patches. You must NOT rely on the
repair agent's explanation or self-assessment.

For each candidate patch, evaluate three dimensions:

1. **Functional Verification** — Does the patch correctly fix the vulnerability?
   - Does it address the specific CWE?
   - Is the fix technically correct for the language?
   - Does it handle edge cases?

2. **Security Verification** — Does the patch introduce any NEW security weaknesses?
   - Check for common mistakes (e.g., fixing SQLi but introducing XSS)
   - Verify the fix follows secure coding best practices
   - Check for information leakage in error messages

3. **Regression Verification** — Does the patch preserve existing functionality?
   - Are API contracts maintained?
   - Are return types and response formats unchanged?
   - Are existing features unaffected?

For each patch, respond with:
{
  "patch_index": 0,
  "functional_pass": true/false,
  "functional_details": "...",
  "security_pass": true/false,
  "security_details": "...",
  "regression_pass": true/false,
  "regression_details": "...",
  "overall_recommendation": "accept" | "reject" | "needs_revision",
  "issues_found": ["...", "..."]
}

Respond with a JSON array of verification results. Do NOT wrap in markdown.
"""


class PatchVerificationAgent(BaseAgent):
    """Independently verifies candidate patches."""

    name = "patch_verification"
    role = "Patch Verification Agent"

    async def execute(self, state: SecureHealState) -> dict:
        patches = state.get("candidate_patches", [])
        if not patches:
            return {
                "verification_results": [],
                "current_phase": "patch_verification",
                "workflow_log": self.log_action(state, "No patches to verify"),
            }

        llm = self.get_llm()
        constraints = state.get("repair_constraints", [])
        threat_report = state.get("threat_report", {})

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(
                content=(
                    f"## Candidate Patches\n{json.dumps(patches, indent=2, default=str)}\n\n"
                    f"## Original Threat Report\n{json.dumps(threat_report, indent=2, default=str)}\n\n"
                    f"## Repair Constraints\n"
                    + "\n".join(f"- {c}" for c in constraints)
                    + f"\n\n## Language: {state.get('language', 'python')}\n"
                )
            ),
        ]

        response = await llm.ainvoke(messages)
        try:
            results = json.loads(response.content)
            if isinstance(results, dict):
                results = [results]
        except json.JSONDecodeError:
            # If LLM output is unparseable, mark all patches as needing revision
            results = [
                {
                    "patch_index": i,
                    "functional_pass": False,
                    "security_pass": False,
                    "regression_pass": False,
                    "overall_recommendation": "needs_revision",
                    "issues_found": ["Verification output was not parseable"],
                }
                for i in range(len(patches))
            ]

        return {
            "verification_results": results,
            "current_phase": "patch_verification",
            "workflow_log": self.log_action(
                state,
                "Patch verification completed",
                {
                    "patches_verified": len(results),
                    "any_passed": any(
                        r.get("functional_pass") and r.get("security_pass") and r.get("regression_pass")
                        for r in results
                    ),
                },
            ),
        }
