"""Agent 2 — Root Cause Analysis.

Forms causal hypotheses linking incident evidence to code defects,
using chain-of-thought reasoning.
"""

from __future__ import annotations

import json

from langchain_core.messages import HumanMessage, SystemMessage

from secureheal.agents.base import BaseAgent
from secureheal.orchestrator.state import SecureHealState

SYSTEM_PROMPT = """\
You are a causal root-cause analysis specialist within the SecureHeal-AI framework.

Given a threat detection report and collected evidence, your job is to:
1. Trace the causal chain from the observed runtime event back to the underlying code defect.
2. Identify the specific file, function or configuration that is the root cause.
3. Rate your confidence (0.0–1.0) in the hypothesis.
4. List alternative explanations that could also explain the evidence.

Think step by step (chain-of-thought):
- What runtime behaviour was observed?
- What code path could produce that behaviour?
- What specific defect in that code path enables the vulnerability?
- What evidence supports this causal link?
- What alternative explanations exist?

Respond ONLY with a valid JSON object:
{
  "hypothesis": "...",
  "causal_chain": ["step1", "step2", ...],
  "affected_component": {"file": "...", "function": "...", "line_range": "..."},
  "confidence": 0.85,
  "supporting_evidence": ["evidence_id_1", ...],
  "alternative_explanations": ["...", "..."]
}
"""


class RootCauseAgent(BaseAgent):
    """Forms causal root-cause hypotheses from threat reports and evidence."""

    name = "root_cause_analysis"
    role = "Root Cause Analysis Agent"

    async def execute(self, state: SecureHealState) -> dict:
        threat_report = state.get("threat_report")
        if not threat_report:
            return {
                "root_cause": None,
                "current_phase": "root_cause_analysis",
                "workflow_log": self.log_action(state, "No threat report — skipping RCA"),
            }

        llm = self.get_llm()
        evidence_text = json.dumps(state.get("evidence", []), indent=2, default=str)
        threat_text = json.dumps(threat_report, indent=2, default=str)

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(
                content=(
                    f"Threat Report:\n{threat_text}\n\n"
                    f"Service: {state.get('service_name')}\n"
                    f"Language: {state.get('language')}\n\n"
                    f"Collected Evidence:\n{evidence_text}"
                )
            ),
        ]

        response = await llm.ainvoke(messages)
        try:
            root_cause = json.loads(response.content)
        except json.JSONDecodeError:
            root_cause = {
                "hypothesis": response.content,
                "causal_chain": [],
                "affected_component": {},
                "confidence": 0.5,
                "supporting_evidence": [],
                "alternative_explanations": [],
            }

        return {
            "root_cause": root_cause,
            "current_phase": "root_cause_analysis",
            "workflow_log": self.log_action(
                state,
                "Root cause analysis completed",
                {"confidence": root_cause.get("confidence", 0)},
            ),
        }
