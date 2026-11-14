"""Agent 1 — Threat Detection.

Analyzes evidence (logs, traces, API events) to identify security threats,
classify them by CWE, and assess severity.
"""

from __future__ import annotations

import json

from langchain_core.messages import HumanMessage, SystemMessage

from secureheal.agents.base import BaseAgent
from secureheal.orchestrator.state import SecureHealState

SYSTEM_PROMPT = """\
You are a cybersecurity threat detection specialist within the SecureHeal-AI framework.

Your role is to analyze collected evidence — application logs, distributed traces,
API events, scan results — and identify security threats.

For each threat you detect, provide:
1. **threat_type** — concise name (e.g. "SQL Injection", "Missing Authorization")
2. **cwe_id** — the CWE identifier (e.g. "CWE-89")
3. **severity** — critical / high / medium / low
4. **affected_endpoints** — list of API endpoints involved
5. **indicators** — specific log entries, trace spans or scan findings that support the detection
6. **raw_findings** — any tool output excerpts

Respond ONLY with a valid JSON object matching the schema above. Do NOT wrap in markdown.
If no threats are found, return: {"threat_type": null}
"""


class ThreatDetectionAgent(BaseAgent):
    """Identifies security threats from collected evidence."""

    name = "threat_detection"
    role = "Threat Detection Agent"

    async def execute(self, state: SecureHealState) -> dict:
        evidence = state.get("evidence", [])
        if not evidence:
            return {
                "threat_report": None,
                "current_phase": "threat_detection",
                "workflow_log": self.log_action(state, "No evidence to analyze"),
            }

        llm = self.get_llm()
        evidence_text = json.dumps(evidence, indent=2, default=str)

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(
                content=(
                    f"Analyze the following evidence for security threats.\n\n"
                    f"Service: {state.get('service_name', 'unknown')}\n"
                    f"Language: {state.get('language', 'unknown')}\n"
                    f"Classification hint: {state.get('incident_classification', 'unknown')}\n\n"
                    f"Evidence:\n{evidence_text}"
                )
            ),
        ]

        response = await llm.ainvoke(messages)
        try:
            threat_report = json.loads(response.content)
        except json.JSONDecodeError:
            threat_report = {
                "threat_type": state.get("incident_classification", "unknown"),
                "cwe_id": "unknown",
                "severity": "medium",
                "affected_endpoints": [],
                "indicators": [response.content],
                "raw_findings": response.content,
            }

        if threat_report.get("threat_type") is None:
            threat_report = None

        return {
            "threat_report": threat_report,
            "current_phase": "threat_detection",
            "workflow_log": self.log_action(
                state,
                "Threat detection completed",
                {"threats_found": threat_report is not None},
            ),
        }
