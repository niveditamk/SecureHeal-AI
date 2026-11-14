"""Agent 3 — Context Intelligence.

Analyzes source code structure, API endpoint mappings, and dependency
relationships to provide rich context for repair generation.
"""

from __future__ import annotations

import json

from langchain_core.messages import HumanMessage, SystemMessage

from secureheal.agents.base import BaseAgent
from secureheal.orchestrator.state import SecureHealState

SYSTEM_PROMPT = """\
You are a code and dependency context intelligence specialist within SecureHeal-AI.

Given a root-cause hypothesis and collected evidence (including source code and
dependency information), your job is to:

1. Identify all **affected files** and the specific vulnerable functions/methods.
2. Map **API endpoints** to their handler functions in the source code.
3. Analyze **dependencies** — check versions, known CVEs, and how the code uses them.
4. Provide a **context map** that a repair agent can use to generate a correct patch.

Respond ONLY with a valid JSON object:
{
  "affected_files": [
    {"path": "...", "vulnerable_functions": ["..."], "line_ranges": ["10-25"]}
  ],
  "api_endpoint_map": {
    "/api/users/search": {"handler": "search_users", "file": "...", "method": "POST"}
  },
  "dependency_analysis": [
    {"name": "...", "version": "...", "known_cves": [], "usage_in_code": "..."}
  ],
  "code_patterns": {
    "input_validation": "missing",
    "output_encoding": "present",
    "auth_checks": "missing"
  },
  "repair_context": "Summary of what the repair agent needs to know..."
}
"""


class ContextIntelligenceAgent(BaseAgent):
    """Analyzes source code and dependency context for repair."""

    name = "context_intelligence"
    role = "Context Intelligence Agent"

    async def execute(self, state: SecureHealState) -> dict:
        root_cause = state.get("root_cause")
        if not root_cause:
            return {
                "context_map": None,
                "current_phase": "context_intelligence",
                "workflow_log": self.log_action(state, "No root cause — skipping context analysis"),
            }

        llm = self.get_llm()

        # Gather source-code evidence
        source_evidence = [
            e for e in state.get("evidence", []) if e.get("source") in ("source_code", "dependency")
        ]
        evidence_text = json.dumps(source_evidence, indent=2, default=str)
        root_cause_text = json.dumps(root_cause, indent=2, default=str)
        threat_text = json.dumps(state.get("threat_report", {}), indent=2, default=str)

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(
                content=(
                    f"Root Cause Hypothesis:\n{root_cause_text}\n\n"
                    f"Threat Report:\n{threat_text}\n\n"
                    f"Service: {state.get('service_name')}\n"
                    f"Language: {state.get('language')}\n\n"
                    f"Source Code and Dependency Evidence:\n{evidence_text}"
                )
            ),
        ]

        response = await llm.ainvoke(messages)
        try:
            context_map = json.loads(response.content)
        except json.JSONDecodeError:
            context_map = {
                "affected_files": [],
                "api_endpoint_map": {},
                "dependency_analysis": [],
                "code_patterns": {},
                "repair_context": response.content,
            }

        # Derive repair constraints from context
        constraints = self._derive_constraints(state, context_map)

        return {
            "context_map": context_map,
            "repair_constraints": constraints,
            "current_phase": "context_intelligence",
            "workflow_log": self.log_action(
                state,
                "Context intelligence completed",
                {"files_analyzed": len(context_map.get("affected_files", []))},
            ),
        }

    def _derive_constraints(self, state: SecureHealState, context_map: dict) -> list[str]:
        """Derive security and functional repair constraints from the context."""
        cwe_id = ""
        threat = state.get("threat_report")
        if threat:
            cwe_id = threat.get("cwe_id", "")

        # CWE-specific constraints
        cwe_constraints: dict[str, list[str]] = {
            "CWE-89": [
                "Must use parameterized queries or prepared statements",
                "Must not concatenate user input into SQL strings",
                "Must validate and sanitize all user inputs",
            ],
            "CWE-79": [
                "Must encode/escape all user-supplied output in HTML context",
                "Must use framework-provided auto-escaping",
                "Must set Content-Type headers correctly",
            ],
            "CWE-862": [
                "Must add authorization check before accessing protected resources",
                "Must verify user roles/permissions",
                "Must return 403 Forbidden for unauthorized access",
            ],
            "CWE-918": [
                "Must validate and whitelist allowed destination URLs",
                "Must block requests to internal/private IP ranges",
                "Must not follow redirects to untrusted destinations",
            ],
            "CWE-22": [
                "Must canonicalize file paths before access",
                "Must validate paths stay within allowed directories",
                "Must reject path traversal sequences (../, ..\\)",
            ],
            "CWE-78": [
                "Must not pass user input to OS commands",
                "Must use safe APIs instead of shell execution",
                "Must whitelist allowed command arguments if shell is unavoidable",
            ],
            "CWE-502": [
                "Must not deserialize untrusted data with unsafe deserializers",
                "Must use safe serialization formats (JSON) instead of pickle/ObjectInputStream",
                "Must validate deserialized object types",
            ],
            "CWE-798": [
                "Must move credentials to environment variables or secret managers",
                "Must not hardcode passwords, API keys or tokens in source code",
                "Must use configuration files excluded from version control",
            ],
        }

        constraints = cwe_constraints.get(cwe_id, [
            "Must address the identified vulnerability",
            "Must preserve existing functionality",
            "Must not introduce new security weaknesses",
        ])

        # Universal constraints
        constraints.extend([
            "Patch must be minimal — change only what is necessary",
            "Patch must preserve existing API contracts",
            "Patch must be compatible with the service's dependencies",
        ])

        return constraints
