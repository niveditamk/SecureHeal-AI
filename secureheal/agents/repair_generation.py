"""Agent 4 — Repair Generation.

Generates 1-3 candidate code patches using LLM, constrained by
security and functional requirements.
"""

from __future__ import annotations

import difflib
import json

from langchain_core.messages import HumanMessage, SystemMessage

from secureheal.agents.base import BaseAgent
from secureheal.orchestrator.state import SecureHealState

SYSTEM_PROMPT = """\
You are a security-aware automated program repair specialist within SecureHeal-AI.

Given a root-cause hypothesis, code context, and explicit repair constraints, generate
1 to 3 candidate code patches that fix the identified vulnerability.

For EACH candidate patch, provide:
1. **file_path** — the file being patched
2. **original_code** — the exact vulnerable code snippet
3. **patched_code** — the corrected code snippet
4. **explanation** — why this patch fixes the vulnerability
5. **constraints_satisfied** — which constraints from the list this patch satisfies

RULES:
- Each patch must be MINIMAL — change only what is necessary.
- Each patch must ADDRESS the specific CWE vulnerability.
- Each patch must PRESERVE existing API contracts and functionality.
- Use language-idiomatic secure coding patterns.
- For Python: use parameterized queries, html.escape, os.path checks, shlex, etc.
- For Java: use PreparedStatement, OWASP encoder, Path.normalize, ProcessBuilder, etc.

Respond ONLY with a valid JSON array of patch objects. Do NOT wrap in markdown.
"""


class RepairGenerationAgent(BaseAgent):
    """Generates candidate code patches using LLM-assisted repair."""

    name = "repair_generation"
    role = "Repair Generation Agent"

    async def execute(self, state: SecureHealState) -> dict:
        root_cause = state.get("root_cause")
        context_map = state.get("context_map")
        if not root_cause or not context_map:
            return {
                "candidate_patches": [],
                "current_phase": "repair_generation",
                "workflow_log": self.log_action(state, "Missing root cause or context — cannot generate repairs"),
            }

        llm = self.get_llm(temperature=0.2)  # Slightly higher temp for diverse patches
        constraints = state.get("repair_constraints", [])

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(
                content=(
                    f"## Root Cause\n{json.dumps(root_cause, indent=2, default=str)}\n\n"
                    f"## Code Context\n{json.dumps(context_map, indent=2, default=str)}\n\n"
                    f"## Repair Constraints\n"
                    + "\n".join(f"- {c}" for c in constraints)
                    + f"\n\n## Target Language: {state.get('language', 'python')}\n"
                    f"## CWE: {state.get('threat_report', {}).get('cwe_id', 'unknown')}\n"
                )
            ),
        ]

        response = await llm.ainvoke(messages)
        try:
            patches = json.loads(response.content)
            if isinstance(patches, dict):
                patches = [patches]
        except json.JSONDecodeError:
            patches = []

        # Ensure each patch has a diff
        for patch in patches:
            if "diff" not in patch:
                patch["diff"] = self._generate_diff(
                    patch.get("original_code", ""),
                    patch.get("patched_code", ""),
                    patch.get("file_path", "unknown"),
                )
            patch["status"] = "generated"

        # Increment retry count if we're retrying
        retry_count = state.get("retry_count", 0)
        if state.get("current_phase") == "repair_generation":
            retry_count += 1

        return {
            "candidate_patches": patches,
            "retry_count": retry_count,
            "current_phase": "repair_generation",
            "workflow_log": self.log_action(
                state,
                "Repair generation completed",
                {"patches_generated": len(patches)},
            ),
        }

    @staticmethod
    def _generate_diff(original: str, patched: str, file_path: str) -> str:
        """Generate a unified diff between original and patched code."""
        original_lines = original.splitlines(keepends=True)
        patched_lines = patched.splitlines(keepends=True)
        diff = difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
        return "".join(diff)
