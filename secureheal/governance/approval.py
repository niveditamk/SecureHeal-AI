"""Approval gateway — prepares review packages and records decisions."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

logger = logging.getLogger("secureheal.governance")


class ApprovalGateway:
    """Manages the human approval workflow for candidate patches."""

    def prepare_review_package(
        self,
        incident_id: str,
        patches: list[dict],
        verification_results: list[dict],
    ) -> dict:
        """Bundle everything a human reviewer needs to make a decision."""
        # Find the best patch
        best_idx = 0
        best_score = -1
        for i, result in enumerate(verification_results):
            score = sum([
                result.get("functional_pass", False),
                result.get("security_pass", False),
                result.get("regression_pass", False),
            ])
            if score > best_score:
                best_score = score
                best_idx = i

        best_patch = patches[best_idx] if best_idx < len(patches) else patches[0] if patches else {}

        return {
            "review_id": str(uuid.uuid4()),
            "incident_id": incident_id,
            "recommended_patch": best_patch,
            "recommended_patch_index": best_idx,
            "all_patches": patches,
            "verification_results": verification_results,
            "risk_summary": self._assess_risk(best_patch, verification_results),
            "deployment_recommendation": self._recommend_deployment(verification_results),
            "rollback_plan": self.get_rollback_plan(best_patch.get("file_path", "")),
            "prepared_at": datetime.now(timezone.utc).isoformat(),
        }

    def submit_approval(
        self,
        patch_id: str,
        reviewer: str,
        decision: str,
        reason: str = "",
    ) -> dict:
        """Record a human approval or rejection decision."""
        record = {
            "approval_id": str(uuid.uuid4()),
            "patch_id": patch_id,
            "reviewer": reviewer,
            "decision": decision,  # "approved" | "rejected"
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info("Patch %s %s by %s: %s", patch_id, decision, reviewer, reason)
        return record

    def get_rollback_plan(self, patch_id_or_path: str) -> dict:
        """Generate rollback instructions for a patch."""
        return {
            "trigger_conditions": [
                "New errors detected in monitoring after deployment",
                "Security scan reveals new vulnerabilities",
                "Functional tests fail in production environment",
                "User reports of broken functionality",
            ],
            "steps": [
                "1. Halt traffic to the patched service (set weight to 0 in load balancer)",
                "2. Revert the code change using git revert or re-deploy the previous container image",
                "3. Run smoke tests against the reverted service",
                "4. Restore traffic gradually (canary → partial → full)",
                "5. Verify all monitoring dashboards show nominal metrics",
                "6. Record the rollback in the audit log with reason",
            ],
            "estimated_rollback_time": "< 5 minutes",
            "verification_after_rollback": (
                "Run the full regression test suite and confirm the vulnerability "
                "alert is re-raised (proving the rollback was successful)."
            ),
        }

    def get_deployment_recommendation(self, verification_results: list[dict]) -> dict:
        """Generate a staged rollout recommendation based on verification results."""
        return self._recommend_deployment(verification_results)

    @staticmethod
    def _assess_risk(patch: dict, verification_results: list[dict]) -> dict:
        """Assess the risk level of deploying a patch."""
        all_pass = all(
            r.get("functional_pass") and r.get("security_pass") and r.get("regression_pass")
            for r in verification_results
            if r  # skip empty results
        )

        if all_pass:
            return {
                "risk_level": "low",
                "risks": ["Minimal risk — all verification checks passed"],
                "mitigations": ["Standard staged rollout", "Post-deployment monitoring"],
            }
        else:
            failed = [
                k for r in verification_results
                for k in ("functional", "security", "regression")
                if not r.get(f"{k}_pass", True)
            ]
            return {
                "risk_level": "high" if "security" in failed else "medium",
                "risks": [f"Verification failures in: {', '.join(set(failed))}"],
                "mitigations": [
                    "Extended canary period with close monitoring",
                    "Manual code review recommended before deployment",
                    "Prepare immediate rollback capability",
                ],
            }

    @staticmethod
    def _recommend_deployment(verification_results: list[dict]) -> dict:
        """Generate deployment strategy recommendation."""
        return {
            "strategy": "staged_rollout",
            "stages": [
                {
                    "name": "canary",
                    "traffic_percentage": 5,
                    "duration": "1 hour",
                    "monitoring": "Error rates, latency p99, security alerts",
                },
                {
                    "name": "partial",
                    "traffic_percentage": 25,
                    "duration": "4 hours",
                    "monitoring": "Full metrics dashboard + security scan",
                },
                {
                    "name": "full",
                    "traffic_percentage": 100,
                    "duration": "ongoing",
                    "monitoring": "Standard production monitoring + weekly security review",
                },
            ],
            "abort_criteria": [
                "Error rate exceeds 1% above baseline",
                "New security alert triggered",
                "P99 latency increases by more than 50%",
            ],
        }
