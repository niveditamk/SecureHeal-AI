"""Tests for the governance and API modules."""

from __future__ import annotations

from secureheal.governance.approval import ApprovalGateway
from secureheal.governance.rollback import RollbackManager


class TestApprovalGateway:
    """Test the human approval gateway."""

    def test_prepare_review_package(self):
        gw = ApprovalGateway()
        patches = [{"file_path": "app.py", "patched_code": "safe code"}]
        verification = [{"functional_pass": True, "security_pass": True, "regression_pass": True}]
        package = gw.prepare_review_package("INC-001", patches, verification)
        assert package["incident_id"] == "INC-001"
        assert package["recommended_patch"] == patches[0]
        assert "rollback_plan" in package

    def test_submit_approval(self):
        gw = ApprovalGateway()
        record = gw.submit_approval("PATCH-001", "reviewer@test.com", "approved", "Looks good")
        assert record["decision"] == "approved"
        assert record["reviewer"] == "reviewer@test.com"

    def test_risk_assessment_low(self):
        gw = ApprovalGateway()
        patches = [{"file_path": "app.py"}]
        verification = [{"functional_pass": True, "security_pass": True, "regression_pass": True}]
        package = gw.prepare_review_package("INC-001", patches, verification)
        assert package["risk_summary"]["risk_level"] == "low"


class TestRollbackManager:
    """Test the rollback manager."""

    def test_create_and_execute_rollback(self):
        rm = RollbackManager()
        point = rm.create_rollback_point("python-fastapi", "PATCH-001")
        assert point["status"] == "active"

        result = rm.execute_rollback(point["rollback_id"])
        assert result["success"]

    def test_verify_rollback(self):
        rm = RollbackManager()
        result = rm.verify_rollback("python-fastapi")
        assert result["health_check"] == "passed"
        assert result["verdict"].startswith("Rollback successful")

    def test_rollback_not_found(self):
        rm = RollbackManager()
        result = rm.execute_rollback("nonexistent-id")
        assert not result["success"]
