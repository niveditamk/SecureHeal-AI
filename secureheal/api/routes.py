"""FastAPI REST endpoints for the SecureHeal-AI dashboard."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from secureheal.governance.approval import ApprovalGateway

router = APIRouter(prefix="/api", tags=["secureheal"])

# In-memory stores for the research prototype
_incidents: dict[str, dict] = {}
_pipeline_results: dict[str, dict] = {}

gateway = ApprovalGateway()


# --- Request/Response models ---

class RunPipelineRequest(BaseModel):
    service_name: str
    language: str = "python"
    classification: str = "unknown"
    evidence: list[dict] = []


class ApprovalRequest(BaseModel):
    reviewer: str
    decision: str  # "approved" | "rejected"
    reason: str = ""


# --- Endpoints ---

@router.get("/incidents")
async def list_incidents():
    """List all incidents with status."""
    return {"incidents": list(_incidents.values()), "total": len(_incidents)}


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """Get full incident details including pipeline results."""
    if incident_id not in _incidents:
        raise HTTPException(status_code=404, detail="Incident not found")
    result = _pipeline_results.get(incident_id, {})
    return {**_incidents[incident_id], "pipeline_result": result}


@router.post("/incidents/{incident_id}/run")
async def run_pipeline_for_incident(incident_id: str, req: RunPipelineRequest):
    """Trigger the SecureHeal-AI pipeline for an incident."""
    from secureheal.orchestrator.graph import run_pipeline

    # Create or update the incident record
    _incidents[incident_id] = {
        "incident_id": incident_id,
        "service_name": req.service_name,
        "language": req.language,
        "classification": req.classification,
        "status": "investigating",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        result = await run_pipeline(
            incident_id=incident_id,
            service_name=req.service_name,
            language=req.language,
            evidence=req.evidence,
            classification=req.classification,
        )
        _pipeline_results[incident_id] = result
        _incidents[incident_id]["status"] = result.get("deployment_status", "completed")
        return {"incident_id": incident_id, "status": "completed", "result": result}
    except Exception as exc:
        _incidents[incident_id]["status"] = "error"
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/patches/{patch_id}/approve")
async def approve_patch(patch_id: str, req: ApprovalRequest):
    """Approve a candidate patch for deployment."""
    record = gateway.submit_approval(
        patch_id=patch_id,
        reviewer=req.reviewer,
        decision="approved",
        reason=req.reason,
    )
    return {"status": "approved", "record": record}


@router.post("/patches/{patch_id}/reject")
async def reject_patch(patch_id: str, req: ApprovalRequest):
    """Reject a candidate patch."""
    record = gateway.submit_approval(
        patch_id=patch_id,
        reviewer=req.reviewer,
        decision="rejected",
        reason=req.reason,
    )
    return {"status": "rejected", "record": record}


@router.get("/metrics")
async def get_metrics():
    """Get evaluation metrics across all incidents."""
    total = len(_incidents)
    completed = sum(1 for i in _incidents.values() if i.get("status") not in ("investigating", "error"))
    approved = sum(1 for i in _incidents.values() if i.get("status") == "approved")

    return {
        "total_incidents": total,
        "completed_investigations": completed,
        "approved_patches": approved,
        "repair_success_rate": completed / total if total > 0 else 0,
        "approval_rate": approved / completed if completed > 0 else 0,
    }


@router.get("/audit/{incident_id}")
async def get_audit_log(incident_id: str):
    """Get the full audit trail for an incident."""
    result = _pipeline_results.get(incident_id, {})
    return {
        "incident_id": incident_id,
        "workflow_log": result.get("workflow_log", []),
        "phases_completed": [
            log.get("phase") for log in result.get("workflow_log", [])
        ],
    }
