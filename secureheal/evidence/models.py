"""Pydantic models for evidence items and incident reports."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class EvidenceSource(str, Enum):
    """Where the evidence came from."""

    LOG = "log"
    TRACE = "trace"
    API_EVENT = "api_event"
    SCAN_RESULT = "scan_result"
    SOURCE_CODE = "source_code"
    DEPENDENCY = "dependency"


class EvidenceItem(BaseModel):
    """A single piece of evidence collected during investigation."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: EvidenceSource
    type: str  # e.g. "auth_failure", "sql_error", "scan_finding"
    content: dict
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    service_name: str = ""
    severity: Optional[str] = None  # critical / high / medium / low / info


class TelemetryData(BaseModel):
    """OpenTelemetry-style telemetry bundle."""

    traces: list[dict] = Field(default_factory=list)
    logs: list[dict] = Field(default_factory=list)
    metrics: list[dict] = Field(default_factory=list)


class IncidentReport(BaseModel):
    """Complete incident report with all collected evidence."""

    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_name: str
    language: str  # "java" | "python"
    classification: str  # CWE-based classification
    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    telemetry: TelemetryData = Field(default_factory=TelemetryData)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
