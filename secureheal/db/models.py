"""SQLAlchemy ORM models for the SecureHeal-AI database."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> uuid.UUID:
    return uuid.uuid4()


class Incident(Base):
    """A security incident under investigation."""

    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_new_uuid)
    service_name: Mapped[str] = mapped_column(String(255), nullable=False)
    language: Mapped[str] = mapped_column(String(20), nullable=False)  # 'java' | 'python'
    classification: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(
        Enum(
            "detected",
            "investigating",
            "repairing",
            "verifying",
            "pending_approval",
            "approved",
            "deployed",
            "rolled_back",
            "rejected",
            name="incident_status",
        ),
        default="detected",
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    # Relationships
    evidence_items: Mapped[list[Evidence]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    hypotheses: Mapped[list[RootCauseHypothesis]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    patches: Mapped[list[CandidatePatch]] = relationship(back_populates="incident", cascade="all, delete-orphan")


class Evidence(Base):
    """A piece of evidence collected during investigation."""

    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_new_uuid)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    source: Mapped[str] = mapped_column(String(50), nullable=False)  # log, trace, api_event, scan_result, source_code, dependency
    evidence_type: Mapped[str] = mapped_column(String(100), nullable=False)
    content: Mapped[dict] = mapped_column(JSON, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    incident: Mapped[Incident] = relationship(back_populates="evidence_items")


class RootCauseHypothesis(Base):
    """A causal root-cause hypothesis for an incident."""

    __tablename__ = "root_cause_hypotheses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_new_uuid)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    hypothesis: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    evidence_ids: Mapped[dict] = mapped_column(JSON, default=list)
    alternative_explanations: Mapped[dict] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    incident: Mapped[Incident] = relationship(back_populates="hypotheses")


class CandidatePatch(Base):
    """A candidate code patch generated for an incident."""

    __tablename__ = "candidate_patches"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_new_uuid)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    original_code: Mapped[str] = mapped_column(Text, nullable=False)
    patched_code: Mapped[str] = mapped_column(Text, nullable=False)
    diff: Mapped[str] = mapped_column(Text, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(
        Enum("generated", "verified", "failed", "approved", "rejected", "deployed", name="patch_status"),
        default="generated",
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    incident: Mapped[Incident] = relationship(back_populates="patches")
    verification_results: Mapped[list[VerificationResult]] = relationship(back_populates="patch", cascade="all, delete-orphan")
    approval_records: Mapped[list[ApprovalRecord]] = relationship(back_populates="patch", cascade="all, delete-orphan")


class VerificationResult(Base):
    """Results of independent patch verification."""

    __tablename__ = "verification_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_new_uuid)
    patch_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("candidate_patches.id"), nullable=False)
    functional_pass: Mapped[bool] = mapped_column(Boolean, nullable=False)
    security_pass: Mapped[bool] = mapped_column(Boolean, nullable=False)
    regression_pass: Mapped[bool] = mapped_column(Boolean, nullable=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    patch: Mapped[CandidatePatch] = relationship(back_populates="verification_results")


class ApprovalRecord(Base):
    """Human approval/rejection record for a candidate patch."""

    __tablename__ = "approval_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_new_uuid)
    patch_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("candidate_patches.id"), nullable=False)
    reviewer: Mapped[str] = mapped_column(String(255), nullable=False)
    decision: Mapped[str] = mapped_column(Enum("approved", "rejected", name="approval_decision"), nullable=False)
    reason: Mapped[str] = mapped_column(Text, default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    patch: Mapped[CandidatePatch] = relationship(back_populates="approval_records")
