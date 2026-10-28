import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from app.db.session import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

class RemediationTask(Base):
    __tablename__ = "remediation_tasks"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    assigned_team = Column(String(128), nullable=True)
    assigned_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    due_date = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(32), default="OPEN", nullable=False, index=True) # OPEN, IN_PROGRESS, READY_FOR_VERIFICATION, RESOLVED, ACCEPTED_RISK, REOPENED
    sla_breached = Column(Boolean, default=False, nullable=False)
    resolution_notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    finding = relationship("Finding", back_populates="remediation_tasks")
    evidence_records = relationship("RemediationEvidence", back_populates="task", cascade="all, delete-orphan")

class RemediationEvidence(Base):
    __tablename__ = "remediation_evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    remediation_task_id = Column(String(36), ForeignKey("remediation_tasks.id", ondelete="CASCADE"), nullable=False, index=True)
    verification_type = Column(String(64), nullable=False) # SCANNER_RESCAN, CONFIGURATION_PROOF, PATCH_COMMIT, MANUAL_INSPECTION
    evidence_payload = Column(JSON, nullable=False)
    evidence_hash = Column(String(64), nullable=True)
    verified_by_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    verified_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    task = relationship("RemediationTask", back_populates="evidence_records")

class ReviewDecision(Base):
    __tablename__ = "review_decisions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    entity_type = Column(String(64), nullable=False, index=True) # DUPLICATE_MERGE, APPLICABILITY_OVERRIDE, ROOT_CAUSE_CLUSTER, REMEDIATION_CLOSE, AI_ASSESSMENT
    entity_id = Column(String(36), nullable=False, index=True)
    decision = Column(String(32), nullable=False) # APPROVED, REJECTED, MODIFIED
    reviewer_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    rationale = Column(Text, nullable=False)
    previous_state = Column(JSON, default=dict)
    new_state = Column(JSON, default=dict)
    reviewed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
