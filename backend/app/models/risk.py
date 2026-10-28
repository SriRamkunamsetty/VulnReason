import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Text, JSON, Boolean
from sqlalchemy.orm import relationship
from app.db.session import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

class RiskPolicy(Base):
    __tablename__ = "risk_policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    version = Column(String(32), nullable=False) # e.g. "v1.0.0"
    name = Column(String(255), nullable=False)
    rules_definition = Column(JSON, nullable=False) # Configurable threshold rules
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    assessments = relationship("RiskAssessment", back_populates="policy")

class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    policy_id = Column(String(36), ForeignKey("risk_policies.id", ondelete="SET NULL"), nullable=True)
    policy_version = Column(String(32), nullable=False)
    priority_tier = Column(String(32), nullable=False, index=True) # P0_URGENT, P1_HIGH, P2_MEDIUM, P3_LOW
    input_signals = Column(JSON, nullable=False) # Snapshot of KEV, EPSS, CVSS, Exposure, Criticality
    applied_rules = Column(JSON, nullable=False) # List of rule IDs that matched
    reasoning_factors = Column(JSON, default=list) # List of human-readable bullet points
    uncertainties = Column(JSON, default=list) # List of missing facts (e.g. "Port 80 reachability unverified")
    recommended_action = Column(Text, nullable=False)
    assessed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    finding = relationship("Finding", back_populates="risk_assessments")
    policy = relationship("RiskPolicy", back_populates="assessments")
