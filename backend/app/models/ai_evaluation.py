import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from app.db.session import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

class AIAssessment(Base):
    __tablename__ = "ai_assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    model_name = Column(String(64), nullable=False) # e.g. "gemini-1.5-pro", "gpt-4o", "mock-analyst-v1"
    prompt_hash = Column(String(64), nullable=False)
    narrative_summary = Column(Text, nullable=False)
    claims_payload = Column(JSON, nullable=False) # List of ReasoningClaim objects
    remediation_recommendations = Column(JSON, default=list)
    citation_audit_passed = Column(Boolean, default=False, nullable=False)
    unsupported_claim_count = Column(Integer, default=0, nullable=False)
    unsupported_claim_rate = Column(Float, default=0.0, nullable=False)
    invalid_citations = Column(JSON, default=list)
    assessed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    finding = relationship("Finding", back_populates="ai_assessments")

class EvaluationScenario(Base):
    __tablename__ = "evaluation_scenarios"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scenario_id = Column(String(32), unique=True, nullable=False, index=True) # e.g. "VR-0001"
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    asset_context = Column(JSON, nullable=False)
    input_findings = Column(JSON, nullable=False)
    ground_truth = Column(JSON, nullable=False) # True applicability, true priority tier, true attack path existence
    injected_attack_payload = Column(Text, nullable=True) # Prompt injection test payload
    is_held_out = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    labels = relationship("EvaluationLabel", back_populates="scenario", cascade="all, delete-orphan")

class EvaluationLabel(Base):
    __tablename__ = "evaluation_labels"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scenario_id = Column(String(36), ForeignKey("evaluation_scenarios.id", ondelete="CASCADE"), nullable=False, index=True)
    baseline_name = Column(String(64), nullable=False, index=True) # CVSS_ONLY, EPSS_ONLY, POLICY_ONLY, DETERMINISTIC_GRAPH, FULL_AI_SYSTEM
    predicted_priority = Column(String(32), nullable=False)
    predicted_applicability = Column(String(32), nullable=True)
    metrics_payload = Column(JSON, nullable=False) # Precision, Recall, UCR, Hallucination score
    evaluated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    scenario = relationship("EvaluationScenario", back_populates="labels")
