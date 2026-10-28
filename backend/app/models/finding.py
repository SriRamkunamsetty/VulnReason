import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from app.db.session import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    vulnerability_id = Column(String(36), ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True, index=True)
    cve_id = Column(String(64), nullable=False, index=True)
    
    package_name = Column(String(255), nullable=True, index=True)
    installed_version = Column(String(128), nullable=True)
    fixed_version = Column(String(128), nullable=True)
    location_path = Column(String(512), nullable=True)
    
    # Applicability State
    applicability = Column(String(32), default="INSUFFICIENT_EVIDENCE", nullable=False, index=True) # CONFIRMED_APPLICABLE, LIKELY_APPLICABLE, NOT_APPLICABLE, INSUFFICIENT_EVIDENCE, CONFLICTING_EVIDENCE
    applicability_rationale = Column(Text, nullable=True)
    applicability_source = Column(String(64), default="DETERMINISTIC_RULES", nullable=False) # DETERMINISTIC_RULES, ANALYST_OVERRIDE, AI_INFERENCE
    
    # Lifecycle Status
    status = Column(String(32), default="OPEN", nullable=False, index=True) # OPEN, TRIAGED, IN_PROGRESS, READY_FOR_VERIFICATION, VERIFIED_REMEDIATED, ACCEPTED_RISK, FALSE_POSITIVE, REOPENED
    
    # Contextual Priority Tier
    contextual_priority = Column(String(32), default="P3_LOW", nullable=False, index=True) # P0_URGENT, P1_HIGH, P2_MEDIUM, P3_LOW
    
    # Clustering
    duplicate_cluster_id = Column(String(36), ForeignKey("duplicate_clusters.id", ondelete="SET NULL"), nullable=True, index=True)
    root_cause_cluster_id = Column(String(36), ForeignKey("root_cause_clusters.id", ondelete="SET NULL"), nullable=True, index=True)
    
    assigned_team = Column(String(128), nullable=True)
    assigned_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    
    first_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    organization = relationship("Organization", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")
    vulnerability = relationship("Vulnerability", back_populates="findings")
    observations = relationship("FindingObservation", back_populates="finding", cascade="all, delete-orphan")
    evidence_links = relationship("FindingEvidence", back_populates="finding", cascade="all, delete-orphan")
    duplicate_cluster = relationship("DuplicateCluster", foreign_keys=[duplicate_cluster_id], back_populates="findings")
    root_cause_cluster = relationship("RootCauseCluster", back_populates="findings")
    risk_assessments = relationship("RiskAssessment", back_populates="finding", cascade="all, delete-orphan")
    remediation_tasks = relationship("RemediationTask", back_populates="finding", cascade="all, delete-orphan")
    ai_assessments = relationship("AIAssessment", back_populates="finding", cascade="all, delete-orphan")

class FindingObservation(Base):
    __tablename__ = "finding_observations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    scanner_name = Column(String(64), nullable=False, index=True) # Snyk, Qualys, Nessus, Trivy, SARIF, CycloneDX
    raw_finding_id = Column(String(255), nullable=True)
    scanner_severity = Column(String(32), nullable=True)
    scan_timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    raw_payload = Column(JSON, nullable=False)

    finding = relationship("Finding", back_populates="observations")

class FindingEvidence(Base):
    __tablename__ = "finding_evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type = Column(String(64), nullable=False) # PACKAGE_MANIFEST, NETWORK_BANNER, SYSTEM_CONFIG, VEX_STATEMENT
    evidence_identifier = Column(String(255), nullable=False)
    evidence_hash = Column(String(64), nullable=True)
    confidence_score = Column(Float, default=1.0, nullable=False) # 0.0 - 1.0
    description = Column(Text, nullable=False)
    collected_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    finding = relationship("Finding", back_populates="evidence_links")

class DuplicateCluster(Base):
    __tablename__ = "duplicate_clusters"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    canonical_finding_id = Column(String(36), nullable=False)
    status = Column(String(32), default="ACTIVE", nullable=False) # ACTIVE, DISBANDED
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    findings = relationship("Finding", foreign_keys="Finding.duplicate_cluster_id", back_populates="duplicate_cluster")

class DuplicateCandidate(Base):
    __tablename__ = "duplicate_candidates"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_a_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_b_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    similarity_score = Column(Float, nullable=False) # 0.00 - 1.00
    shared_signals = Column(JSON, default=list) # e.g. ["SAME_CVE", "SAME_PACKAGE", "SAME_ASSET"]
    status = Column(String(32), default="PENDING_REVIEW", nullable=False, index=True) # PENDING_REVIEW, MERGED, REJECTED
    reviewed_by = Column(String(36), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    review_rationale = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

class RootCauseCluster(Base):
    __tablename__ = "root_cause_clusters"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    shared_component = Column(String(255), nullable=False) # e.g. "log4j-core:2.14.1" or "nginx.conf SSL Cipher Suite"
    cluster_type = Column(String(64), nullable=False) # SHARED_DEPENDENCY, CONFIGURATION_DRIFT, REPEATED_TEMPLATE
    description = Column(Text, nullable=False)
    remediation_leverage_score = Column(Float, default=1.0, nullable=False)
    status = Column(String(32), default="ACTIVE", nullable=False) # ACTIVE, REMEDIATED, IGNORED
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    findings = relationship("Finding", back_populates="root_cause_cluster")
