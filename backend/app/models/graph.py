import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, Integer, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.db.session import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

class AttackGraphNode(Base):
    __tablename__ = "attack_graph_nodes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    node_type = Column(String(32), nullable=False, index=True) # ASSET, VULNERABILITY, IDENTITY, ZONE, CONTROL
    entity_id = Column(String(36), nullable=False, index=True)
    label = Column(String(255), nullable=False)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

class AttackGraphEdge(Base):
    __tablename__ = "attack_graph_edges"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    source_node_id = Column(String(36), ForeignKey("attack_graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    target_node_id = Column(String(36), ForeignKey("attack_graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type = Column(String(64), nullable=False, index=True) # CAN_ACCESS, EXPOSED_TO, RUNS_COMPONENT, PERMITS_PIVOT, MITIGATED_BY
    state = Column(String(32), default="UNKNOWN", nullable=False, index=True) # VERIFIED, INFERRED, HYPOTHETICAL, UNKNOWN
    prerequisites = Column(JSON, default=list) # e.g. ["Unauthenticated RCE", "Egress port 443 permitted"]
    evidence_ids = Column(JSON, default=list)
    confidence = Column(Float, default=1.0, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

class AttackPathAssessment(Base):
    __tablename__ = "attack_path_assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    entry_node_id = Column(String(36), ForeignKey("attack_graph_nodes.id", ondelete="CASCADE"), nullable=False)
    target_node_id = Column(String(36), ForeignKey("attack_graph_nodes.id", ondelete="CASCADE"), nullable=False)
    path_length = Column(Integer, nullable=False)
    hops = Column(JSON, nullable=False) # Sequence of nodes and edges
    verified_edge_ratio = Column(Float, nullable=False) # 0.0 - 1.0
    feasibility_tier = Column(String(32), nullable=False, index=True) # VERIFIED_CHAIN, PLAUSIBLE_HYPOTHESIS, UNVERIFIED_PATH
    missing_prerequisites = Column(JSON, default=list)
    mitigating_controls = Column(JSON, default=list)
    assessed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
