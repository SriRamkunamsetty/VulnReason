import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.db.session import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

class Asset(Base):
    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    hostname = Column(String(255), nullable=False, index=True)
    ip_addresses = Column(JSON, default=list, nullable=False) # list of string IPs
    operating_system = Column(String(128), nullable=True)
    exposure = Column(String(32), default="INTERNAL", nullable=False, index=True) # INTERNET_FACING, DMZ, INTERNAL, RESTRICTED_ISOLATED
    criticality = Column(String(32), default="MEDIUM", nullable=False, index=True) # MISSION_CRITICAL, HIGH, MEDIUM, LOW
    environment = Column(String(32), default="production", nullable=False) # production, staging, development
    owner_team = Column(String(128), nullable=True)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    organization = relationship("Organization", back_populates="assets")
    software_components = relationship("SoftwareComponent", back_populates="asset", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")
    outgoing_relationships = relationship(
        "AssetRelationship",
        foreign_keys="AssetRelationship.source_asset_id",
        back_populates="source_asset",
        cascade="all, delete-orphan"
    )
    incoming_relationships = relationship(
        "AssetRelationship",
        foreign_keys="AssetRelationship.target_asset_id",
        back_populates="target_asset",
        cascade="all, delete-orphan"
    )

class AssetRelationship(Base):
    __tablename__ = "asset_relationships"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    source_asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    target_asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type = Column(String(64), nullable=False, index=True) # CAN_ACCESS, TRUSTS_IDENTITY, EXPOSED_VIA, CONNECTS_TO
    protocol = Column(String(32), nullable=True) # TCP, UDP, HTTPS, SSH, etc.
    port = Column(Integer, nullable=True)
    state = Column(String(32), default="UNKNOWN", nullable=False, index=True) # VERIFIED, INFERRED, HYPOTHETICAL, UNKNOWN
    evidence_ids = Column(JSON, default=list) # List of UUIDs
    verified_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    source_asset = relationship("Asset", foreign_keys=[source_asset_id], back_populates="outgoing_relationships")
    target_asset = relationship("Asset", foreign_keys=[target_asset_id], back_populates="incoming_relationships")

class SoftwareComponent(Base):
    __tablename__ = "software_components"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    version = Column(String(128), nullable=False)
    purl = Column(String(512), nullable=True, index=True) # Package URL
    cpe = Column(String(255), nullable=True)
    ecosystem = Column(String(64), nullable=True) # npm, pypi, maven, deb, etc.
    location_path = Column(String(512), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    asset = relationship("Asset", back_populates="software_components")
