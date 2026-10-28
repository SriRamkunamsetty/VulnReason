from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

class AssetBase(BaseModel):
    hostname: str
    ip_addresses: List[str] = Field(default_factory=list)
    operating_system: Optional[str] = None
    exposure: str = "INTERNAL"
    criticality: str = "MEDIUM"
    environment: str = "production"
    owner_team: Optional[str] = None
    metadata_json: Dict[str, Any] = Field(default_factory=dict)

class AssetCreate(AssetBase):
    pass

class AssetResponse(AssetBase):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    created_at: datetime
    updated_at: datetime

class AssetRelationshipCreate(BaseModel):
    source_asset_id: str
    target_asset_id: str
    relationship_type: str
    protocol: Optional[str] = "TCP"
    port: Optional[int] = None
    state: str = "VERIFIED"
    evidence_ids: List[str] = Field(default_factory=list)

class AssetRelationshipResponse(AssetRelationshipCreate):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    verified_at: Optional[datetime] = None
    created_at: datetime
