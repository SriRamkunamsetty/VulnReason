from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

class FindingObservationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    scanner_name: str
    raw_finding_id: Optional[str]
    scanner_severity: Optional[str]
    scan_timestamp: datetime
    raw_payload: Dict[str, Any]

class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    asset_id: str
    cve_id: str
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    location_path: Optional[str] = None
    applicability: str
    applicability_rationale: Optional[str] = None
    status: str
    contextual_priority: str
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime

class FindingDetailResponse(FindingResponse):
    observations: List[FindingObservationResponse] = Field(default_factory=list)
    asset_hostname: Optional[str] = None
    asset_exposure: Optional[str] = None
    asset_criticality: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None
    cisa_kev_listed: bool = False

class ApplicabilityOverrideRequest(BaseModel):
    applicability: str
    rationale: str = Field(min_length=5)

class DuplicateCandidateResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    finding_a_id: str
    finding_b_id: str
    similarity_score: float
    shared_signals: List[str]
    status: str
    created_at: datetime

class DuplicateReviewRequest(BaseModel):
    decision: str
    rationale: str
