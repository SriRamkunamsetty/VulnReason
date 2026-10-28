from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

class RiskAssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    finding_id: str
    policy_version: str
    priority_tier: str
    input_signals: Dict[str, Any]
    applied_rules: List[str]
    reasoning_factors: List[str]
    uncertainties: List[str]
    recommended_action: str
    assessed_at: datetime

class AttackGraphHop(BaseModel):
    step_number: int
    source_asset_id: str
    source_hostname: str
    target_asset_id: str
    target_hostname: str
    relationship_type: str
    port: Optional[int] = None
    state: str
    via_vulnerability_cve: Optional[str] = None
    prerequisites: List[str] = Field(default_factory=list)

class AttackPathResponse(BaseModel):
    path_id: str
    entry_asset: str
    target_asset: str
    target_criticality: str
    path_length: int
    verified_edge_ratio: float
    feasibility_tier: str
    has_unverified_hops: bool
    hops: List[AttackGraphHop]
    mitigating_controls: List[str] = Field(default_factory=list)

class CounterfactualSimulationRequest(BaseModel):
    sever_relationship_ids: List[str] = Field(default_factory=list)
    remediate_cves: List[str] = Field(default_factory=list)

class CounterfactualSimulationResponse(BaseModel):
    initial_critical_paths_count: int
    residual_critical_paths_count: int
    severed_paths_count: int
    remediated_findings_count: int
    severed_path_details: List[Dict[str, Any]]
    recommendations: List[str]
