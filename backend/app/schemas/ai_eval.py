from datetime import datetime
from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field, ConfigDict

class ReasoningClaim(BaseModel):
    claim_id: str
    claim_type: Literal["OBSERVED_FACT", "INFERENCE", "HYPOTHESIS", "UNKNOWN"]
    statement: str
    supporting_evidence_ids: List[str] = Field(
        default_factory=list,
        description="Must map to exact finding or asset evidence identifiers in the evidence bundle"
    )
    prerequisites: List[str] = Field(default_factory=list)
    missing_verification: List[str] = Field(default_factory=list)

class RemediationLeverageItem(BaseModel):
    action: str
    target_component: str
    estimated_findings_resolved: int
    validation_step: str

class StructuredSecurityAssessment(BaseModel):
    narrative_summary: str
    attack_chain_hypothesis: List[ReasoningClaim]
    remediation_recommendations: List[RemediationLeverageItem]
    unsupported_assumptions_detected: List[str]
    analyst_action_required: bool

class AIAssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    finding_id: str
    model_name: str
    narrative_summary: str
    claims_payload: List[Dict[str, Any]]
    remediation_recommendations: List[Dict[str, Any]]
    citation_audit_passed: bool
    unsupported_claim_count: int
    unsupported_claim_rate: float
    invalid_citations: List[str]
    assessed_at: datetime

class BenchmarkScenarioResponse(BaseModel):
    id: str
    scenario_id: str
    title: str
    description: str
    ground_truth: Dict[str, Any]
    is_held_out: bool

class BaselineMetricResult(BaseModel):
    baseline_name: str
    precision_at_k: float
    recall_at_k: float
    ndcg_at_k: float
    unsupported_claim_rate: float
    prompt_injection_resistance_pct: float
    sample_size: int

class BenchmarkEvaluationReport(BaseModel):
    total_scenarios_evaluated: int
    evaluation_timestamp: datetime
    baselines: List[BaselineMetricResult]
    adversarial_findings_summary: str
