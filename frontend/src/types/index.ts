export type PriorityTier = 'P0_URGENT' | 'P1_HIGH' | 'P2_MEDIUM' | 'P3_LOW';
export type ApplicabilityState = 'CONFIRMED_APPLICABLE' | 'LIKELY_APPLICABLE' | 'NOT_APPLICABLE' | 'INSUFFICIENT_EVIDENCE' | 'CONFLICTING_EVIDENCE';
export type FindingStatus = 'OPEN' | 'TRIAGED' | 'IN_PROGRESS' | 'READY_FOR_VERIFICATION' | 'VERIFIED_REMEDIATED' | 'ACCEPTED_RISK' | 'FALSE_POSITIVE' | 'REOPENED' | 'MERGED_DUPLICATE';

export interface FindingObservation {
  id: string;
  scanner_name: string;
  raw_finding_id?: string;
  scanner_severity?: string;
  scan_timestamp: string;
  raw_payload: Record<string, any>;
}

export interface Finding {
  id: string;
  tenant_id: string;
  asset_id: string;
  cve_id: string;
  package_name?: string;
  installed_version?: string;
  fixed_version?: string;
  location_path?: string;
  applicability: ApplicabilityState;
  applicability_rationale?: string;
  status: FindingStatus;
  contextual_priority: PriorityTier;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  observations?: FindingObservation[];
  asset_hostname?: string;
  asset_exposure?: string;
  asset_criticality?: string;
  cvss_score?: number;
  cvss_vector?: string;
  epss_score?: number;
  cisa_kev_listed?: boolean;
}

export interface Asset {
  id: string;
  tenant_id: string;
  hostname: string;
  ip_addresses: string[];
  operating_system?: string;
  exposure: 'INTERNET_FACING' | 'DMZ' | 'INTERNAL' | 'RESTRICTED_ISOLATED';
  criticality: 'MISSION_CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  environment: string;
}

export interface AttackGraphHop {
  step_number: number;
  source_asset_id: string;
  source_hostname: string;
  target_asset_id: string;
  target_hostname: string;
  relationship_type: string;
  port?: number;
  state: 'VERIFIED' | 'INFERRED' | 'UNKNOWN';
  prerequisites: string[];
}

export interface AttackPath {
  path_id: string;
  entry_asset: string;
  target_asset: string;
  target_criticality: string;
  path_length: number;
  verified_edge_ratio: number;
  feasibility_tier: 'VERIFIED_CHAIN' | 'PLAUSIBLE_HYPOTHESIS' | 'UNVERIFIED_PATH';
  has_unverified_hops: boolean;
  hops: AttackGraphHop[];
  mitigating_controls: string[];
}

export interface CounterfactualSimulationResult {
  initial_critical_paths_count: number;
  residual_critical_paths_count: number;
  severed_paths_count: number;
  remediated_findings_count: number;
  severed_path_details: AttackPath[];
  recommendations: string[];
}

export interface ReasoningClaim {
  claim_id: string;
  claim_type: 'OBSERVED_FACT' | 'INFERENCE' | 'HYPOTHESIS' | 'UNKNOWN';
  statement: string;
  supporting_evidence_ids: string[];
  prerequisites: string[];
  missing_verification: string[];
}

export interface AIAssessment {
  id: string;
  finding_id: string;
  model_name: string;
  narrative_summary: string;
  claims_payload: ReasoningClaim[];
  remediation_recommendations: Array<{
    action: string;
    target_component: string;
    estimated_findings_resolved: number;
    validation_step: string;
  }>;
  citation_audit_passed: boolean;
  unsupported_claim_count: number;
  unsupported_claim_rate: number;
  invalid_citations: string[];
  assessed_at: string;
}

export interface BaselineMetricResult {
  baseline_name: string;
  precision_at_k: number;
  recall_at_k: number;
  ndcg_at_k: number;
  unsupported_claim_rate: number;
  prompt_injection_resistance_pct: number;
  sample_size: number;
}

export interface BenchmarkReport {
  total_scenarios_evaluated: number;
  evaluation_timestamp: string;
  baselines: BaselineMetricResult[];
  adversarial_findings_summary: string;
}

export interface RemediationTask {
  id: string;
  finding_id: string;
  cve_id: string;
  assigned_team: string;
  status: string;
  due_date: string;
  sla_breached: boolean;
  resolution_notes?: string;
  evidence_count: number;
  created_at: string;
}
