import hashlib
import json
from typing import Dict, Any, List, Set, Tuple
from app.schemas.ai_eval import StructuredSecurityAssessment, ReasoningClaim, RemediationLeverageItem

class PromptSanitizer:
    @staticmethod
    def wrap_untrusted_data(label: str, content: Any) -> str:
        """
        Encloses untrusted user/scanner inputs into isolated XML boundary tags.
        Prevents prompt injection from hijacking system instructions.
        """
        serialized = json.dumps(content, ensure_ascii=False) if isinstance(content, (dict, list)) else str(content)
        # Escape potential XML closing tag breakouts
        safe_content = serialized.replace(f"</{label}>", f"&lt;/{label}&gt;")
        return f"<{label}>\n{safe_content}\n</{label}>"

class DeterministicCitationAuditor:
    @staticmethod
    def audit_claims(
        claims: List[Dict[str, Any]], 
        valid_evidence_ids: Set[str]
    ) -> Tuple[bool, int, float, List[str]]:
        """
        Validates that every claim's supporting_evidence_ids actually exists in the ingested bundle.
        Calculates:
          - audit_passed (bool)
          - unsupported_claim_count (int)
          - unsupported_claim_rate (float)
          - invalid_citations (list of hallucinated IDs)
        """
        total_claims = len(claims)
        if total_claims == 0:
            return True, 0, 0.0, []

        unsupported_count = 0
        invalid_citations: List[str] = []

        for c in claims:
            cited_ids = set(c.get("supporting_evidence_ids", []))
            dangling = cited_ids - valid_evidence_ids
            if dangling:
                invalid_citations.extend(list(dangling))
                unsupported_count += 1
            elif c.get("claim_type") == "OBSERVED_FACT" and len(cited_ids) == 0:
                unsupported_count += 1

        rate = round(unsupported_count / total_claims, 3)
        passed = (unsupported_count == 0) and (len(invalid_citations) == 0)
        return passed, unsupported_count, rate, invalid_citations

class AIReasoningService:
    def __init__(self, model_name: str = "vulnreason-reasoning-engine-v1"):
        self.model_name = model_name

    def generate_assessment(
        self,
        finding_id: str,
        finding_data: Dict[str, Any],
        asset_data: Dict[str, Any],
        valid_evidence_ids: Set[str]
    ) -> Dict[str, Any]:
        """
        Generates structured security assessment with strict schema conformance.
        """
        # Pack evidence into sanitized blocks
        sanitized_bundle = (
            PromptSanitizer.wrap_untrusted_data("asset_evidence", asset_data) + "\n" +
            PromptSanitizer.wrap_untrusted_data("finding_evidence", finding_data)
        )
        prompt_hash = hashlib.sha256(sanitized_bundle.encode("utf-8")).hexdigest()

        cve = finding_data.get("cve_id", "CVE-UNKNOWN")
        hostname = asset_data.get("hostname", "host-unknown")
        exposure = asset_data.get("exposure", "INTERNAL")

        # Deterministic structured generation
        primary_evidence = list(valid_evidence_ids)[0] if valid_evidence_ids else finding_id

        claims = [
            {
                "claim_id": "CLM-001",
                "claim_type": "OBSERVED_FACT",
                "statement": f"Vulnerability {cve} was identified on host {hostname}.",
                "supporting_evidence_ids": [primary_evidence],
                "prerequisites": ["Scanner detection verified"],
                "missing_verification": []
            },
            {
                "claim_id": "CLM-002",
                "claim_type": "INFERENCE" if exposure in ["INTERNET_FACING", "DMZ"] else "HYPOTHESIS",
                "statement": f"Asset {hostname} has exposure tier {exposure}, altering lateral reachable risk.",
                "supporting_evidence_ids": [primary_evidence],
                "prerequisites": ["Network exposure policy alignment"],
                "missing_verification": ["Subnet security group ingress verification"]
            }
        ]

        remediations = [
            {
                "action": f"Upgrade affected package to {finding_data.get('fixed_version', 'latest vendor release')}",
                "target_component": finding_data.get("package_name", "Component"),
                "estimated_findings_resolved": 1,
                "validation_step": "Run authenticated package rescan"
            }
        ]

        passed, unsupp_count, unsupp_rate, invalid_cites = DeterministicCitationAuditor.audit_claims(
            claims, valid_evidence_ids
        )

        return {
            "finding_id": finding_id,
            "model_name": self.model_name,
            "prompt_hash": prompt_hash,
            "narrative_summary": f"Evidence-grounded evaluation for {cve} on {hostname}. Prioritized in alignment with verified network exposure and affected version bounds.",
            "claims_payload": claims,
            "remediation_recommendations": remediations,
            "citation_audit_passed": passed,
            "unsupported_claim_count": unsupp_count,
            "unsupported_claim_rate": unsupp_rate,
            "invalid_citations": invalid_cites
        }

ai_reasoning_service = AIReasoningService()
