import pytest
from app.services.ai.reasoning import DeterministicCitationAuditor

def test_citation_auditor_passed():
    claims = [
        {
            "claim_id": "C1",
            "claim_type": "OBSERVED_FACT",
            "statement": "Port 443 is open",
            "supporting_evidence_ids": ["ev-100"]
        }
    ]
    valid_ids = {"ev-100", "ev-101"}
    passed, unsupp_count, rate, invalid = DeterministicCitationAuditor.audit_claims(claims, valid_ids)
    assert passed is True
    assert unsupp_count == 0
    assert rate == 0.0
    assert len(invalid) == 0

def test_citation_auditor_detects_hallucinated_citations():
    claims = [
        {
            "claim_id": "C2",
            "claim_type": "OBSERVED_FACT",
            "statement": "Database has unencrypted credit cards",
            "supporting_evidence_ids": ["fake-id-999"]
        }
    ]
    valid_ids = {"ev-100"}
    passed, unsupp_count, rate, invalid = DeterministicCitationAuditor.audit_claims(claims, valid_ids)
    assert passed is False
    assert unsupp_count == 1
    assert rate == 1.0
    assert "fake-id-999" in invalid
