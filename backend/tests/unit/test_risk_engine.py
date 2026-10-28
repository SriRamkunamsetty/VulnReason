import pytest
from app.services.risk.engine import risk_engine

def test_kev_on_perimeter_is_p0_urgent():
    signals = {
        "is_cisa_kev": True,
        "epss_percentile": 0.95,
        "cvss_score": 9.8,
        "asset_exposure": "INTERNET_FACING",
        "asset_criticality": "HIGH",
        "has_reachable_attack_path": True,
        "applicability": "CONFIRMED_APPLICABLE"
    }
    result = risk_engine.evaluate(signals)
    assert result["priority_tier"] == "P0_URGENT"
    assert "RULE_CISA_KEV_ACTIVE_EXPLOIT" in result["applied_rules"]

def test_isolated_critical_cvss_is_p2_medium():
    signals = {
        "is_cisa_kev": False,
        "epss_percentile": 0.15,
        "cvss_score": 9.8,
        "asset_exposure": "RESTRICTED_ISOLATED",
        "asset_criticality": "MEDIUM",
        "has_reachable_attack_path": False,
        "applicability": "CONFIRMED_APPLICABLE"
    }
    result = risk_engine.evaluate(signals)
    assert result["priority_tier"] == "P2_MEDIUM"
    assert "RULE_CRITICAL_CVSS_ISOLATED_BLAST_RADIUS" in result["applied_rules"]

def test_not_applicable_is_p3_low():
    signals = {
        "is_cisa_kev": True,
        "epss_percentile": 0.99,
        "cvss_score": 10.0,
        "asset_exposure": "INTERNET_FACING",
        "asset_criticality": "MISSION_CRITICAL",
        "applicability": "NOT_APPLICABLE"
    }
    result = risk_engine.evaluate(signals)
    assert result["priority_tier"] == "P3_LOW"
    assert "RULE_VERIFIED_NOT_APPLICABLE" in result["applied_rules"]
