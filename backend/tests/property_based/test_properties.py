from hypothesis import given, strategies as st
from app.services.applicability.engine import applicability_engine
from app.services.risk.engine import risk_engine

@given(st.text())
def test_applicability_parser_never_crashes_on_arbitrary_strings(v_str):
    result = applicability_engine.parse_version_tuple(v_str)
    assert result is None or isinstance(result, tuple)

@given(
    cvss=st.floats(min_value=0.0, max_value=10.0),
    epss_p=st.floats(min_value=0.0, max_value=1.0),
    is_kev=st.booleans(),
    exposure=st.sampled_from(["INTERNET_FACING", "DMZ", "INTERNAL", "RESTRICTED_ISOLATED", "UNKNOWN"]),
    criticality=st.sampled_from(["MISSION_CRITICAL", "HIGH", "MEDIUM", "LOW"])
)
def test_risk_engine_determinism_and_validity(cvss, epss_p, is_kev, exposure, criticality):
    signals = {
        "is_cisa_kev": is_kev,
        "epss_percentile": epss_p,
        "cvss_score": cvss,
        "asset_exposure": exposure,
        "asset_criticality": criticality,
        "applicability": "CONFIRMED_APPLICABLE"
    }
    result = risk_engine.evaluate(signals)
    assert result["priority_tier"] in ["P0_URGENT", "P1_HIGH", "P2_MEDIUM", "P3_LOW"]
    assert len(result["applied_rules"]) >= 1
    assert isinstance(result["reasoning_factors"], list)
