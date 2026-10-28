import pytest
from app.services.applicability.engine import applicability_engine

def test_version_tuple_parsing():
    assert applicability_engine.parse_version_tuple("2.14.1") == (2, 14, 1)
    assert applicability_engine.parse_version_tuple("v1.0.0-beta.1") == (1, 0, 0)
    assert applicability_engine.parse_version_tuple("16.0.14326.20454") == (16, 0, 14326, 20454)
    assert applicability_engine.parse_version_tuple("") is None

def test_applicability_confirmed():
    status, rationale = applicability_engine.evaluate_applicability("2.14.1", "2.15.0")
    assert status == "CONFIRMED_APPLICABLE"
    assert "strictly less than" in rationale

def test_applicability_not_applicable():
    status, rationale = applicability_engine.evaluate_applicability("2.16.0", "2.15.0")
    assert status == "NOT_APPLICABLE"
    assert "at or above" in rationale

def test_applicability_insufficient_evidence():
    status, rationale = applicability_engine.evaluate_applicability(None, "2.15.0")
    assert status == "INSUFFICIENT_EVIDENCE"
