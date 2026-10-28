import pytest
from app.services.graph.engine import AttackGraphEngine

def test_attack_path_discovery_and_counterfactual_simulation():
    engine = AttackGraphEngine()
    
    assets = [
        {"id": "A1", "hostname": "web-gateway", "exposure": "INTERNET_FACING", "criticality": "MEDIUM"},
        {"id": "A2", "hostname": "internal-app", "exposure": "INTERNAL", "criticality": "MEDIUM"},
        {"id": "A3", "hostname": "crown-jewel-db", "exposure": "RESTRICTED_ISOLATED", "criticality": "MISSION_CRITICAL"}
    ]
    
    relationships = [
        {"id": "edge-1", "source_asset_id": "A1", "target_asset_id": "A2", "relationship_type": "CAN_ACCESS", "state": "VERIFIED"},
        {"id": "edge-2", "source_asset_id": "A2", "target_asset_id": "A3", "relationship_type": "AUTHENTICATES_TO", "state": "VERIFIED"}
    ]
    
    findings = [
        {"id": "F1", "asset_id": "A1", "cve_id": "CVE-2024-21413", "contextual_priority": "P0_URGENT", "status": "OPEN"}
    ]
    
    engine.build_graph(assets, relationships, findings)
    
    # 1. Verify attack path found
    paths = engine.find_attack_paths(entry_exposure="INTERNET_FACING", target_criticality="MISSION_CRITICAL")
    assert len(paths) == 1
    assert paths[0]["path_length"] == 2
    assert paths[0]["feasibility_tier"] == "VERIFIED_CHAIN"
    assert paths[0]["verified_edge_ratio"] == 1.0

    # 2. Simulate severing edge-2 (firewall block between A2 and A3)
    sim_result = engine.simulate_counterfactual_remediation(
        sever_relationship_ids=["edge-2"],
        remediate_cves=[]
    )
    assert sim_result["initial_critical_paths_count"] == 1
    assert sim_result["residual_critical_paths_count"] == 0
    assert sim_result["severed_paths_count"] == 1
