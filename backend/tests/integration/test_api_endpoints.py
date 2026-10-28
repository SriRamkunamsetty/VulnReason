import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest.mark.asyncio
async def test_health_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/health/liveness")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

        resp2 = await client.get("/api/v1/health/readiness")
        assert resp2.status_code == 200
        assert resp2.json()["database_connected"] is True

@pytest.mark.asyncio
async def test_list_findings_and_graph_paths():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Findings list
        f_resp = await client.get("/api/v1/findings")
        assert f_resp.status_code == 200
        findings = f_resp.json()
        assert len(findings) >= 2

        # Graph attack paths
        g_resp = await client.get("/api/v1/graph/paths?entry_exposure=INTERNET_FACING&target_criticality=MISSION_CRITICAL")
        assert g_resp.status_code == 200
        paths = g_resp.json()
        assert len(paths) >= 1
        assert paths[0]["feasibility_tier"] == "VERIFIED_CHAIN"

@pytest.mark.asyncio
async def test_counterfactual_simulation_api():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "sever_relationship_ids": ["rel-app-to-db"],
            "remediate_cves": []
        }
        sim_resp = await client.post("/api/v1/graph/simulate", json=payload)
        assert sim_resp.status_code == 200
        data = sim_resp.json()
        assert data["initial_critical_paths_count"] >= 1
        assert data["residual_critical_paths_count"] == 0
        assert data["severed_paths_count"] >= 1

@pytest.mark.asyncio
async def test_evaluation_benchmark_run():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        eval_resp = await client.post("/api/v1/evaluation/run")
        assert eval_resp.status_code == 200
        report = eval_resp.json()
        assert report["total_scenarios_evaluated"] >= 50
        assert len(report["baselines"]) == 5

@pytest.mark.asyncio
async def test_downloadable_report_generation():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Request report for seeded finding-001
        rep_resp = await client.get("/api/v1/findings/finding-001/report")
        assert rep_resp.status_code == 200
        text = rep_resp.text
        assert "Security Assessment & Attack Narrative Report" in text
        assert "CVE-2024-21413" in text
        assert "Executive Summary" in text
