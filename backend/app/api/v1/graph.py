from typing import List, Dict, Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.models.asset import Asset, AssetRelationship
from app.models.finding import Finding
from app.schemas.risk_graph import AttackPathResponse, CounterfactualSimulationRequest, CounterfactualSimulationResponse
from app.core.middleware import get_current_tenant, TenantContext
from app.services.graph.engine import attack_graph_engine

router = APIRouter(prefix="/graph", tags=["Attack Graph & Counterfactual Simulation"])

async def _load_tenant_graph(db: AsyncSession, tenant_id: str):
    assets_res = await db.execute(select(Asset).where(Asset.tenant_id == tenant_id))
    assets = [
        {"id": a.id, "hostname": a.hostname, "exposure": a.exposure, "criticality": a.criticality, "environment": a.environment}
        for a in assets_res.scalars().all()
    ]

    rel_res = await db.execute(select(AssetRelationship).where(AssetRelationship.tenant_id == tenant_id))
    relationships = [
        {
            "id": r.id,
            "source_asset_id": r.source_asset_id,
            "target_asset_id": r.target_asset_id,
            "relationship_type": r.relationship_type,
            "state": r.state,
            "port": r.port,
            "protocol": r.protocol
        }
        for r in rel_res.scalars().all()
    ]

    findings_res = await db.execute(select(Finding).where(Finding.tenant_id == tenant_id))
    findings = [
        {"id": f.id, "asset_id": f.asset_id, "cve_id": f.cve_id, "contextual_priority": f.contextual_priority, "status": f.status}
        for f in findings_res.scalars().all()
    ]

    attack_graph_engine.build_graph(assets, relationships, findings)

@router.get("/paths", response_model=List[AttackPathResponse])
async def get_attack_paths(
    entry_exposure: str = Query("INTERNET_FACING"),
    target_criticality: str = Query("MISSION_CRITICAL"),
    max_depth: int = Query(5, ge=1, le=10),
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    await _load_tenant_graph(db, tenant.tenant_id)
    paths = attack_graph_engine.find_attack_paths(entry_exposure, target_criticality, max_depth)
    return paths

@router.post("/simulate", response_model=CounterfactualSimulationResponse)
async def simulate_remediation(
    req: CounterfactualSimulationRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    await _load_tenant_graph(db, tenant.tenant_id)
    result = attack_graph_engine.simulate_counterfactual_remediation(
        sever_relationship_ids=req.sever_relationship_ids,
        remediate_cves=req.remediate_cves
    )
    return result
