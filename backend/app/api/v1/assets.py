from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.models.asset import Asset, AssetRelationship
from app.schemas.asset import AssetCreate, AssetResponse, AssetRelationshipCreate, AssetRelationshipResponse
from app.core.middleware import get_current_tenant, TenantContext

router = APIRouter(prefix="/assets", tags=["Assets & Topology"])

@router.get("", response_model=List[AssetResponse])
async def list_assets(
    exposure: Optional[str] = None,
    criticality: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    query = select(Asset).where(Asset.tenant_id == tenant.tenant_id)
    if exposure:
        query = query.where(Asset.exposure == exposure)
    if criticality:
        query = query.where(Asset.criticality == criticality)
    result = await db.execute(query)
    return result.scalars().all()

@router.post("", response_model=AssetResponse)
async def create_asset(
    req: AssetCreate,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    asset = Asset(
        tenant_id=tenant.tenant_id,
        hostname=req.hostname,
        ip_addresses=req.ip_addresses,
        operating_system=req.operating_system,
        exposure=req.exposure,
        criticality=req.criticality,
        environment=req.environment,
        owner_team=req.owner_team,
        metadata_json=req.metadata_json
    )
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    return asset

@router.get("/relationships", response_model=List[AssetRelationshipResponse])
async def list_relationships(
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    query = select(AssetRelationship).where(AssetRelationship.tenant_id == tenant.tenant_id)
    result = await db.execute(query)
    return result.scalars().all()

@router.post("/relationships", response_model=AssetRelationshipResponse)
async def create_relationship(
    req: AssetRelationshipCreate,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    rel = AssetRelationship(
        tenant_id=tenant.tenant_id,
        source_asset_id=req.source_asset_id,
        target_asset_id=req.target_asset_id,
        relationship_type=req.relationship_type,
        protocol=req.protocol,
        port=req.port,
        state=req.state,
        evidence_ids=req.evidence_ids
    )
    db.add(rel)
    await db.commit()
    await db.refresh(rel)
    return rel
