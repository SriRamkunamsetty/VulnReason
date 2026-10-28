from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from app.db.session import get_db
from app.models.finding import Finding
from app.models.ai_evaluation import AIAssessment
from app.schemas.ai_eval import AIAssessmentResponse
from app.core.middleware import get_current_tenant, TenantContext
from app.services.ai.reasoning import ai_reasoning_service

router = APIRouter(prefix="/reasoning", tags=["AI Reasoning & Citation Auditor"])

@router.post("/assess/{finding_id}", response_model=AIAssessmentResponse)
async def assess_finding_with_ai(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    query = (
        select(Finding)
        .where(Finding.id == finding_id, Finding.tenant_id == tenant.tenant_id)
        .options(selectinload(Finding.asset), selectinload(Finding.observations))
    )
    result = await db.execute(query)
    finding = result.scalars().first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    asset = finding.asset
    asset_data = {
        "asset_id": asset.id if asset else "unknown",
        "hostname": asset.hostname if asset else "unknown",
        "exposure": asset.exposure if asset else "INTERNAL",
        "criticality": asset.criticality if asset else "MEDIUM"
    }

    finding_data = {
        "finding_id": finding.id,
        "cve_id": finding.cve_id,
        "package_name": finding.package_name,
        "installed_version": finding.installed_version,
        "fixed_version": finding.fixed_version,
        "applicability": finding.applicability,
        "contextual_priority": finding.contextual_priority
    }

    valid_evidence_ids = {finding.id}
    if asset:
        valid_evidence_ids.add(asset.id)
    for obs in finding.observations:
        valid_evidence_ids.add(obs.id)

    assessment = ai_reasoning_service.generate_assessment(
        finding_id=finding.id,
        finding_data=finding_data,
        asset_data=asset_data,
        valid_evidence_ids=valid_evidence_ids
    )

    ai_record = AIAssessment(
        finding_id=finding.id,
        model_name=assessment["model_name"],
        prompt_hash=assessment["prompt_hash"],
        narrative_summary=assessment["narrative_summary"],
        claims_payload=assessment["claims_payload"],
        remediation_recommendations=assessment["remediation_recommendations"],
        citation_audit_passed=assessment["citation_audit_passed"],
        unsupported_claim_count=assessment["unsupported_claim_count"],
        unsupported_claim_rate=assessment["unsupported_claim_rate"],
        invalid_citations=assessment["invalid_citations"]
    )
    db.add(ai_record)
    await db.commit()
    await db.refresh(ai_record)
    return ai_record
