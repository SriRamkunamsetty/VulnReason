from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from app.db.session import get_db
from app.models.finding import Finding, FindingObservation, DuplicateCandidate
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.auth import AuditEvent
from app.schemas.finding import (
    FindingResponse,
    FindingDetailResponse,
    ApplicabilityOverrideRequest,
    DuplicateCandidateResponse,
    DuplicateReviewRequest,
)
from app.core.middleware import get_current_tenant, TenantContext
from app.services.risk.engine import risk_engine
from app.services.reporting.generator import report_generator
from fastapi.responses import PlainTextResponse

router = APIRouter(prefix="/findings", tags=["Findings & Triage"])

@router.get("", response_model=List[FindingResponse])
async def list_findings(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    applicability: Optional[str] = None,
    cve_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    query = select(Finding).where(Finding.tenant_id == tenant.tenant_id)
    if status:
        query = query.where(Finding.status == status)
    if priority:
        query = query.where(Finding.contextual_priority == priority)
    if applicability:
        query = query.where(Finding.applicability == applicability)
    if cve_id:
        query = query.where(Finding.cve_id.ilike(f"%{cve_id}%"))
    
    result = await db.execute(query.order_by(Finding.first_seen_at.desc()))
    return result.scalars().all()

@router.get("/{finding_id}", response_model=FindingDetailResponse)
async def get_finding_detail(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    query = (
        select(Finding)
        .where(Finding.id == finding_id, Finding.tenant_id == tenant.tenant_id)
        .options(selectinload(Finding.observations), selectinload(Finding.asset), selectinload(Finding.vulnerability))
    )
    result = await db.execute(query)
    finding = result.scalars().first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    asset = finding.asset
    vuln = finding.vulnerability

    return FindingDetailResponse(
        id=finding.id,
        tenant_id=finding.tenant_id,
        asset_id=finding.asset_id,
        cve_id=finding.cve_id,
        package_name=finding.package_name,
        installed_version=finding.installed_version,
        fixed_version=finding.fixed_version,
        location_path=finding.location_path,
        applicability=finding.applicability,
        applicability_rationale=finding.applicability_rationale,
        status=finding.status,
        contextual_priority=finding.contextual_priority,
        first_seen_at=finding.first_seen_at,
        last_seen_at=finding.last_seen_at,
        created_at=finding.created_at,
        observations=[
            {
                "id": obs.id,
                "scanner_name": obs.scanner_name,
                "raw_finding_id": obs.raw_finding_id,
                "scanner_severity": obs.scanner_severity,
                "scan_timestamp": obs.scan_timestamp,
                "raw_payload": obs.raw_payload
            }
            for obs in finding.observations
        ],
        asset_hostname=asset.hostname if asset else None,
        asset_exposure=asset.exposure if asset else None,
        asset_criticality=asset.criticality if asset else None,
        cvss_score=vuln.cvss_v3_base_score if vuln else None,
        cvss_vector=vuln.cvss_v3_vector if vuln else None,
        epss_score=vuln.epss_score if vuln else None,
        cisa_kev_listed=vuln.cisa_kev_listed if vuln else False
    )

@router.get("/{finding_id}/report", response_class=PlainTextResponse)
async def get_finding_report(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    query = (
        select(Finding)
        .where(Finding.id == finding_id, Finding.tenant_id == tenant.tenant_id)
        .options(selectinload(Finding.asset), selectinload(Finding.vulnerability), selectinload(Finding.ai_assessments))
    )
    result = await db.execute(query)
    finding = result.scalars().first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    asset = finding.asset
    vuln = finding.vulnerability

    asset_data = {
        "hostname": asset.hostname if asset else "unknown",
        "exposure": asset.exposure if asset else "INTERNAL",
        "criticality": asset.criticality if asset else "MEDIUM"
    }

    finding_data = {
        "cve_id": finding.cve_id,
        "package_name": finding.package_name,
        "installed_version": finding.installed_version,
        "fixed_version": finding.fixed_version,
        "applicability": finding.applicability,
        "applicability_rationale": finding.applicability_rationale,
        "epss_score": vuln.epss_score if vuln else 0.0,
        "cisa_kev_listed": vuln.cisa_kev_listed if vuln else False
    }

    signals = {
        "is_cisa_kev": vuln.cisa_kev_listed if vuln else False,
        "epss_percentile": vuln.epss_percentile if vuln else 0.0,
        "cvss_score": vuln.cvss_v3_base_score if vuln else 0.0,
        "asset_exposure": asset.exposure if asset else "INTERNAL",
        "asset_criticality": asset.criticality if asset else "MEDIUM",
        "applicability": finding.applicability
    }
    risk_eval = risk_engine.evaluate(signals)

    latest_ai = finding.ai_assessments[-1] if finding.ai_assessments else None
    ai_data = {
        "model_name": latest_ai.model_name if latest_ai else "vulnreason-reasoning-engine-v1",
        "citation_audit_passed": latest_ai.citation_audit_passed if latest_ai else True,
        "narrative_summary": latest_ai.narrative_summary if latest_ai else "Deterministic risk evaluation completed; AI narrative synthesis pending analyst trigger.",
        "claims_payload": latest_ai.claims_payload if latest_ai else []
    }

    report_md = report_generator.generate_markdown_report(finding_data, asset_data, risk_eval, ai_data)
    return report_md

@router.patch("/{finding_id}/applicability", response_model=FindingResponse)
async def override_applicability(
    finding_id: str,
    req: ApplicabilityOverrideRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    query = select(Finding).where(Finding.id == finding_id, Finding.tenant_id == tenant.tenant_id).options(selectinload(Finding.asset), selectinload(Finding.vulnerability))
    result = await db.execute(query)
    finding = result.scalars().first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    old_applicability = finding.applicability
    finding.applicability = req.applicability
    finding.applicability_rationale = req.rationale
    finding.applicability_source = "ANALYST_OVERRIDE"

    # Re-evaluate priority tier deterministically
    asset = finding.asset
    vuln = finding.vulnerability
    signals = {
        "is_cisa_kev": vuln.cisa_kev_listed if vuln else False,
        "epss_percentile": vuln.epss_percentile if vuln else 0.0,
        "cvss_score": vuln.cvss_v3_base_score if vuln else 0.0,
        "asset_exposure": asset.exposure if asset else "INTERNAL",
        "asset_criticality": asset.criticality if asset else "MEDIUM",
        "applicability": req.applicability
    }
    eval_res = risk_engine.evaluate(signals)
    finding.contextual_priority = eval_res["priority_tier"]

    # Audit event
    audit = AuditEvent(
        tenant_id=tenant.tenant_id,
        actor_id=tenant.user_id,
        action="APPLICABILITY_OVERRIDE",
        resource_type="FINDING",
        resource_id=finding.id,
        details={
            "old": old_applicability,
            "new": req.applicability,
            "new_priority": finding.contextual_priority,
            "rationale": req.rationale
        }
    )
    db.add(audit)
    await db.commit()
    await db.refresh(finding)
    return finding

@router.get("/deduplication/candidates", response_model=List[DuplicateCandidateResponse])
async def list_duplicate_candidates(
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    query = select(DuplicateCandidate).where(
        DuplicateCandidate.tenant_id == tenant.tenant_id,
        DuplicateCandidate.status == "PENDING_REVIEW"
    )
    result = await db.execute(query)
    return result.scalars().all()

@router.post("/deduplication/review/{candidate_id}")
async def review_duplicate_candidate(
    candidate_id: str,
    req: DuplicateReviewRequest,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    query = select(DuplicateCandidate).where(
        DuplicateCandidate.id == candidate_id,
        DuplicateCandidate.tenant_id == tenant.tenant_id
    )
    result = await db.execute(query)
    candidate = result.scalars().first()
    if not candidate:
        raise HTTPException(status_code=404, detail="Duplicate candidate not found")

    candidate.status = req.decision # MERGED or REJECTED
    candidate.reviewed_by = tenant.user_id
    candidate.review_rationale = req.rationale

    # If merged, update finding_b status to MERGED_DUPLICATE
    if req.decision == "MERGED":
        finding_b = await db.get(Finding, candidate.finding_b_id)
        if finding_b:
            finding_b.status = "MERGED_DUPLICATE"

    # Audit record
    audit = AuditEvent(
        tenant_id=tenant.tenant_id,
        actor_id=tenant.user_id,
        action="DUPLICATE_MERGE_REVIEW",
        resource_type="DUPLICATE_CANDIDATE",
        resource_id=candidate.id,
        details={"decision": req.decision, "rationale": req.rationale}
    )
    db.add(audit)
    await db.commit()
    return {"status": "success", "decision": req.decision}
