from typing import List, Optional
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from app.db.session import get_db
from app.models.finding import Finding
from app.models.remediation import RemediationTask, RemediationEvidence
from app.models.auth import AuditEvent
from app.core.middleware import get_current_tenant, TenantContext

router = APIRouter(prefix="/remediation", tags=["Remediation & Verification"])

class RemediationTaskCreate(BaseModel):
    finding_id: str
    assigned_team: Optional[str] = "AppSec"
    due_days: int = 30

class RemediationTaskUpdate(BaseModel):
    status: str # OPEN, IN_PROGRESS, READY_FOR_VERIFICATION, RESOLVED, ACCEPTED_RISK, REOPENED
    resolution_notes: Optional[str] = None
    verification_type: Optional[str] = None # SCANNER_RESCAN, CONFIGURATION_PROOF, PATCH_COMMIT
    evidence_proof: Optional[dict] = None

@router.get("/tasks")
async def list_tasks(
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    query = (
        select(RemediationTask)
        .where(RemediationTask.tenant_id == tenant.tenant_id)
        .options(selectinload(RemediationTask.evidence_records), selectinload(RemediationTask.finding))
    )
    if status:
        query = query.where(RemediationTask.status == status)
    result = await db.execute(query)
    tasks = result.scalars().all()
    return [
        {
            "id": t.id,
            "finding_id": t.finding_id,
            "cve_id": t.finding.cve_id if t.finding else "UNKNOWN",
            "assigned_team": t.assigned_team,
            "status": t.status,
            "due_date": t.due_date,
            "sla_breached": t.sla_breached,
            "resolution_notes": t.resolution_notes,
            "evidence_count": len(t.evidence_records),
            "created_at": t.created_at
        }
        for t in tasks
    ]

@router.post("/tasks")
async def create_task(
    req: RemediationTaskCreate,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    finding = await db.get(Finding, req.finding_id)
    if not finding or finding.tenant_id != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")

    due_date = datetime.now(timezone.utc) + timedelta(days=req.due_days)
    task = RemediationTask(
        tenant_id=tenant.tenant_id,
        finding_id=finding.id,
        assigned_team=req.assigned_team,
        due_date=due_date,
        status="OPEN"
    )
    db.add(task)
    finding.status = "IN_PROGRESS"

    audit = AuditEvent(
        tenant_id=tenant.tenant_id,
        actor_id=tenant.user_id,
        action="REMEDIATION_TASK_CREATED",
        resource_type="REMEDIATION_TASK",
        resource_id=task.id,
        details={"finding_id": finding.id, "due_date": str(due_date)}
    )
    db.add(audit)
    await db.commit()
    await db.refresh(task)
    return {"task_id": task.id, "status": task.status, "due_date": task.due_date}

@router.patch("/tasks/{task_id}")
async def update_task_status(
    task_id: str,
    req: RemediationTaskUpdate,
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    query = (
        select(RemediationTask)
        .where(RemediationTask.id == task_id, RemediationTask.tenant_id == tenant.tenant_id)
        .options(selectinload(RemediationTask.finding))
    )
    result = await db.execute(query)
    task = result.scalars().first()
    if not task:
        raise HTTPException(status_code=404, detail="Remediation task not found")

    # Production rule: closure requires verification evidence!
    if req.status == "RESOLVED":
        if not req.verification_type or not req.evidence_proof:
            raise HTTPException(
                status_code=400,
                detail="Production Gate Enforced: Task cannot be transitioned to RESOLVED without cryptographic verification proof or scan evidence."
            )
        evidence = RemediationEvidence(
            remediation_task_id=task.id,
            verification_type=req.verification_type,
            evidence_payload=req.evidence_proof,
            verified_by_user_id=tenant.user_id
        )
        db.add(evidence)
        if task.finding:
            task.finding.status = "VERIFIED_REMEDIATED"

    task.status = req.status
    if req.resolution_notes:
        task.resolution_notes = req.resolution_notes

    audit = AuditEvent(
        tenant_id=tenant.tenant_id,
        actor_id=tenant.user_id,
        action="REMEDIATION_STATUS_UPDATED",
        resource_type="REMEDIATION_TASK",
        resource_id=task.id,
        details={"new_status": req.status, "verification_type": req.verification_type}
    )
    db.add(audit)
    await db.commit()
    return {"task_id": task.id, "status": task.status}
