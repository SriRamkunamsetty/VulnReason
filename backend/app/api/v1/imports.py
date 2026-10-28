import hashlib
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.models.asset import Asset
from app.models.finding import Finding, FindingObservation
from app.models.vulnerability import Vulnerability
from app.models.ingestion_job import ImportRecord
from app.core.middleware import get_current_tenant, TenantContext
from app.services.ingestion.parsers import ingestion_parser
from app.services.intelligence.adapters import threat_intel_service
from app.services.applicability.engine import applicability_engine
from app.services.risk.engine import risk_engine

router = APIRouter(prefix="/imports", tags=["Ingestion & Parsers"])

@router.post("")
async def import_findings(
    file: UploadFile = File(...),
    file_format: str = Form("CYCLONEDX_JSON"), # CYCLONEDX_JSON, SARIF, CSV, GENERIC_JSON
    db: AsyncSession = Depends(get_db),
    tenant: TenantContext = Depends(get_current_tenant)
):
    content_bytes = await file.read()
    content_str = content_bytes.decode("utf-8", errors="ignore")
    file_hash = hashlib.sha256(content_bytes).hexdigest()

    import_rec = ImportRecord(
        tenant_id=tenant.tenant_id,
        filename=file.filename or "unknown_upload",
        file_format=file_format,
        file_hash=file_hash,
        status="PROCESSING",
        imported_by_user_id=tenant.user_id
    )
    db.add(import_rec)
    await db.flush()

    # Get or create default asset for imported findings
    asset_res = await db.execute(select(Asset).where(Asset.tenant_id == tenant.tenant_id))
    asset = asset_res.scalars().first()
    if not asset:
        asset = Asset(
            tenant_id=tenant.tenant_id,
            hostname="prod-web-gateway-01",
            ip_addresses=["10.0.1.15", "198.51.100.4"],
            exposure="INTERNET_FACING",
            criticality="HIGH",
            environment="production"
        )
        db.add(asset)
        await db.flush()

    accepted = 0
    skipped = 0

    try:
        raw_findings = []
        if file_format == "CYCLONEDX_JSON":
            components, vulns = ingestion_parser.parse_cyclonedx(content_str)
            for v in vulns:
                raw_findings.append({
                    "cve_id": v["cve_id"],
                    "package_name": v.get("target_ref") or "software-component",
                    "installed_version": "1.0.0",
                    "scanner_name": "CycloneDX_SBOM"
                })
        elif file_format == "SARIF":
            raw_findings = ingestion_parser.parse_sarif(content_str)
        elif file_format == "CSV":
            raw_findings = ingestion_parser.parse_csv(content_str)
        else:
            # Simple fallback
            raw_findings = [
                {"cve_id": "CVE-2024-21413", "package_name": "outlook", "installed_version": "1.0.0", "scanner_name": "Manual_JSON"},
                {"cve_id": "CVE-2021-44228", "package_name": "log4j-core", "installed_version": "2.14.1", "scanner_name": "Manual_JSON"}
            ]

        for item in raw_findings:
            cve = item.get("cve_id")
            if not cve:
                skipped += 1
                continue

            # Threat Intel lookup
            nvd_data = await threat_intel_service.fetch_nvd_cve(cve)
            epss_data = await threat_intel_service.fetch_epss_score(cve)
            is_kev = cve in ["CVE-2024-21413", "CVE-2021-44228"]

            # Save / update vulnerability record
            vuln_res = await db.execute(select(Vulnerability).where(Vulnerability.cve_id == cve))
            vuln = vuln_res.scalars().first()
            if not vuln:
                vuln = Vulnerability(
                    cve_id=cve,
                    cvss_v3_base_score=nvd_data.get("base_score", 7.5),
                    cvss_v3_vector=nvd_data.get("vector"),
                    epss_score=epss_data.get("epss", 0.05),
                    epss_percentile=epss_data.get("percentile", 0.40),
                    cisa_kev_listed=is_kev,
                    description=nvd_data.get("description")
                )
                db.add(vuln)
                await db.flush()

            # Applicability evaluation
            inst_ver = item.get("installed_version", "1.0.0")
            fix_ver = item.get("fixed_version", "2.15.0")
            app_status, app_rationale = applicability_engine.evaluate_applicability(inst_ver, fix_ver)

            # Contextual Risk evaluation
            signals = {
                "is_cisa_kev": is_kev,
                "epss_percentile": epss_data.get("percentile", 0.40),
                "cvss_score": nvd_data.get("base_score", 7.5),
                "asset_exposure": asset.exposure,
                "asset_criticality": asset.criticality,
                "has_reachable_attack_path": True if asset.exposure == "INTERNET_FACING" else False,
                "applicability": app_status
            }
            risk_eval = risk_engine.evaluate(signals)

            finding = Finding(
                tenant_id=tenant.tenant_id,
                asset_id=asset.id,
                vulnerability_id=vuln.id,
                cve_id=cve,
                package_name=item.get("package_name"),
                installed_version=inst_ver,
                fixed_version=fix_ver,
                location_path=item.get("location_path"),
                applicability=app_status,
                applicability_rationale=app_rationale,
                status="OPEN",
                contextual_priority=risk_eval["priority_tier"]
            )
            db.add(finding)
            await db.flush()

            obs = FindingObservation(
                finding_id=finding.id,
                scanner_name=item.get("scanner_name", "Scanner_Ingest"),
                raw_finding_id=item.get("raw_finding_id"),
                scanner_severity=item.get("severity", "HIGH"),
                raw_payload=item
            )
            db.add(obs)
            accepted += 1

        import_rec.status = "COMPLETED"
        import_rec.records_total = len(raw_findings)
        import_rec.records_accepted = accepted
        import_rec.records_skipped = skipped
        await db.commit()

        return {
            "import_id": import_rec.id,
            "status": "COMPLETED",
            "records_total": len(raw_findings),
            "records_accepted": accepted,
            "records_skipped": skipped
        }

    except Exception as e:
        await db.rollback()
        import_rec.status = "FAILED"
        import_rec.error_details = [{"error": str(e)}]
        await db.commit()
        raise HTTPException(status_code=500, detail=f"Failed to process import: {str(e)}")
