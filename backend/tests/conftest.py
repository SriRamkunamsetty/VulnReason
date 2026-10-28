import pytest
import asyncio
from app.db.session import async_engine, Base, AsyncSessionLocal
from app.models.auth import Organization, User, OrganizationMembership
from app.models.asset import Asset, AssetRelationship
from app.models.vulnerability import Vulnerability
from app.models.finding import Finding
from app.core.security import get_password_hash
from sqlalchemy import select

async def _init_and_seed():
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        org_res = await session.execute(select(Organization).where(Organization.id == "demo-tenant-001"))
        if not org_res.scalars().first():
            org = Organization(id="demo-tenant-001", name="Alignerr CyberSec Demo Org", slug="alignerr-demo")
            session.add(org)
            
            user = User(
                id="demo-user-001",
                email="analyst@vulnreason.io",
                full_name="Moksha Security Analyst",
                hashed_password=get_password_hash("AlignerrSec2026!"),
                is_superuser=True
            )
            session.add(user)
            await session.flush()

            mem = OrganizationMembership(
                organization_id=org.id,
                user_id=user.id,
                role="admin"
            )
            session.add(mem)

            gateway = Asset(
                id="asset-gw-01",
                tenant_id=org.id,
                hostname="dmz-api-gateway.corp.net",
                ip_addresses=["198.51.100.10", "10.0.1.5"],
                exposure="INTERNET_FACING",
                criticality="HIGH",
                environment="production"
            )
            app_svr = Asset(
                id="asset-app-02",
                tenant_id=org.id,
                hostname="internal-app-02.corp.net",
                ip_addresses=["10.0.2.14"],
                exposure="INTERNAL",
                criticality="MEDIUM",
                environment="production"
            )
            db_svr = Asset(
                id="asset-db-03",
                tenant_id=org.id,
                hostname="pci-customer-db.internal",
                ip_addresses=["10.0.3.99"],
                exposure="RESTRICTED_ISOLATED",
                criticality="MISSION_CRITICAL",
                environment="production"
            )
            session.add_all([gateway, app_svr, db_svr])
            await session.flush()

            rel1 = AssetRelationship(
                id="rel-gw-to-app",
                tenant_id=org.id,
                source_asset_id=gateway.id,
                target_asset_id=app_svr.id,
                relationship_type="CAN_ACCESS",
                protocol="TCP",
                port=8080,
                state="VERIFIED"
            )
            rel2 = AssetRelationship(
                id="rel-app-to-db",
                tenant_id=org.id,
                source_asset_id=app_svr.id,
                target_asset_id=db_svr.id,
                relationship_type="AUTHENTICATES_TO",
                protocol="TCP",
                port=5432,
                state="VERIFIED"
            )
            session.add_all([rel1, rel2])

            v1 = Vulnerability(
                id="vuln-cve-2024-21413",
                cve_id="CVE-2024-21413",
                cvss_v3_base_score=9.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                epss_score=0.9423,
                epss_percentile=0.9850,
                cisa_kev_listed=True
            )
            session.add(v1)
            await session.flush()

            f1 = Finding(
                id="finding-001",
                tenant_id=org.id,
                asset_id=gateway.id,
                vulnerability_id=v1.id,
                cve_id="CVE-2024-21413",
                package_name="ms-office-client",
                installed_version="16.0.14326.20454",
                fixed_version="16.0.14326.21000",
                applicability="CONFIRMED_APPLICABLE",
                status="OPEN",
                contextual_priority="P0_URGENT"
            )
            f2 = Finding(
                id="finding-002",
                tenant_id=org.id,
                asset_id=app_svr.id,
                vulnerability_id=v1.id,
                cve_id="CVE-2021-44228",
                package_name="log4j-core",
                installed_version="2.14.1",
                fixed_version="2.15.0",
                applicability="CONFIRMED_APPLICABLE",
                status="OPEN",
                contextual_priority="P0_URGENT"
            )
            session.add_all([f1, f2])
            await session.commit()

@pytest.fixture(scope="session", autouse=True)
def setup_database_session():
    asyncio.run(_init_and_seed())
