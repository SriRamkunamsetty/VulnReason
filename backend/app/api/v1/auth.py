from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.models.auth import User, Organization, OrganizationMembership
from app.schemas.auth import LoginRequest, TokenResponse, UserCreate, UserResponse
from app.core.security import verify_password, get_password_hash, create_access_token, create_refresh_token
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == req.email))
    user = result.scalars().first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )

    # Get membership
    mem_result = await db.execute(
        select(OrganizationMembership).where(OrganizationMembership.user_id == user.id)
    )
    membership = mem_result.scalars().first()
    tenant_id = membership.organization_id if membership else "demo-tenant-001"
    role = membership.role if membership else "security_analyst"

    access_token = create_access_token(user.id, tenant_id, role)
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=user.id,
        tenant_id=tenant_id,
        role=role
    )

@router.post("/register", response_model=UserResponse)
async def register(req: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == req.email))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="User with this email already exists")

    user = User(
        email=req.email,
        full_name=req.full_name,
        hashed_password=get_password_hash(req.password)
    )
    db.add(user)
    await db.flush()

    # Create default organization if not exists
    org_res = await db.execute(select(Organization).where(Organization.slug == "default-org"))
    org = org_res.scalars().first()
    if not org:
        org = Organization(name="Default Organization", slug="default-org")
        db.add(org)
        await db.flush()

    membership = OrganizationMembership(
        organization_id=org.id,
        user_id=user.id,
        role=req.role
    )
    db.add(membership)
    await db.commit()
    await db.refresh(user)
    return user
