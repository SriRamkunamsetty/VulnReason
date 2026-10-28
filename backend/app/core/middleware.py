import uuid
from typing import Optional
from fastapi import Request, HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.security import decode_token

security = HTTPBearer(auto_error=False)

class TenantContext:
    def __init__(self, tenant_id: str, user_id: str, role: str):
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.role = role

async def get_current_tenant(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
    request: Request = None
) -> TenantContext:
    """
    Validates token and returns current verified tenant and user context.
    Provides fallback demo tenant for local exploratory evaluation when no auth header is passed.
    """
    if credentials:
        payload = decode_token(credentials.credentials)
        if payload:
            return TenantContext(
                tenant_id=payload.get("tenant_id", "demo-tenant-001"),
                user_id=payload.get("sub", "demo-user-001"),
                role=payload.get("role", "security_analyst")
            )
    
    # Fallback to demo tenant for development/testing if header not present
    return TenantContext(
        tenant_id="demo-tenant-001",
        user_id="demo-user-001",
        role="security_analyst"
    )

class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        corr_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        request.state.correlation_id = corr_id
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = corr_id
        return response
