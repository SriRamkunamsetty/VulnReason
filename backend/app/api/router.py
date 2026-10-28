from fastapi import APIRouter
from app.api.v1.auth import router as auth_router
from app.api.v1.assets import router as assets_router
from app.api.v1.findings import router as findings_router
from app.api.v1.graph import router as graph_router
from app.api.v1.reasoning import router as reasoning_router
from app.api.v1.evaluation import router as evaluation_router
from app.api.v1.remediation import router as remediation_router
from app.api.v1.imports import router as imports_router
from app.api.v1.health import router as health_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(assets_router)
api_router.include_router(findings_router)
api_router.include_router(graph_router)
api_router.include_router(reasoning_router)
api_router.include_router(evaluation_router)
api_router.include_router(remediation_router)
api_router.include_router(imports_router)
