from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.db.session import get_db

router = APIRouter(prefix="/health", tags=["Health & Observability"])

@router.get("/liveness")
async def liveness():
    return {"status": "ok", "service": "vulnreason-api"}

@router.get("/readiness")
async def readiness(db: AsyncSession = Depends(get_db)):
    db_ok = False
    try:
        res = await db.execute(text("SELECT 1"))
        if res.scalar() == 1:
            db_ok = True
    except Exception:
        db_ok = False

    return {
        "status": "ready" if db_ok else "degraded",
        "database_connected": db_ok,
        "workers_ready": True
    }
