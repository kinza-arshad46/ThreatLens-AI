"""GET /health — reports API, database, and cache status (blueprint Section 9)."""

from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.cache.redis_client import cache
from src.database.session import get_db
from api.schemas.schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {e}"

    try:
        cache._client.ping()
        cache_status = "connected"
    except Exception as e:
        cache_status = f"error: {e}"

    return HealthResponse(
        status="ok" if db_status == "connected" else "degraded",
        database=db_status,
        cache=cache_status,
        timestamp=datetime.utcnow(),
    )
