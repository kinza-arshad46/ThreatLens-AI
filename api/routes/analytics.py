"""GET /analytics/overview — the numbers behind the dashboard's KPI row."""

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from src.database.models import Alert, SecurityEvent
from src.database.session import get_db
from src.cache.redis_client import cache
from api.schemas.schemas import AnalyticsOverview

router = APIRouter(tags=["analytics"])

CACHE_KEY = "analytics:overview"
CACHE_TTL_SECONDS = 15  # short TTL: dashboard KPIs should feel near-live, not stale


@router.get("/analytics/overview", response_model=AnalyticsOverview)
def get_overview(db: Session = Depends(get_db)):
    """
    Powers the dashboard's Total Events / Active Threats / Critical Alerts /
    System Health KPI cards. Cached briefly in Redis (see
    src/cache/redis_client.py) since this endpoint is expected to be polled
    frequently by the live dashboard — recomputing four aggregate queries on
    every poll would be wasted database load for numbers that only need to
    be a few seconds fresh, not millisecond-fresh.
    """
    cached = cache.get_json(CACHE_KEY)
    if cached is not None:
        return AnalyticsOverview(**cached)

    total_events = db.query(func.count(SecurityEvent.id)).scalar() or 0
    active_threats = db.query(func.count(Alert.id)).filter(Alert.status == "Open").scalar() or 0
    critical_alerts = db.query(func.count(Alert.id)).filter(Alert.severity == "Critical").scalar() or 0

    result = AnalyticsOverview(
        total_events=total_events,
        active_threats=active_threats,
        critical_alerts=critical_alerts,
        system_health_pct=99.8,  # placeholder until Notebook-based service-health checks are wired in
    )
    cache.set_json(CACHE_KEY, result.model_dump(), ttl_seconds=CACHE_TTL_SECONDS)
    return result
