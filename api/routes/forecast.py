"""GET /forecast — returns the latest saved 1h/6h/24h forecast (Notebook 08 output)."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.database.models import ThreatPrediction
from src.database.session import get_db
from api.schemas.schemas import ForecastPoint, ForecastResponse

router = APIRouter(tags=["forecast"])


@router.get("/forecast", response_model=ForecastResponse)
def get_forecast(db: Session = Depends(get_db)):
    latest_run_time = db.query(ThreatPrediction.generated_at).order_by(ThreatPrediction.generated_at.desc()).first()

    if latest_run_time is None:
        return ForecastResponse(generated_at=None, points=[])

    rows = (
        db.query(ThreatPrediction)
        .filter(ThreatPrediction.generated_at == latest_run_time[0])
        .order_by(ThreatPrediction.horizon_hours)
        .all()
    )
    return ForecastResponse(
        generated_at=latest_run_time[0],
        points=[ForecastPoint(horizon_hours=r.horizon_hours, predicted_attack_ratio=r.predicted_attack_ratio) for r in rows],
    )
