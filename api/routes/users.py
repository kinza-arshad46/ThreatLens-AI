"""GET /users/{id}/risk, GET /users/{id}/profile — UBA-backed user endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from src.database.models import Alert, User, UBAProfile
from src.database.session import get_db
from api.schemas.schemas import UserRiskOut

router = APIRouter(tags=["users"])


@router.get("/users/{external_id}/risk", response_model=UserRiskOut)
def get_user_risk(external_id: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.external_id == external_id).first()
    if user is None:
        raise HTTPException(404, f"User '{external_id}' not found")

    stats = (
        db.query(func.avg(Alert.threat_score), func.count(Alert.id))
        .filter(Alert.user_id == user.id).first()
    )
    avg_score, count = stats if stats else (0.0, 0)

    return UserRiskOut(
        external_id=external_id,
        avg_threat_score=round(avg_score or 0.0, 1),
        alert_count=count or 0,
        last_seen=user.last_seen,
    )


@router.get("/users/{external_id}/profile")
def get_user_profile(external_id: str, db: Session = Depends(get_db)):
    """
    Returns the UBA baseline (Notebook 06 output) for this entity — the same
    data behind the dashboard's 'Normal Hours / Typical OS / Typical IP'
    profile card.
    """
    user = db.query(User).filter(User.external_id == external_id).first()
    if user is None:
        raise HTTPException(404, f"User '{external_id}' not found")

    profile = db.query(UBAProfile).filter(UBAProfile.user_id == user.id).order_by(UBAProfile.updated_at.desc()).first()
    if profile is None:
        raise HTTPException(404, f"No UBA profile computed yet for '{external_id}'. Run notebooks/06_user_behavior_analytics.ipynb and persist its output.")

    return {
        "external_id": external_id,
        "typical_hour": profile.typical_hour,
        "hour_std": profile.hour_std,
        "avg_daily_events": profile.avg_daily_events,
        "updated_at": profile.updated_at,
    }
