"""
POST /detect, GET /threats, GET /threats/{id} — the core detection +
retrieval endpoints (blueprint Section 9).

POST /detect runs the full pipeline built across Notebooks 02, 03 and 05 on
one event: anomaly score -> attack classification -> combined threat score
-> persisted Alert row. This is the live-inference equivalent of what those
three notebooks demonstrated offline on historical data.
"""

import numpy as np
import pandas as pd
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from src.database.models import Alert, Anomaly, Attack, SecurityEvent, User
from src.database.session import get_db
from src.models.anomaly import predict_anomalies
from src.models.registry import ModelNotTrainedError, get_anomaly_model, get_classifier_model
from src.models.threat_score import compute_threat_score, normalize_anomaly_score
from api.schemas.schemas import AlertOut, DetectionResult

router = APIRouter(tags=["threats"])


@router.post("/detect", response_model=DetectionResult)
def detect(event_id: int, db: Session = Depends(get_db)):
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if event is None:
        raise HTTPException(404, f"Event {event_id} not found")
    if not event.raw_features:
        raise HTTPException(400, "Event has no feature data to run inference on")

    try:
        anomaly_model = get_anomaly_model()
        classifier_model, label_encoder = get_classifier_model()
    except ModelNotTrainedError as e:
        raise HTTPException(503, str(e))

    X = pd.DataFrame([event.raw_features])

    anomaly_out = predict_anomalies(anomaly_model, X)
    anomaly_score_norm = normalize_anomaly_score(anomaly_out["anomaly_score"]).iloc[0]
    is_anomaly = bool(anomaly_out["is_anomaly"].iloc[0])

    proba = classifier_model.predict_proba(X)[0]
    pred_idx = int(np.argmax(proba))
    confidence = float(proba[pred_idx])
    attack_category = (
        label_encoder.inverse_transform([pred_idx])[0] if label_encoder is not None
        else classifier_model.classes_[pred_idx]
    )

    scores = compute_threat_score(
        anomaly_score_normalized=pd.Series([anomaly_score_norm]),
        predicted_attack_category=pd.Series([attack_category]),
        classifier_confidence=pd.Series([confidence]),
    )
    threat_score = float(scores["threat_score"].iloc[0])
    severity = scores["severity"].iloc[0]

    db.add(Anomaly(event_id=event.id, anomaly_score=float(anomaly_score_norm), is_anomaly=is_anomaly))
    db.add(Attack(event_id=event.id, attack_category=str(attack_category), confidence=confidence))

    user = None
    if event.user_external_id:
        user = db.query(User).filter(User.external_id == event.user_external_id).first()
    db.add(Alert(
        event_id=event.id, user_id=user.id if user else None, source_ip=event.source_ip,
        attack_category=str(attack_category), threat_score=threat_score, severity=severity,
    ))
    db.commit()

    return DetectionResult(
        event_id=event.id, is_anomaly=is_anomaly, anomaly_score=round(float(anomaly_score_norm), 3),
        attack_category=str(attack_category), classifier_confidence=round(confidence, 3),
        threat_score=threat_score, severity=severity,
    )


@router.get("/threats", response_model=list[AlertOut])
def list_threats(limit: int = 50, severity: str | None = None, db: Session = Depends(get_db)):
    query = db.query(Alert).order_by(Alert.created_at.desc())
    if severity:
        query = query.filter(Alert.severity == severity)
    return query.limit(limit).all()


@router.get("/threats/{alert_id}", response_model=AlertOut)
def get_threat(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(404, f"Alert {alert_id} not found")
    return alert
