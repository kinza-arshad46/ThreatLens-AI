"""
POST /events — ingest one raw security event (blueprint Section 9).

This is the entry point of the "Ingestion" stage in a live API context —
the same conceptual step Notebook 01's `load_all_csvs()` performs in bulk
for historical CSVs, but here for one real-time event at a time.
"""

from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.database.models import SecurityEvent
from src.database.session import get_db
from api.schemas.schemas import SecurityEventIn

router = APIRouter(tags=["events"])


@router.post("/events", status_code=201)
def create_event(payload: SecurityEventIn, db: Session = Depends(get_db)):
    event = SecurityEvent(
        timestamp=payload.timestamp or datetime.utcnow(),
        event_type=payload.event_type,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        user_external_id=payload.user_external_id,
        raw_features=payload.features,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return {"event_id": event.id, "status": "ingested"}
