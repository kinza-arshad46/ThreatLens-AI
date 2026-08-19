"""
schemas.py
----------
Pydantic request/response models for the FastAPI layer. Kept separate from
the SQLAlchemy ORM models in src/database/models.py on purpose: API
contracts (what a client sees) and database structure (how data is stored)
are allowed to evolve independently -- e.g. we may want to rename or hide
a DB column without breaking the public API response shape.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    database: str
    cache: str
    timestamp: datetime


class SecurityEventIn(BaseModel):
    """Payload for POST /events — one raw event to ingest."""
    event_type: str
    source_ip: str
    destination_ip: Optional[str] = None
    user_external_id: Optional[str] = None
    features: dict[str, float] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class DetectionResult(BaseModel):
    """Response for POST /detect — combined output of every AI engine."""
    event_id: int
    is_anomaly: bool
    anomaly_score: float
    attack_category: str
    classifier_confidence: float
    threat_score: float
    severity: str


class AlertOut(BaseModel):
    id: int
    source_ip: str
    attack_category: str
    threat_score: float
    severity: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class UserRiskOut(BaseModel):
    external_id: str
    avg_threat_score: float
    alert_count: int
    last_seen: Optional[datetime] = None


class ForecastPoint(BaseModel):
    horizon_hours: int
    predicted_attack_ratio: float


class ForecastResponse(BaseModel):
    generated_at: Optional[datetime] = None
    points: list[ForecastPoint]


class GraphNode(BaseModel):
    id: str
    node_type: str
    out_degree: int = 0


class GraphEdge(BaseModel):
    source: str
    target: str
    weight: int
    attack_types: list[str]


class GraphResponse(BaseModel):
    entity: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class AnalystQueryIn(BaseModel):
    question: str


class AnalystQueryOut(BaseModel):
    question: str
    intent: str
    answer: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class AnalyticsOverview(BaseModel):
    total_events: int
    active_threats: int
    critical_alerts: int
    system_health_pct: float
