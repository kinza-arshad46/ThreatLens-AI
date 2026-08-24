"""
models.py
---------
SQLAlchemy ORM models for the ThreatLens AI database schema
(blueprint Section 9: "Core database entities").

Every table listed in the blueprint is defined here: users, devices,
ip_addresses, security_events, attacks, anomalies, uba_profiles,
threat_predictions, alerts, model_predictions. Column choices follow
directly from what the earlier notebooks actually produce -- e.g.
`Alert.threat_score` and `Alert.severity` are exactly the two values
`src/models/threat_score.py` (Notebook 05) computes, so persisting a
notebook's output into this table is a straight 1:1 mapping, not a
re-interpretation.
"""

from datetime import datetime

from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Boolean, ForeignKey, Text, JSON,
)
from sqlalchemy.orm import relationship

from src.database.session import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    external_id = Column(String(64), unique=True, index=True, nullable=False)  # e.g. "U-1042" or a source IP
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    uba_profiles = relationship("UBAProfile", back_populates="user")
    alerts = relationship("Alert", back_populates="user")


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    signature = Column(String(128), unique=True, index=True, nullable=False)  # OS + browser fingerprint
    os = Column(String(64))
    browser = Column(String(64))
    first_seen = Column(DateTime, default=datetime.utcnow)


class IPAddress(Base):
    __tablename__ = "ip_addresses"

    id = Column(Integer, primary_key=True)
    address = Column(String(45), unique=True, index=True, nullable=False)  # IPv4/IPv6
    country = Column(String(64), nullable=True)
    risk_score = Column(Float, default=0.0)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String(64))          # e.g. "Failed Login", "API Request"
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45), nullable=True)
    user_external_id = Column(String(64), nullable=True, index=True)
    raw_features = Column(JSON, nullable=True)  # the full feature row, for re-scoring/audit later

    attacks = relationship("Attack", back_populates="event")
    anomalies = relationship("Anomaly", back_populates="event")


class Attack(Base):
    """Output of the multi-class classifier (Notebook 03)."""
    __tablename__ = "attacks"

    id = Column(Integer, primary_key=True)
    event_id = Column(Integer, ForeignKey("security_events.id"))
    attack_category = Column(String(64), index=True)   # e.g. "Brute Force"
    confidence = Column(Float)
    model_version = Column(String(64), default="v1")
    created_at = Column(DateTime, default=datetime.utcnow)

    event = relationship("SecurityEvent", back_populates="attacks")


class Anomaly(Base):
    """Output of the Isolation Forest anomaly detector (Notebook 02)."""
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True)
    event_id = Column(Integer, ForeignKey("security_events.id"))
    anomaly_score = Column(Float)     # normalized 0-1, higher = more anomalous
    is_anomaly = Column(Boolean)
    model_version = Column(String(64), default="v1")
    created_at = Column(DateTime, default=datetime.utcnow)

    event = relationship("SecurityEvent", back_populates="anomalies")


class UBAProfile(Base):
    """Output of the UBA engine (Notebook 06) — one row per user/entity baseline."""
    __tablename__ = "uba_profiles"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    typical_hour = Column(Float, nullable=True)
    hour_std = Column(Float, nullable=True)
    avg_daily_events = Column(Float, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="uba_profiles")


class ThreatPrediction(Base):
    """Output of the forecasting engine (Notebook 08) — one row per forecast run."""
    __tablename__ = "threat_predictions"

    id = Column(Integer, primary_key=True)
    generated_at = Column(DateTime, default=datetime.utcnow)
    horizon_hours = Column(Integer)          # 1, 6, or 24
    predicted_attack_ratio = Column(Float)
    model_version = Column(String(64), default="v1")


class Alert(Base):
    """
    The unified alert record — combines classifier + anomaly + threat score
    (Notebook 05) into the single row the dashboard's alert cards read from.
    """
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    event_id = Column(Integer, ForeignKey("security_events.id"), nullable=True)
    source_dataset_id = Column(Integer, ForeignKey("data_sources.id"), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    source_ip = Column(String(45), index=True, nullable=True)  # nullable: upload-sourced alerts may not carry a raw IP after feature alignment
    attack_category = Column(String(64))
    threat_score = Column(Float)             # 0-100, from src/models/threat_score.py
    severity = Column(String(16), index=True)  # Low / Medium / High / Critical
    status = Column(String(32), default="Open")  # Open / Investigating / Blocked / Closed
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    user = relationship("User", back_populates="alerts")


class DataSource(Base):
    """
    One row per uploaded company dataset (the "bring your own data" feature).
    Deliberately does NOT store every individual row from the upload —
    for a large company export that would bloat the database on every
    upload. Instead it stores the AGGREGATE analysis (breakdown, average
    threat score, counts), with the highest-risk rows separately linked
    via Alert.source_dataset_id for actual investigation.
    """
    __tablename__ = "data_sources"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), index=True)           # e.g. company name or upload label
    original_filename = Column(String(256), nullable=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow, index=True)
    total_rows = Column(Integer, default=0)
    rows_analyzed = Column(Integer, default=0)
    rows_dropped_invalid = Column(Integer, default=0)
    avg_threat_score = Column(Float, default=0.0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    attack_breakdown = Column(JSON, default=dict)     # {"Brute Force": 12, "DDoS": 4, ...}


class ModelPrediction(Base):
    """
    Generic log of every model inference call, kept for governance
    (blueprint Section 14: "Log inference results for debugging and
    analysis"). Independent of the more specific Attack/Anomaly tables above
    so ANY model (including future ones) can log here without a schema change.
    """
    __tablename__ = "model_predictions"

    id = Column(Integer, primary_key=True)
    model_name = Column(String(64))          # e.g. "isolation_forest", "attack_classifier"
    model_version = Column(String(64))
    input_event_id = Column(Integer, ForeignKey("security_events.id"), nullable=True)
    output = Column(JSON)                    # raw prediction payload
    created_at = Column(DateTime, default=datetime.utcnow)


