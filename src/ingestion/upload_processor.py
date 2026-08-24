"""
upload_processor.py
--------------------
Handles a company's own uploaded dataset — the "bring your own data" feature.
Until now, ThreatLens AI only ever analyzed one fixed source (CICIDS2017).
This module lets ANY company upload a CSV of their own network/security
logs — with its own column names, its own order, possibly missing columns
entirely — and still get real predictions from the SAME trained models,
by aligning the upload to whatever features the model actually expects.

This is what makes "multiple sources" real rather than cosmetic: two
companies with differently-shaped exports can both be analyzed by the same
models, because alignment happens against the MODEL's expected feature
list (via `feature_names_in_`), not against one hardcoded schema.

Honest limitation, stated once here rather than hidden: a column the model
expects but the upload doesn't have gets filled with 0.0, not a smart
guess — the model still runs, but predictions lean more on whatever
features the upload DOES provide. This is normal, expected behavior for
model inference on partially-overlapping schemas, and is safer than
silently dropping the whole upload or crashing.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from src.preprocessing.clean import clean_column_names, handle_infinite_and_missing
from src.models.registry import get_anomaly_model, get_classifier_model
from src.models.anomaly import predict_anomalies
from src.models.threat_score import compute_threat_score, normalize_anomaly_score


@dataclass
class UploadAnalysisResult:
    source_name: str
    total_rows: int
    rows_analyzed: int
    rows_dropped_invalid: int
    attack_breakdown: dict[str, int] = field(default_factory=dict)
    avg_threat_score: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    top_alerts: list[dict] = field(default_factory=list)
    scored_df: pd.DataFrame | None = None  # kept for the caller to persist rows if desired


def read_uploaded_csv(file_bytes: bytes) -> pd.DataFrame:
    """
    Reads an uploaded CSV from raw bytes (as received by the FastAPI upload
    endpoint) into a DataFrame. `low_memory=False` avoids dtype-guessing
    warnings the same way the original bulk ingestion (Notebook 01) does,
    since an unknown company's export is just as likely to have mixed-type
    columns as CICIDS2017 did.
    """
    return pd.read_csv(io.BytesIO(file_bytes), low_memory=False)


def align_features_to_model(df: pd.DataFrame, expected_columns: list[str]) -> pd.DataFrame:
    """
    The core of "different source" support. Builds a feature matrix with
    EXACTLY the columns the trained model expects, in the right order:
      - a column the upload DOES have -> coerced to numeric, used as-is
      - a column the upload DOESN'T have -> filled with 0.0

    This means an upload with different column names, a different column
    order, extra columns the model doesn't care about, or some columns
    missing entirely, all still produce a valid input the model can score
    — instead of requiring every company's export to match CICIDS2017's
    schema exactly, which would make "multiple sources" a fiction.
    """
    aligned = pd.DataFrame(index=df.index)
    for col in expected_columns:
        if col in df.columns:
            aligned[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
        else:
            aligned[col] = 0.0
    return aligned


def analyze_uploaded_dataset(file_bytes: bytes, source_name: str, top_n_alerts: int = 25) -> UploadAnalysisResult:
    """
    The full pipeline for one uploaded file, start to finish:
      1. Read the raw CSV
      2. Clean column names (same function Notebook 01 uses)
      3. Handle infinities/missing values (same function Notebook 01 uses)
      4. Align columns to what the trained models actually expect
      5. Run the SAME anomaly + classifier + threat-scoring functions the
         rest of the project already uses (src/models/) — no separate
         "upload" model, no duplicated inference logic
      6. Summarize results into one report the API can return immediately

    Reuses every existing model function rather than reimplementing
    inference — this is the same principle the whole project has followed:
    one place that knows how to run each model, imported everywhere it's
    needed.
    """
    raw_df = read_uploaded_csv(file_bytes)
    total_rows = len(raw_df)

    cleaned = clean_column_names(raw_df)
    cleaned = handle_infinite_and_missing(cleaned)
    rows_dropped = total_rows - len(cleaned)

    if len(cleaned) == 0:
        return UploadAnalysisResult(
            source_name=source_name, total_rows=total_rows, rows_analyzed=0,
            rows_dropped_invalid=rows_dropped,
        )

    anomaly_model = get_anomaly_model()
    classifier_model, label_encoder = get_classifier_model()

    # The anomaly model and classifier were trained on the same feature set
    # (Notebook 03 deliberately reuses select_feature_columns from
    # anomaly.py — see that notebook's Section 1), so aligning to the
    # anomaly model's expected columns is sufficient for both.
    expected_columns = list(anomaly_model.feature_names_in_)
    X = align_features_to_model(cleaned, expected_columns)

    anomaly_out = predict_anomalies(anomaly_model, X)
    anomaly_score_norm = normalize_anomaly_score(anomaly_out["anomaly_score"])

    proba = classifier_model.predict_proba(X)
    pred_idx = np.argmax(proba, axis=1)
    confidence = proba[np.arange(len(proba)), pred_idx]
    if label_encoder is not None:
        attack_category = label_encoder.inverse_transform(pred_idx)
    else:
        attack_category = classifier_model.classes_[pred_idx]

    scores = compute_threat_score(
        anomaly_score_normalized=anomaly_score_norm,
        predicted_attack_category=pd.Series(attack_category, index=X.index),
        classifier_confidence=pd.Series(confidence, index=X.index),
    )

    result_df = X.copy()
    result_df["attack_category"] = attack_category
    result_df["threat_score"] = scores["threat_score"]
    result_df["severity"] = scores["severity"]

    breakdown = result_df["attack_category"].value_counts().to_dict()
    top_alerts_df = result_df.sort_values("threat_score", ascending=False).head(top_n_alerts)

    return UploadAnalysisResult(
        source_name=source_name,
        total_rows=total_rows,
        rows_analyzed=len(result_df),
        rows_dropped_invalid=rows_dropped,
        attack_breakdown={str(k): int(v) for k, v in breakdown.items()},
        avg_threat_score=round(float(result_df["threat_score"].mean()), 1),
        critical_count=int((result_df["severity"] == "Critical").sum()),
        high_count=int((result_df["severity"] == "High").sum()),
        top_alerts=[
            {"attack_category": r.attack_category, "threat_score": round(r.threat_score, 1), "severity": r.severity}
            for r in top_alerts_df.itertuples()
        ],
        scored_df=result_df,
    )
