"""
test_pipeline.py
-----------------
Unit tests for the core src/ modules, using small synthetic fixtures
instead of the real CICIDS2017 dataset — CI shouldn't need a multi-hundred-
MB download to catch a broken function. These are the same kinds of checks
that were run manually against synthetic data while building each phase of
this project; formalizing them here means CI catches a regression
automatically the next time something in src/ changes.
"""

import numpy as np
import pandas as pd
import pytest

from src.preprocessing.clean import (
    clean_column_names,
    handle_infinite_and_missing,
    remove_duplicates,
    standardize_labels,
)
from src.models.anomaly import select_feature_columns, train_isolation_forest, predict_anomalies
from src.models.threat_score import normalize_anomaly_score, compute_threat_score, severity_label
from src.ingestion.upload_processor import align_features_to_model


@pytest.fixture
def raw_like_df():
    """A tiny frame shaped like a raw CICIDS2017 CSV, messy on purpose."""
    return pd.DataFrame({
        " Flow Duration": [100, 200, np.inf, 400, 100],
        " Total Fwd Packets": [1, 2, 3, 4, 1],
        " Label": ["BENIGN", "FTP-Patator", "DoS Hulk", "PortScan", "BENIGN"],
    })


def test_clean_column_names(raw_like_df):
    cleaned = clean_column_names(raw_like_df)
    assert "flow_duration" in cleaned.columns
    assert "total_fwd_packets" in cleaned.columns
    assert " Flow Duration" not in cleaned.columns


def test_handle_infinite_and_missing(raw_like_df):
    cleaned = clean_column_names(raw_like_df)
    result = handle_infinite_and_missing(cleaned)
    assert not np.isinf(result.select_dtypes(include=[np.number])).any().any()
    assert result.isna().sum().sum() == 0
    assert len(result) == 4  # one row dropped (the inf row)


def test_remove_duplicates(raw_like_df):
    cleaned = clean_column_names(raw_like_df)
    result = remove_duplicates(cleaned)
    assert len(result) == 4  # last row was a duplicate of the first


def test_standardize_labels(raw_like_df):
    cleaned = clean_column_names(raw_like_df)
    result = standardize_labels(cleaned, label_col="label")
    assert set(result["attack_category"]) == {"Normal", "Brute Force", "DDoS", "Port Scanning"}


def test_select_feature_columns_excludes_metadata():
    df = pd.DataFrame({
        "flow_duration": [1, 2],
        "label": ["BENIGN", "DDoS"],
        "attack_category": ["Normal", "DDoS"],
        "source_file": ["monday", "tuesday"],
    })
    cols = select_feature_columns(df)
    assert cols == ["flow_duration"]
    assert "label" not in cols and "attack_category" not in cols and "source_file" not in cols


def test_isolation_forest_trains_and_predicts():
    X = pd.DataFrame({
        "a": np.random.normal(0, 1, 200),
        "b": np.random.normal(0, 1, 200),
    })
    model = train_isolation_forest(X, contamination=0.1)
    result = predict_anomalies(model, X)
    assert set(result["is_anomaly"].unique()).issubset({0, 1})
    assert len(result) == len(X)


def test_normalize_anomaly_score_bounds():
    raw = pd.Series([-0.5, -0.2, 0.0, 0.3, 0.5])
    norm = normalize_anomaly_score(raw)
    assert norm.min() >= 0 and norm.max() <= 1


def test_compute_threat_score_bounds_and_severity():
    result = compute_threat_score(
        anomaly_score_normalized=pd.Series([0.9, 0.1]),
        predicted_attack_category=pd.Series(["Brute Force", "Normal"]),
        classifier_confidence=pd.Series([0.95, 0.6]),
    )
    assert result["threat_score"].between(0, 100).all()
    assert result["severity"].iloc[0] in {"Low", "Medium", "High", "Critical"}


def test_severity_label_thresholds():
    assert severity_label(95) == "Critical"
    assert severity_label(80) == "High"
    assert severity_label(60) == "Medium"
    assert severity_label(20) == "Low"


# ---------------------------------------------------------------------
# Tests for the company-upload feature (src/ingestion/upload_processor.py)
# ---------------------------------------------------------------------

def test_align_features_to_model_fills_missing_columns():
    """
    The core promise of the upload feature: an uploaded file missing a
    column the model expects must not crash — it gets filled with 0.0
    instead, so the model can still run.
    """
    upload_df = pd.DataFrame({"flow_duration": [100, 200], "total_fwd_packets": [5, 8]})
    expected = ["flow_duration", "total_fwd_packets", "flow_bytes_s"]  # model expects 3, upload has 2

    aligned = align_features_to_model(upload_df, expected)
    assert list(aligned.columns) == expected
    assert (aligned["flow_bytes_s"] == 0.0).all()
    assert list(aligned["flow_duration"]) == [100, 200]


def test_align_features_to_model_ignores_extra_columns():
    """Columns the upload has but the model doesn't expect are dropped, not errored on."""
    upload_df = pd.DataFrame({"flow_duration": [10], "some_company_specific_field": ["x"]})
    aligned = align_features_to_model(upload_df, ["flow_duration"])
    assert list(aligned.columns) == ["flow_duration"]


def test_align_features_to_model_coerces_non_numeric_to_zero():
    """A column with garbage/non-numeric values shouldn't crash the pipeline — it becomes 0.0."""
    upload_df = pd.DataFrame({"flow_duration": ["not_a_number", "200"]})
    aligned = align_features_to_model(upload_df, ["flow_duration"])
    assert list(aligned["flow_duration"]) == [0.0, 200.0]
