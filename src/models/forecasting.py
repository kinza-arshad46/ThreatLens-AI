"""
forecasting.py
--------------
Time-series Threat Forecasting engine (ThreatLens AI blueprint, Section 5):
aggregates security events into time windows and predicts near-future
attack volume / threat probability for the 1h / 6h / 24h horizons shown on
the dashboard's Threat Forecast page.

Model choice: gradient-boosted trees (via scikit-learn's
HistGradientBoostingRegressor) on lag + rolling-window + calendar features,
exactly the "strong practical baseline" the blueprint recommends before
reaching for something heavier like an LSTM. This keeps the forecasting
engine consistent with the rest of the project (tree-based models
throughout) and easy to explain to a non-ML reader.

Same honesty note as uba.py / graph.py: this needs a `timestamp` column.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingRegressor
from sklearn.metrics import mean_absolute_error, mean_squared_error

TIMESTAMP_CANDIDATES = ["timestamp", "flow_start_time", "time"]


def _find_column(df: pd.DataFrame, candidates: list[str]) -> str | None:
    for c in candidates:
        if c in df.columns:
            return c
    return None


def require_timestamp_column(df: pd.DataFrame) -> str:
    ts_col = _find_column(df, TIMESTAMP_CANDIDATES)
    if ts_col is None:
        raise ValueError(
            "Forecasting requires a timestamp column, which this dataset doesn't "
            "have. Some 'cleaned' CICIDS2017 CSVs strip it out. Re-download a "
            "version that keeps the Timestamp column (e.g. 'dhoogla/cicids2017' "
            "on Kaggle) if you need real time-series forecasting. "
            "Columns found: " + str(list(df.columns))
        )
    return ts_col


def build_time_series(
    df: pd.DataFrame,
    ts_col: str,
    attack_col: str = "attack_category",
    freq: str = "1h",
) -> pd.DataFrame:
    """
    Collapses row-level events into a regular time series: one row per time
    bucket (`freq`, default hourly), with the total event count and the
    attack event count in that bucket. This is the "aggregates security
    activity into time windows" step the blueprint describes as the basis
    for forecasting.
    """
    ts = pd.to_datetime(df[ts_col], errors="coerce")
    work = pd.DataFrame({
        "ts": ts,
        "is_attack": (df[attack_col] != "Normal").astype(int),
    }).dropna(subset=["ts"])

    series = work.set_index("ts").resample(freq).agg(
        total_events=("is_attack", "count"),
        attack_events=("is_attack", "sum"),
    )
    series["attack_ratio"] = (series["attack_events"] / series["total_events"].replace(0, 1)).fillna(0)
    return series


def make_supervised_features(series: pd.DataFrame, target_col: str = "attack_ratio", n_lags: int = 6) -> pd.DataFrame:
    """
    Turns the time series into a supervised learning table: lag features
    (value N steps ago), a rolling mean/std (recent trend), and calendar
    features (hour of day, day of week) — the exact feature family the
    blueprint recommends for the XGBoost/LightGBM forecasting baseline.
    Rows with any NaN lag (the first `n_lags` rows) are dropped since they
    have no history to learn from.
    """
    feat = series.copy()
    for lag in range(1, n_lags + 1):
        feat[f"lag_{lag}"] = feat[target_col].shift(lag)

    feat["rolling_mean_3"] = feat[target_col].shift(1).rolling(3).mean()
    feat["rolling_std_3"] = feat[target_col].shift(1).rolling(3).std()
    feat["hour"] = feat.index.hour
    feat["day_of_week"] = feat.index.dayofweek

    feat = feat.dropna()
    return feat


def train_forecaster(X_train: pd.DataFrame, y_train: pd.Series) -> HistGradientBoostingRegressor:
    """
    Trains a gradient-boosted regressor to predict `attack_ratio` for the
    next time step given lag/rolling/calendar features. HistGradientBoosting
    is used (rather than plain GradientBoosting) since it's noticeably
    faster on larger feature tables and handles this size of data well
    without extra tuning.
    """
    model = HistGradientBoostingRegressor(max_iter=300, random_state=42)
    model.fit(X_train, y_train)
    return model


def evaluate_forecaster(y_true: pd.Series, y_pred: np.ndarray) -> dict:
    """
    MAE and RMSE, per the blueprint's own stated evaluation metrics for the
    forecasting engine (Section 5 / Section 14). MAPE is intentionally
    skipped when y_true contains zeros (a quiet hour with literally 0 attack
    ratio), since MAPE divides by the true value and would blow up to
    infinity/undefined on those rows.
    """
    mae = mean_absolute_error(y_true, y_pred)
    rmse = np.sqrt(mean_squared_error(y_true, y_pred))
    return {"mae": mae, "rmse": rmse}


def forecast_horizon(model, last_known_row: pd.Series, steps: int, target_col: str = "attack_ratio", n_lags: int = 6) -> list[float]:
    """
    Recursively forecasts `steps` time-buckets into the future: predicts the
    next value, appends it as the newest lag, shifts the lag window forward,
    and repeats. This is what actually produces the "1 hour / 6 hour / 24
    hour" style horizon values shown on the dashboard's forecast bars,
    starting from one real, most-recent row of features.
    """
    row = last_known_row.copy()
    predictions = []
    lag_cols = [f"lag_{i}" for i in range(1, n_lags + 1)]

    for _ in range(steps):
        X_next = row[lag_cols + ["rolling_mean_3", "rolling_std_3", "hour", "day_of_week"]].to_frame().T
        pred = float(model.predict(X_next)[0])
        pred = max(0.0, min(1.0, pred))  # attack_ratio is bounded [0,1]
        predictions.append(pred)

        # shift lag window: newest lag becomes this prediction, everything else shifts back
        for i in range(n_lags, 1, -1):
            row[f"lag_{i}"] = row[f"lag_{i-1}"]
        row["lag_1"] = pred
        row["hour"] = (row["hour"] + 1) % 24

    return predictions
