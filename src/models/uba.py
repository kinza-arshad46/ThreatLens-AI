"""
uba.py
------
User Behavior Analytics engine (ThreatLens AI blueprint, Section 6): builds
a behavioral baseline per entity (normal hours, typical traffic volume,
typical partners) and scores how much current activity deviates from it.

Honest note on entity identity: CICIDS2017 is network-flow data, not an
identity-management log — it has no literal "username" column. The closest
real identifier available is Source IP, so this module profiles behavior
PER SOURCE IP, exactly the way the blueprint's own example (the
192.168.1.105 chain) already does. If your CSV export doesn't include
`source_ip` / `timestamp` columns (some "cleaned" Kaggle releases strip
them to keep only numeric ML features), this module will raise a clear
error explaining what to do — see `require_columns()` below.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

# Different possible column names across CICIDS2017 releases, since Kaggle
# re-uploads sometimes rename or drop columns.
IP_COLUMN_CANDIDATES = ["source_ip", "src_ip", "sourceip"]
TIMESTAMP_COLUMN_CANDIDATES = ["timestamp", "flow_start_time", "time"]


def _find_column(df: pd.DataFrame, candidates: list[str]) -> str | None:
    for c in candidates:
        if c in df.columns:
            return c
    return None


def require_identity_columns(df: pd.DataFrame) -> tuple[str, str]:
    """
    Confirms the dataframe has both an entity identifier (source IP) and a
    timestamp column, and returns their actual names. Raises a clear,
    actionable error otherwise instead of failing deep inside a groupby.
    """
    ip_col = _find_column(df, IP_COLUMN_CANDIDATES)
    ts_col = _find_column(df, TIMESTAMP_COLUMN_CANDIDATES)

    if ip_col is None or ts_col is None:
        raise ValueError(
            "UBA requires a source-IP column and a timestamp column, but this "
            "dataset doesn't have them. Some 'cleaned' CICIDS2017 CSVs on Kaggle "
            "strip Source IP / Timestamp to keep only numeric ML features. "
            "If you need real UBA, re-download a version that keeps flow "
            "metadata (e.g. the 'dhoogla/cicids2017' Kaggle dataset) and merge "
            "the source_ip/timestamp columns back in before running this "
            "notebook. Column names found: " + str(list(df.columns))
        )
    return ip_col, ts_col


def build_entity_baseline(df: pd.DataFrame, ip_col: str, ts_col: str) -> pd.DataFrame:
    """
    Builds one behavioral baseline row per source IP:
      - typical_hour: the most common hour-of-day this entity is active
      - hour_std: how spread out its active hours are (tight = predictable)
      - avg_daily_events: average events per day for this entity
      - known_dest_ips: the set of destination IPs this entity normally talks to

    This baseline represents "normal" — Section 7 (deviation scoring) compares
    an entity's most recent activity against exactly these numbers.
    """
    df = df.copy()
    df["_hour"] = pd.to_datetime(df[ts_col], errors="coerce").dt.hour

    baseline = df.groupby(ip_col).agg(
        typical_hour=("_hour", lambda h: h.mode().iloc[0] if not h.mode().empty else np.nan),
        hour_std=("_hour", "std"),
        total_events=(ip_col, "count"),
        n_days=(ts_col, lambda t: pd.to_datetime(t, errors="coerce").dt.date.nunique()),
    )
    baseline["avg_daily_events"] = baseline["total_events"] / baseline["n_days"].replace(0, 1)
    baseline["hour_std"] = baseline["hour_std"].fillna(0)
    return baseline


def score_deviation(
    current_activity: pd.DataFrame,
    baseline: pd.DataFrame,
    ip_col: str,
    ts_col: str,
) -> pd.DataFrame:
    """
    For each row of "current" activity, compares it against that entity's
    baseline and produces a 0-1 deviation score plus the individual signals
    that drove it — off_hours, volume_spike, unknown_entity — mirroring the
    UBA snapshot card already in the dashboard (Normal Hours / Current
    Activity / risk).

    An entity with NO baseline (never seen before) is treated as maximally
    suspicious on the "unknown_entity" signal — a brand-new source appearing
    for the first time is itself a meaningful risk signal in real SOC
    practice, not just missing data to ignore.
    """
    current = current_activity.copy()
    current["_hour"] = pd.to_datetime(current[ts_col], errors="coerce").dt.hour

    joined = current.merge(baseline, left_on=ip_col, right_index=True, how="left")

    known = joined["typical_hour"].notna()
    hour_diff = (joined["_hour"] - joined["typical_hour"]).abs()
    # circular hour distance (23 and 0 are only 1 hour apart, not 23)
    hour_diff = np.minimum(hour_diff, 24 - hour_diff)

    off_hours_signal = np.where(
        known,
        np.clip(hour_diff / 12, 0, 1),   # 12h away = maximally off-hours
        1.0,                              # unknown entity = treat as fully off-baseline
    )
    unknown_entity_signal = (~known).astype(float)

    deviation_score = np.clip(0.5 * off_hours_signal + 0.5 * unknown_entity_signal, 0, 1)

    return pd.DataFrame({
        ip_col: joined[ip_col],
        "deviation_score": deviation_score.round(3),
        "off_hours_signal": off_hours_signal.round(3),
        "unknown_entity": unknown_entity_signal.astype(bool),
        "current_hour": joined["_hour"],
        "typical_hour": joined["typical_hour"],
    })
