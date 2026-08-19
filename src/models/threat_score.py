"""
threat_score.py
----------------
The Threat Scoring engine (ThreatLens AI blueprint, Section 4 -- "Threat
Scoring" row): combines the outputs of the anomaly detector (Notebook 02)
and the attack classifier (Notebook 03) into a single 0-100 threat score
and a severity label (Low / Medium / High / Critical) -- the same numbers
shown on every alert card in the dashboard we built earlier.

Design choice: this is a *weighted rule engine*, not another trained model.
The blueprint calls it a "weighted risk engine using model + behavioral
signals" for a reason -- at this stage we have two model outputs (anomaly
score, classifier confidence) and no separate labeled "true severity"
column to train a third model against. A transparent weighted formula is
also easier for a security analyst to trust and audit than a black-box
score, which matters for a SOC dashboard context.
"""

import numpy as np
import pandas as pd


# Different attack types carry different inherent severity even at the same
# confidence level -- e.g. a 70%-confidence DDoS prediction is operationally
# scarier than a 70%-confidence Port Scan. These weights are a starting
# point informed by the blueprint's own example severities (Section 13:
# Brute Force flagged CRITICAL at 94%) -- they are meant to be tuned later
# against real incident feedback, not treated as final.
ATTACK_SEVERITY_WEIGHT = {
    "Normal": 0.0,
    "Port Scanning": 0.55,
    "Web Attack": 0.70,
    "Brute Force": 0.80,
    "Botnet": 0.85,
    "Infiltration": 0.90,
    "DDoS": 0.90,
    "Other": 0.60,
}


def normalize_anomaly_score(raw_score: pd.Series) -> pd.Series:
    """
    Isolation Forest's raw decision_function output is roughly in [-0.5, 0.5],
    where LOWER means MORE anomalous -- not an intuitive scale for a
    dashboard. This rescales it to [0, 1] where HIGHER means MORE anomalous,
    matching how "risk" should read everywhere else in the product.
    """
    inverted = -raw_score
    min_v, max_v = inverted.min(), inverted.max()
    if max_v == min_v:
        return pd.Series(0.5, index=raw_score.index)
    return (inverted - min_v) / (max_v - min_v)


def compute_threat_score(
    anomaly_score_normalized: pd.Series,
    predicted_attack_category: pd.Series,
    classifier_confidence: pd.Series,
    anomaly_weight: float = 0.35,
    classifier_weight: float = 0.35,
    severity_weight: float = 0.30,
) -> pd.DataFrame:
    """
    Combines three signals into one 0-100 threat score:
      1. anomaly_score_normalized  -- "how unusual" (from Notebook 02, 0-1)
      2. classifier_confidence     -- "how sure the model is" (from Notebook 03, 0-1)
      3. attack severity weight    -- "how bad is this attack type inherently"
                                       (ATTACK_SEVERITY_WEIGHT lookup, 0-1)

    The three weights sum to 1.0 by default so the output lands cleanly in
    [0, 100]. Every weight is a named argument (not hardcoded inline) so an
    analyst tuning this later can see and change the formula's logic in one
    place, matching the blueprint's "keep thresholds configurable" governance
    rule (Section 14).
    """
    severity = predicted_attack_category.map(ATTACK_SEVERITY_WEIGHT).fillna(0.5)

    raw = (
        anomaly_weight * anomaly_score_normalized.values
        + classifier_weight * classifier_confidence.values
        + severity_weight * severity.values
    )
    threat_score = np.clip(raw * 100, 0, 100).round(1)

    return pd.DataFrame({
        "threat_score": threat_score,
        "severity": [severity_label(s) for s in threat_score],
    }, index=anomaly_score_normalized.index)


def severity_label(score: float) -> str:
    """
    Maps a 0-100 threat score to the four severity tiers used across the
    dashboard (KPI cards, alert table, System Health page). Thresholds match
    the visual bands already shown in the frontend (Critical badge at ~90%+,
    High at ~75-89%, etc.) so the backend and the UI agree on what "Critical"
    means.
    """
    if score >= 90:
        return "Critical"
    if score >= 75:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"
