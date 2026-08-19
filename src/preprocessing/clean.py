"""
clean.py
--------
Cleaning + validation layer for the merged CICIDS2017 dataset.

Each function does ONE job and returns a new/modified DataFrame, so every
step can be tested and explained on its own (this mirrors the "Validation &
Cleaning" box in the ThreatLens AI architecture diagram). The functions are
called in order by `run_full_cleaning()` at the bottom of this file, and
that exact order is also what the EDA notebook walks through, cell by cell.
"""

import numpy as np
import pandas as pd

# CICIDS2017's raw "Label" column uses these exact strings. We map them onto
# ThreatLens AI's 7-class scheme from the project blueprint. Two honesty notes
# baked in here on purpose (see README / notebook markdown for the full
# explanation):
#   1. CICIDS2017 has no traffic literally called "Credential Stuffing" —
#      FTP-Patator / SSH-Patator are brute-force login attempts, which is the
#      closest real match, so they are mapped to "Brute Force".
#   2. "Bot" and "Infiltration" don't have a clean home in the blueprint's 7
#      classes. We keep them as their own classes rather than force a wrong
#      label onto them — a wrong label would quietly corrupt every model
#      trained on this data.
LABEL_MAP = {
    "BENIGN": "Normal",
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "DoS slowloris": "DDoS",
    "DoS Slowhttptest": "DDoS",
    "DoS Hulk": "DDoS",
    "DoS GoldenEye": "DDoS",
    "DDoS": "DDoS",
    "PortScan": "Port Scanning",
    "Web Attack \x96 Brute Force": "Web Attack",
    "Web Attack \x96 XSS": "Web Attack",
    "Web Attack \x96 Sql Injection": "Web Attack",
    "Web Attack � Brute Force": "Web Attack",   # encoding variants seen in the wild
    "Web Attack � XSS": "Web Attack",
    "Web Attack � Sql Injection": "Web Attack",
    "Bot": "Botnet",
    "Infiltration": "Infiltration",
    "Heartbleed": "Other",
}


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """
    CICIDS2017's raw headers have inconsistent leading/trailing spaces
    (e.g. ' Flow Duration', 'Total Fwd Packets '). Left as-is, this causes
    silent bugs — df['Flow Duration'] would raise a KeyError even though the
    column visually looks like it exists. We normalize to lowercase,
    underscore-separated names.
    """
    df = df.copy()
    df.columns = (
        df.columns
        .str.strip()
        .str.lower()
        .str.replace(r"[^\w]+", "_", regex=True)
        .str.strip("_")
    )
    return df


def handle_infinite_and_missing(df: pd.DataFrame) -> pd.DataFrame:
    """
    CICIDS2017 is known to contain `Infinity` and `NaN` values in a handful
    of rate-based columns (e.g. flow_bytes_s, flow_packets_s) — these appear
    when a flow's duration is 0, causing a division by zero during the
    original feature extraction. Most ML models (and SHAP) will silently
    break or produce garbage on Infinity values, so we:
      1. Replace +/-inf with NaN so they're handled by one consistent path.
      2. Report how many NaNs exist per column (kept in the notebook output
         as part of the Data Quality Center numbers).
      3. Drop rows that are still NaN in any numeric column, since imputing
         flow-rate features here would fabricate traffic patterns that never
         happened — safer to drop than to invent.
    """
    df = df.replace([np.inf, -np.inf], np.nan)
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    before = len(df)
    df = df.dropna(subset=numeric_cols)
    dropped = before - len(df)
    print(f"  dropped {dropped:,} rows containing inf/NaN in numeric columns "
          f"({dropped / before:.3%} of data)")
    return df


def remove_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """
    CICIDS2017 has a documented duplicate-row issue (the same flow appearing
    more than once across the released files). Duplicates inflate whichever
    class they belong to and leak near-identical rows across any train/test
    split, so we drop them before doing anything else with class balance.
    """
    before = len(df)
    df = df.drop_duplicates()
    removed = before - len(df)
    print(f"  removed {removed:,} duplicate rows ({removed / before:.3%} of data)")
    return df


def standardize_labels(df: pd.DataFrame, label_col: str = "label") -> pd.DataFrame:
    """
    Maps CICIDS2017's raw attack-name strings onto ThreatLens AI's attack
    taxonomy using LABEL_MAP above. Any label we don't recognize is kept
    as-is but flagged loudly — silently dropping unknown labels would hide
    a real data problem.
    """
    df = df.copy()
    df[label_col] = df[label_col].astype(str).str.strip()

    unmapped = set(df[label_col].unique()) - set(LABEL_MAP)
    if unmapped:
        print(f"  WARNING: {len(unmapped)} label value(s) not found in LABEL_MAP "
              f"and left unchanged: {unmapped}")

    df["attack_category"] = df[label_col].map(LABEL_MAP).fillna(df[label_col])
    return df


def run_full_cleaning(df: pd.DataFrame, label_col: str = "label") -> pd.DataFrame:
    """
    Orchestrates the full cleaning sequence in the correct order:
    column names -> infinities/missing -> duplicates -> label standardization.
    This is the single function the EDA notebook calls; every sub-step above
    is still independently testable and independently explained in markdown.
    """
    print("Step 1/4 — cleaning column names")
    df = clean_column_names(df)

    print("Step 2/4 — handling infinite / missing values")
    df = handle_infinite_and_missing(df)

    print("Step 3/4 — removing duplicate rows")
    df = remove_duplicates(df)

    print("Step 4/4 — standardizing attack labels")
    df = standardize_labels(df, label_col=label_col)

    return df
