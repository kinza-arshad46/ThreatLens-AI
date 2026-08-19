"""
load_data.py
------------
Ingestion layer for the CICIDS2017 raw CSV files.

This corresponds to the "Ingestion" stage of the ThreatLens AI architecture
(Security Logs -> Ingestion -> Data Pipeline). At this stage we are only
responsible for READING the raw files and stitching them into a single
DataFrame, tagged with which day/session each row came from. No cleaning
happens here on purpose — cleaning is a separate, testable step
(see src/preprocessing/clean.py) so the two responsibilities never mix.
"""

from pathlib import Path
import pandas as pd

# The exact 8 files that ship with the CICIDS2017 "MachineLearningCSV" release.
# Keys are a short, readable session name; values are the substrings we expect
# to find in the actual filenames (Kaggle uploads sometimes rename them
# slightly, so we match on substring rather than exact name).
EXPECTED_SESSIONS = {
    "monday": "Monday-WorkingHours",
    "tuesday": "Tuesday-WorkingHours",
    "wednesday": "Wednesday-workingHours",
    "thursday_morning": "Thursday-WorkingHours-Morning",
    "thursday_afternoon": "Thursday-WorkingHours-Afternoon",
    "friday_morning": "Friday-WorkingHours-Morning",
    "friday_afternoon_ddos": "Friday-WorkingHours-Afternoon-DDos",
    "friday_afternoon_portscan": "Friday-WorkingHours-Afternoon-PortScan",
}


def find_raw_files(raw_dir: str | Path) -> dict[str, Path]:
    """
    Scan `raw_dir` for CSV files and match them to the expected session names.

    Returns a dict like {"monday": Path(".../Monday-WorkingHours.pcap_ISCX.csv"), ...}
    Raises a clear error listing exactly which files are missing, instead of
    failing deep inside pandas with a confusing traceback.
    """
    raw_dir = Path(raw_dir)
    all_csvs = list(raw_dir.glob("*.csv"))

    found = {}
    for session_key, name_fragment in EXPECTED_SESSIONS.items():
        match = next((f for f in all_csvs if name_fragment.lower() in f.name.lower()), None)
        if match is not None:
            found[session_key] = match

    missing = set(EXPECTED_SESSIONS) - set(found)
    if missing:
        missing_fragments = [EXPECTED_SESSIONS[m] for m in missing]
        raise FileNotFoundError(
            f"Could not find {len(missing)} expected file(s) in {raw_dir}.\n"
            f"Missing (looking for filenames containing): {missing_fragments}\n"
            f"Files actually present: {[f.name for f in all_csvs]}"
        )
    return found


def load_all_csvs(raw_dir: str | Path, verbose: bool = True) -> pd.DataFrame:
    """
    Load all 8 CICIDS2017 CSVs and concatenate them into one DataFrame.

    A `source_file` column is added so that, even after merging, we can always
    trace any row back to the day/session it came from — useful for debugging
    and for the "Data Quality Center" style checks later in the pipeline.
    """
    files = find_raw_files(raw_dir)
    frames = []

    for session_key, path in files.items():
        # low_memory=False avoids pandas' dtype-guessing warnings on the
        # mixed-type columns this dataset is known to have.
        df = pd.read_csv(path, low_memory=False)
        df["source_file"] = session_key
        frames.append(df)
        if verbose:
            print(f"  loaded {session_key:28s} -> {df.shape[0]:>8,} rows, {df.shape[1]} cols  ({path.name})")

    combined = pd.concat(frames, ignore_index=True)
    if verbose:
        print(f"\n  TOTAL combined -> {combined.shape[0]:,} rows, {combined.shape[1]} cols")
    return combined
