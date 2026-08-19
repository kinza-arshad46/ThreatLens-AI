"""
anomaly.py
----------
Reusable functions for the Anomaly Detection engine described in the
ThreatLens AI blueprint (Section 4: AI Detection & Multi-Class Attack
Classification -> Anomaly Detection row).

Model choice: Isolation Forest.
Why: it's unsupervised (doesn't need attack labels to train — realistic,
since in production a lot of traffic is unlabeled), scales well to the
~2.8M row size of CICIDS2017, and doesn't require feature scaling to work
correctly (tree-based, splits on raw feature values). This makes it the
right "first" anomaly engine per the blueprint's own implementation
strategy: build the simplest reliable thing first, compare more complex
options (One-Class SVM, DBSCAN, Autoencoder) later against this baseline.

As with clean.py, every function here does one job and is unit-testable on
its own, and this exact code is what both the notebook and, later, the
FastAPI inference service will import — no duplicated logic between them.
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)

# Columns that must never be used as model features — either because they
# are metadata (not traffic behavior), or because they leak the answer
# (the label itself, or anything derived from it).
NON_FEATURE_COLUMNS = {"label", "attack_category", "source_file"}


def select_feature_columns(df: pd.DataFrame) -> list[str]:
    """
    Returns the list of numeric columns safe to use as model input features —
    i.e. every numeric column except identifiers/labels in NON_FEATURE_COLUMNS.
    Kept as its own function (rather than inlined) so notebooks 03+ reuse the
    exact same feature set as this one, keeping every model comparable.
    """
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    return [c for c in numeric_cols if c not in NON_FEATURE_COLUMNS]


def train_isolation_forest(
    X_train: pd.DataFrame,
    contamination: float = 0.15,
    n_estimators: int = 200,
    random_state: int = 42,
) -> IsolationForest:
    """
    Trains an Isolation Forest on the given feature matrix.

    `contamination` is the expected proportion of anomalies in the data —
    Isolation Forest uses it to decide where to draw the anomaly/normal
    threshold on its raw scores. We estimate a reasonable starting value
    from the actual attack ratio in the training data (done in the notebook,
    not hardcoded here) rather than guessing blindly.

    Note this function receives ONLY features — never the label column —
    because Isolation Forest is unsupervised: it never sees attack_category
    during training. We only use labels afterwards, in `evaluate_anomaly_model`,
    to check how well the unsupervised result lines up with reality.
    """
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X_train)
    return model


def predict_anomalies(model: IsolationForest, X: pd.DataFrame) -> pd.DataFrame:
    """
    Runs the trained model and returns a small DataFrame with:
      - anomaly_score: raw model score (lower = more anomalous)
      - is_anomaly: 1 if the model flags the row as anomalous, else 0

    Isolation Forest's native `.predict()` returns -1/1; we remap to 1/0
    so "1 = anomaly" reads naturally everywhere else in the project
    (dashboard, evaluation code, etc).
    """
    raw_pred = model.predict(X)          # -1 = anomaly, 1 = normal
    scores = model.decision_function(X)  # lower = more anomalous
    return pd.DataFrame({
        "anomaly_score": scores,
        "is_anomaly": (raw_pred == -1).astype(int),
    }, index=X.index)


def evaluate_anomaly_model(y_true_is_attack: pd.Series, y_pred_is_anomaly: pd.Series) -> dict:
    """
    Compares the model's unsupervised anomaly flags against the REAL attack
    labels (attack_category != "Normal"), purely for evaluation — the model
    itself never saw these labels during training.

    Returns precision/recall/F1 plus the full confusion matrix, and prints a
    readable classification report. Precision/recall matter more than raw
    accuracy here because the classes are imbalanced (mostly normal traffic),
    so a model that just predicts "normal" for everything would score a
    misleadingly high accuracy while being useless.
    """
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true_is_attack, y_pred_is_anomaly, average="binary", zero_division=0
    )
    cm = confusion_matrix(y_true_is_attack, y_pred_is_anomaly)

    print(classification_report(
        y_true_is_attack, y_pred_is_anomaly,
        target_names=["Normal", "Anomaly"], zero_division=0
    ))

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix": cm,
    }


def save_model(model: IsolationForest, path: str | Path) -> None:
    """Saves the trained model to disk with joblib (standard for sklearn models)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    print(f"Model saved -> {path}")


def load_model(path: str | Path) -> IsolationForest:
    """Loads a previously trained model back from disk."""
    return joblib.load(path)
