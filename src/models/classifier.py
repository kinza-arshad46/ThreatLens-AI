"""
classifier.py
-------------
Reusable functions for the Multi-Class Attack Classification engine
(ThreatLens AI blueprint, Section 4 -- "Attack Classification" row).

Model choice: Random Forest first, then XGBoost, compared head-to-head.
Why both: Random Forest is the safer, more interpretable baseline -- fast to
train, hard to badly misconfigure, and a fair reference point. XGBoost
usually performs better on structured/tabular data like network flow
features, but needs more careful tuning and is more prone to overfitting on
minority classes if left unchecked. Training both and comparing honestly
(same features, same split) is how the blueprint's own "Model Lab" concept
is supposed to work -- no model is assumed best without evidence.

Unlike anomaly.py (unsupervised), this module IS supervised: it uses
`attack_category` as the training target, so it can name *which* attack
type a row belongs to, not just "anomalous or not."
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    accuracy_score,
)

try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False


def train_random_forest(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    n_estimators: int = 300,
    class_weight: str = "balanced",
    random_state: int = 42,
) -> RandomForestClassifier:
    """
    Trains a Random Forest multi-class classifier.

    class_weight="balanced" matters a lot here: CICIDS2017 is imbalanced
    (e.g. Heartbleed/Infiltration have very few rows compared to Normal or
    DDoS). Without balancing, the model would learn to mostly predict the
    majority classes and silently ignore rare-but-important attack types.
    """
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight=class_weight,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    return model


def train_xgboost(
    X_train: pd.DataFrame,
    y_train_encoded: np.ndarray,
    num_classes: int,
    random_state: int = 42,
):
    """
    Trains an XGBoost multi-class classifier.

    XGBoost needs integer-encoded labels (0..num_classes-1), not strings --
    encoding/decoding is handled in the notebook via a LabelEncoder, kept
    out of this function so this module doesn't own encoding state.

    Raises a clear error if xgboost isn't installed, rather than letting the
    notebook fail with a confusing NameError deep inside a cell.
    """
    if not XGBOOST_AVAILABLE:
        raise ImportError("xgboost is not installed. Run: pip install xgboost")
    model = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        objective="multi:softprob",
        num_class=num_classes,
        eval_metric="mlogloss",
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X_train, y_train_encoded)
    return model


def evaluate_classifier(y_true, y_pred, label_names: list[str]) -> dict:
    """
    Prints a full per-class classification report (precision/recall/F1 for
    EVERY class, not just overall accuracy -- overall accuracy on an
    imbalanced dataset can look great while the model completely misses a
    rare-but-critical class like Infiltration).

    Returns the key summary numbers plus the raw confusion matrix so the
    notebook can visualize it.
    """
    acc = accuracy_score(y_true, y_pred)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)

    print(classification_report(y_true, y_pred, target_names=label_names, zero_division=0))

    cm = confusion_matrix(y_true, y_pred)

    return {
        "accuracy": acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "confusion_matrix": cm,
    }


def get_feature_importance(model, feature_names: list[str]) -> pd.Series:
    """
    Returns feature importances as a sorted pandas Series (most important
    first). Works for both RandomForestClassifier and XGBClassifier since
    both expose `.feature_importances_`.
    """
    importances = pd.Series(model.feature_importances_, index=feature_names)
    return importances.sort_values(ascending=False)


def save_model(model, path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    print(f"Model saved -> {path}")


def load_model(path):
    return joblib.load(path)
