"""
registry.py
-----------
Lazy-loads the trained models produced by Notebooks 02/03 so the FastAPI
service can run inference without retraining anything. Models are loaded
once on first use and cached in memory for the lifetime of the process —
loading a joblib file on every request would add unnecessary latency.

Deliberately fails SOFT, not hard: if a model file isn't there yet (e.g.
someone spins up the API before running the training notebooks), routes
that depend on it return a clear "model not trained yet" message instead
of the whole API crashing on startup. This matters for a project meant to
be run and demoed incrementally, phase by phase, exactly like this one has
been built.
"""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ANOMALY_MODEL_PATH = PROJECT_ROOT / "models" / "anomaly" / "isolation_forest_v1.joblib"
CLASSIFIER_DIR = PROJECT_ROOT / "models" / "classifier"

_anomaly_model = None
_classifier_model = None
_label_encoder = None


class ModelNotTrainedError(Exception):
    """Raised when a route needs a model that hasn't been trained/saved yet."""
    pass


def get_anomaly_model():
    global _anomaly_model
    if _anomaly_model is None:
        if not ANOMALY_MODEL_PATH.exists():
            raise ModelNotTrainedError(
                f"Anomaly model not found at {ANOMALY_MODEL_PATH}. "
                f"Run notebooks/02_anomaly_detection.ipynb first."
            )
        from src.models.anomaly import load_model
        _anomaly_model = load_model(ANOMALY_MODEL_PATH)
    return _anomaly_model


def get_classifier_model():
    global _classifier_model, _label_encoder
    if _classifier_model is None:
        candidates = list(CLASSIFIER_DIR.glob("attack_classifier_*_v1.joblib")) if CLASSIFIER_DIR.exists() else []
        if not candidates:
            raise ModelNotTrainedError(
                f"No classifier model found in {CLASSIFIER_DIR}. "
                f"Run notebooks/03_attack_classifier.ipynb first."
            )
        from src.models.classifier import load_model
        _classifier_model = load_model(candidates[0])

        encoder_path = CLASSIFIER_DIR / "label_encoder_v1.joblib"
        if encoder_path.exists():
            _label_encoder = load_model(encoder_path)
    return _classifier_model, _label_encoder
