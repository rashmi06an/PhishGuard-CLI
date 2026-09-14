"""Machine learning predictor and training pipeline for PhishGuard-CLI.

Uses scikit-learn (RandomForest / LogisticRegression) to train on explainable
lexical domain features and calculate phishing probability.
"""

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from phishguard.features import FEATURE_NAMES, FeatureResult, extract_features

DEFAULT_MODEL_PATH = "models/phishguard_model.joblib"


class ModelNotFoundError(FileNotFoundError):
    """Raised when the trained machine learning model file does not exist."""

    pass


@dataclass
class PredictionResult:
    """Structured result of model prediction on a target domain."""

    target: str
    probability: float  # Phishing probability between 0.0 and 1.0
    classification: str  # SAFE, SUSPICIOUS, or PHISHING
    feature_result: FeatureResult


def load_model_artifact(model_path: str = DEFAULT_MODEL_PATH) -> Dict[str, Any]:
    """Load the trained model artifact from disk.

    Raises ModelNotFoundError if the model file is not found.
    """
    import warnings

    if not os.path.isfile(model_path):
        raise ModelNotFoundError(
            f"Model not found at '{model_path}'. "
            f"Please run 'phishguard train' first to train the detection model."
        )

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return joblib.load(model_path)


def train_model(
    dataset_path: str,
    model_type: str = "random_forest",
    output_path: str = DEFAULT_MODEL_PATH,
) -> Dict[str, Any]:
    """Train classifier on a CSV dataset, compute evaluation metrics, and persist artifact.

    The CSV must contain a URL/domain column ('url' or 'domain') and a binary 'label' column.
    """
    if not os.path.isfile(dataset_path):
        raise FileNotFoundError(f"Training dataset not found: '{dataset_path}'")

    # Load dataset, skipping comment lines
    df = pd.read_csv(dataset_path, comment="#")

    # Normalize column names
    col_map = {col: col.lower().strip() for col in df.columns}
    df = df.rename(columns=col_map)

    target_col: Optional[str] = None
    for candidate in ["url", "domain", "target", "hostname"]:
        if candidate in df.columns:
            target_col = candidate
            break

    if not target_col:
        raise ValueError(
            f"Dataset '{dataset_path}' must have a 'url' or 'domain' column. Found: {list(df.columns)}"
        )

    if "label" not in df.columns:
        raise ValueError(
            f"Dataset '{dataset_path}' must have a 'label' column. Found: {list(df.columns)}"
        )

    # Clean missing values
    df = df.dropna(subset=[target_col, "label"])
    df = df[df[target_col].astype(str).str.strip() != ""]

    if len(df) < 10:
        raise ValueError(f"Dataset in '{dataset_path}' has too few samples ({len(df)}) for training.")

    # Normalize labels to integer 0 or 1
    def normalize_label(val: Any) -> int:
        s = str(val).strip().lower()
        if s in ["1", "phishing", "bad", "malicious", "true"]:
            return 1
        return 0

    y_series = df["label"].apply(normalize_label)

    # Extract features row by row using our canonical feature extractor
    X_rows: List[List[float]] = []
    for raw_target in df[target_col]:
        res = extract_features(str(raw_target))
        X_rows.append(res.feature_vector)

    X = pd.DataFrame(X_rows, columns=FEATURE_NAMES)
    y = y_series.to_numpy()

    # Split dataset into train (80%) and test (20%)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # Initialize model
    if model_type == "logistic_regression":
        model = LogisticRegression(max_iter=1000, random_state=42)
    else:
        model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)

    # Fit model
    model.fit(X_train, y_train)

    # Evaluate model
    y_pred = model.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))

    metrics: Dict[str, Any] = {
        "dataset_samples": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "accuracy": round(acc * 100, 2),
        "precision": round(prec * 100, 2),
        "recall": round(rec * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "model_type": model_type,
    }

    # Ensure destination directory exists
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    artifact = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "metrics": metrics,
        "model_type": model_type,
    }

    joblib.dump(artifact, output_path)
    return metrics


def predict_target(
    target: str,
    model_path: str = DEFAULT_MODEL_PATH,
) -> PredictionResult:
    """Predict phishing probability for a target using the trained ML model.

    Raises ModelNotFoundError if the model has not yet been trained.
    """
    artifact = load_model_artifact(model_path)
    model = artifact["model"]

    # Extract lexical features
    feat_result = extract_features(target)

    # Prepare feature matrix with correct column names to avoid warnings
    X = pd.DataFrame([feat_result.feature_vector], columns=FEATURE_NAMES)

    probabilities = model.predict_proba(X)[0]
    # probabilities[0] is class 0 (safe), probabilities[1] is class 1 (phishing)
    phishing_prob = float(probabilities[1])

    if phishing_prob >= 0.70:
        classification = "PHISHING"
    elif phishing_prob >= 0.40:
        classification = "SUSPICIOUS"
    else:
        classification = "SAFE"

    return PredictionResult(
        target=target,
        probability=round(phishing_prob, 4),
        classification=classification,
        feature_result=feat_result,
    )
