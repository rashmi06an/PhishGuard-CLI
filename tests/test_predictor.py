"""Unit tests for ML predictor and training pipeline."""

import os
import pytest

from phishguard.predictor import (
    ModelNotFoundError,
    PredictionResult,
    predict_target,
    train_model,
)

TEST_MODEL_PATH = "models/test_predictor_model.joblib"


@pytest.fixture(scope="module")
def trained_test_model():
    """Fixture that trains a temporary model for testing and cleans it up afterward."""
    metrics = train_model(
        dataset_path="data/train_dataset.csv",
        model_type="random_forest",
        output_path=TEST_MODEL_PATH,
    )
    yield metrics
    if os.path.exists(TEST_MODEL_PATH):
        os.remove(TEST_MODEL_PATH)


class TestPredictor:
    """Test suite for predictor model training, errors, and inference."""

    def test_missing_model_raises_clean_error(self):
        with pytest.raises(ModelNotFoundError) as exc_info:
            predict_target("example.com", model_path="models/definitely_missing.joblib")
        err_msg = str(exc_info.value)
        assert "not found" in err_msg.lower()
        assert "phishguard train" in err_msg

    def test_missing_dataset_raises_error(self):
        with pytest.raises(FileNotFoundError):
            train_model("data/non_existent_dataset.csv", output_path=TEST_MODEL_PATH)

    def test_training_pipeline_returns_valid_metrics(self, trained_test_model):
        metrics = trained_test_model
        assert isinstance(metrics, dict)
        assert metrics["dataset_samples"] > 50
        assert "accuracy" in metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1_score" in metrics
        assert 0.0 <= metrics["accuracy"] <= 100.0
        assert os.path.isfile(TEST_MODEL_PATH)

    def test_safe_domain_prediction(self, trained_test_model):
        res = predict_target("google.com", model_path=TEST_MODEL_PATH)
        assert isinstance(res, PredictionResult)
        assert res.target == "google.com"
        assert res.classification == "SAFE"
        assert res.probability < 0.40
        assert res.feature_result is not None

    def test_phishing_domain_prediction(self, trained_test_model):
        res = predict_target(
            "paypal-update-account-verification.com", model_path=TEST_MODEL_PATH
        )
        assert isinstance(res, PredictionResult)
        assert res.classification == "PHISHING"
        assert res.probability >= 0.70

    def test_prediction_result_bounds(self, trained_test_model):
        domains = ["wikipedia.org", "chase-fraud-prevention-alert.com", "github.com"]
        for d in domains:
            res = predict_target(d, model_path=TEST_MODEL_PATH)
            assert 0.0 <= res.probability <= 1.0
            assert res.classification in ["SAFE", "SUSPICIOUS", "PHISHING"]
