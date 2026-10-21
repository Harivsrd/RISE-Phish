"""Comprehensive test suite for Phase 8 Baseline Classifier & Benchmarks (Experiment 1).

Verifies:
- 26-dimensional URL + HTML feature extraction
- Supervised model training (RandomForest & LogisticRegression)
- Academic evaluation metrics generation (accuracy, precision, recall, F1, ROC-AUC, FPR, FNR)
- Model serialization and deserialization via joblib
- Single-sample inference and feature contribution attribution
- Error handling on untrained states
"""
import os
import numpy as np
import pytest

from backend.app.ml.baseline_features import extract_baseline_features, get_feature_names
from backend.app.ml.baseline_model import BaselineClassifier
from backend.app.models.schemas import HTMLFeatures, URLFeatures
from experiments.baseline.run_baseline_experiment import (
    generate_synthetic_benchmark_dataset,
    run_experiment_1,
)


def test_baseline_features_extraction():
    """Verify feature vector length, types, and alignment with feature names."""
    url_f = URLFeatures(
        raw_url="https://secure.login-update.com/account",
        url_length=38,
        scheme="https",
        hostname="secure.login-update.com",
        registered_domain="login-update.com",
        subdomain="secure",
        path="/account",
        query="",
        tld="com",
        num_dots=2,
        num_hyphens=1,
        num_digits=0,
        num_special_chars=0,
        has_ip_address=False,
        has_at_symbol=False,
        has_punycode=False,
        percent_encoding_count=0,
        subdomain_parts_count=1,
        shannon_entropy=3.1,
        suspicious_tld=False,
        suspicious_keywords_found=["secure", "login", "update", "account"],
        url_risk_score=0.65,
    )
    html_f = HTMLFeatures(
        title="Sign In",
        total_tags=50,
        script_count=2,
        iframe_count=0,
        has_password_field=True,
        forms=[],
        input_fields=[],
        password_inputs=[],
        buttons=["Log In"],
        links=[],
        images=[],
        visible_text="Please sign in to update your account.",
    )

    vec = extract_baseline_features(url_f, html_f)
    feature_names = get_feature_names()

    assert len(vec) == 26
    assert len(feature_names) == 26
    assert isinstance(vec, np.ndarray)
    assert np.all(np.isfinite(vec))
    assert vec[0] == 38.0  # url_length
    assert vec[13] == 0.65  # url_risk_score
    assert vec[17] == 1.0   # has_password_field


def test_baseline_random_forest_training_and_evaluation():
    """Verify RandomForest model fitting and academic metric evaluation."""
    X, y = generate_synthetic_benchmark_dataset(n_samples=100, seed=42)
    clf = BaselineClassifier(model_type="random_forest", n_estimators=50, random_state=42)

    clf.fit(X[:80], y[:80])
    assert clf.is_fitted is True

    metrics = clf.evaluate(X[80:], y[80:])
    assert metrics.total_samples == 20
    assert 0.0 <= metrics.accuracy <= 1.0
    assert 0.0 <= metrics.precision <= 1.0
    assert 0.0 <= metrics.recall <= 1.0
    assert 0.0 <= metrics.f1_score <= 1.0
    assert metrics.false_positive_rate >= 0.0
    assert metrics.false_negative_rate >= 0.0
    assert len(metrics.confusion_matrix) == 2


def test_baseline_logistic_regression_pipeline():
    """Verify LogisticRegression baseline works seamlessly with feature scaling."""
    X, y = generate_synthetic_benchmark_dataset(n_samples=60, seed=123)
    clf = BaselineClassifier(model_type="logistic_regression", random_state=42)

    clf.fit(X[:40], y[:40])
    probas = clf.predict_proba(X[40:])
    preds = clf.predict(X[40:])

    assert probas.shape == (20, 2)
    assert len(preds) == 20
    assert np.all((probas >= 0.0) & (probas <= 1.0))


def test_baseline_predict_sample_with_importances():
    """Verify single-sample inference and feature importance reporting."""
    X, y = generate_synthetic_benchmark_dataset(n_samples=50)
    clf = BaselineClassifier(model_type="random_forest", n_estimators=30)
    clf.fit(X, y)

    url_f = URLFeatures(
        raw_url="http://bank-login.xyz/auth",
        url_length=26,
        scheme="http",
        hostname="bank-login.xyz",
        registered_domain="bank-login.xyz",
        subdomain="",
        path="/auth",
        query="",
        tld="xyz",
        url_risk_score=0.85,
    )
    html_f = HTMLFeatures(title="Bank Login", has_password_field=True)

    prediction = clf.predict_sample(url_f, html_f)
    assert isinstance(prediction.is_phishing, bool)
    assert 0.0 <= prediction.probability <= 1.0
    assert prediction.model_name == "random_forest"
    assert len(prediction.feature_contributions) > 0


def test_baseline_model_serialization(tmp_path):
    """Verify model persistence to disk and reloading via joblib."""
    X, y = generate_synthetic_benchmark_dataset(n_samples=40)
    clf = BaselineClassifier(model_type="random_forest", n_estimators=20)
    clf.fit(X, y)

    save_file = os.path.join(str(tmp_path), "test_model.joblib")
    clf.save(save_file)
    assert os.path.exists(save_file)

    loaded_clf = BaselineClassifier.load(save_file)
    assert loaded_clf.is_fitted is True

    # Predictions must match identically
    orig_preds = clf.predict(X)
    loaded_preds = loaded_clf.predict(X)
    assert np.array_equal(orig_preds, loaded_preds)


def test_untrained_model_raises_runtime_error():
    """Verify querying an unfitted model raises a descriptive RuntimeError."""
    clf = BaselineClassifier()
    dummy_x = np.zeros((2, 26))

    with pytest.raises(RuntimeError):
        clf.predict(dummy_x)

    with pytest.raises(RuntimeError):
        clf.evaluate(dummy_x, np.array([0, 1]))


def test_run_experiment_1_protocol(tmp_path):
    """Verify the Experiment 1 protocol script generates structured results."""
    metrics, m_path, r_path = run_experiment_1(output_dir=str(tmp_path))

    assert os.path.exists(m_path)
    assert os.path.exists(r_path)
    assert metrics.accuracy > 0.0
    assert metrics.total_samples == 40
