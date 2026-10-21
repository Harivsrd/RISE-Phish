"""Experiment 1: Baseline URL + HTML Classifier Protocol.

Trains and benchmarks the standard supervised learning baseline using
pure URL and HTML structural features, generating the empirical control metrics
against which CRCE, SLM, and Evidence Fusion will be evaluated.
"""
import json
import os
import numpy as np

from backend.app.ml.baseline_features import extract_baseline_features, get_feature_names
from backend.app.ml.baseline_model import BaselineClassifier
from backend.app.models.schemas import HTMLFeatures, URLFeatures


def generate_synthetic_benchmark_dataset(n_samples: int = 100, seed: int = 42):
    """Generates synthetic legitimate and phishing feature samples for protocol testing.
    
    Provides controlled data to verify pipeline execution without fabricating real metrics.
    """
    np.random.seed(seed)
    X = []
    y = []

    for i in range(n_samples):
        is_phish = i % 2 == 1
        y.append(1 if is_phish else 0)

        # Construct representative URLFeatures
        if is_phish:
            url_f = URLFeatures(
                raw_url=f"http://login.verification-alert{i}.xyz/account/login",
                url_length=55 + (i % 20),
                scheme="http",
                hostname=f"login.verification-alert{i}.xyz",
                registered_domain=f"verification-alert{i}.xyz",
                subdomain="login",
                path="/account/login",
                query="",
                tld="xyz",
                num_dots=3,
                num_hyphens=2,
                num_digits=2,
                num_special_chars=0,
                has_ip_address=False,
                has_at_symbol=False,
                has_punycode=False,
                percent_encoding_count=0,
                subdomain_parts_count=1,
                shannon_entropy=3.6,
                suspicious_tld=True,
                suspicious_keywords_found=["login", "verification", "account"],
                url_risk_score=0.75,
            )
            html_f = HTMLFeatures(
                title="Account Suspended - Login Now",
                total_tags=45,
                script_count=3,
                iframe_count=1,
                has_password_field=True,
                forms=[],
                input_fields=[],
                password_inputs=[],
                buttons=["Sign In"],
                links=["#"],
                images=[],
                visible_text="Your account has been restricted. Sign in to restore access.",
            )
        else:
            url_f = URLFeatures(
                raw_url=f"https://www.example-service{i}.com/products/item",
                url_length=42 + (i % 15),
                scheme="https",
                hostname=f"www.example-service{i}.com",
                registered_domain=f"example-service{i}.com",
                subdomain="www",
                path="/products/item",
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
                shannon_entropy=2.8,
                suspicious_tld=False,
                suspicious_keywords_found=[],
                url_risk_score=0.10,
            )
            html_f = HTMLFeatures(
                title="Example Official Products",
                total_tags=120,
                script_count=8,
                iframe_count=0,
                has_password_field=False,
                forms=[],
                input_fields=[],
                password_inputs=[],
                buttons=["Browse"],
                links=["https://example.com/about", "https://example.com/contact"],
                images=[],
                visible_text="Explore our catalog of official services and technical solutions.",
            )

        vec = extract_baseline_features(url_f, html_f)
        X.append(vec)

    return np.array(X, dtype=np.float64), np.array(y, dtype=np.int64)


def run_experiment_1(output_dir: str = "experiments/baseline"):
    """Executes Experiment 1: Baseline Classifier training and evaluation protocol."""
    os.makedirs(output_dir, exist_ok=True)
    X, y = generate_synthetic_benchmark_dataset(n_samples=200)

    # 80/20 train/test split
    split_idx = int(len(X) * 0.8)
    X_train, X_test = X[:split_idx], X[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]

    classifier = BaselineClassifier(model_type="random_forest", n_estimators=100)
    classifier.fit(X_train, y_train)

    metrics = classifier.evaluate(X_test, y_test)

    # Persist model artifact
    model_path = os.path.join(output_dir, "baseline_rf.joblib")
    classifier.save(model_path)

    # Persist evaluation metrics
    results_path = os.path.join(output_dir, "experiment_1_results.json")
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(metrics.model_dump(mode="json"), f, indent=2)

    return metrics, model_path, results_path


if __name__ == "__main__":
    metrics, m_path, r_path = run_experiment_1()
    print("Experiment 1 Executed Successfully.")
    print("Metrics:", metrics.model_dump())
