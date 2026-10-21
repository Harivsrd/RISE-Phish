"""Feature extraction for the baseline URL + HTML machine learning classifier.

Extracts fixed-length numerical feature vectors purely from URL and HTML structures
without cross-representation discrepancy metrics, establishing Experiment 1 baseline.
"""
from typing import List
import numpy as np

from backend.app.models.schemas import HTMLFeatures, URLFeatures

FEATURE_NAMES: List[str] = [
    # URL Lexical & Syntactic Features (14)
    "url_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_special_chars",
    "has_ip_address",
    "has_at_symbol",
    "has_punycode",
    "percent_encoding_count",
    "subdomain_parts_count",
    "shannon_entropy",
    "suspicious_tld",
    "suspicious_keywords_count",
    "url_risk_score",
    # HTML Structural & Content Features (12)
    "total_tags",
    "script_count",
    "iframe_count",
    "has_password_field",
    "num_forms",
    "num_inputs",
    "num_password_inputs",
    "num_buttons",
    "num_links",
    "num_images",
    "visible_text_length",
    "title_length",
]


def get_feature_names() -> List[str]:
    """Returns the ordered list of feature names in the baseline vector."""
    return list(FEATURE_NAMES)


def extract_baseline_features(
    url_features: URLFeatures,
    html_features: HTMLFeatures,
) -> np.ndarray:
    """Extracts a 1D numerical numpy array of 26 baseline features.

    Args:
        url_features: Processed URLFeatures from Phase 3.
        html_features: Processed HTMLFeatures from Phase 2.

    Returns:
        1D np.ndarray of shape (26,) dtype float64.
    """
    raw_vector = [
        # URL features
        float(url_features.url_length),
        float(url_features.num_dots),
        float(url_features.num_hyphens),
        float(url_features.num_digits),
        float(url_features.num_special_chars),
        1.0 if url_features.has_ip_address else 0.0,
        1.0 if url_features.has_at_symbol else 0.0,
        1.0 if url_features.has_punycode else 0.0,
        float(url_features.percent_encoding_count),
        float(url_features.subdomain_parts_count),
        float(url_features.shannon_entropy),
        1.0 if url_features.suspicious_tld else 0.0,
        float(len(url_features.suspicious_keywords_found)),
        float(url_features.url_risk_score),
        # HTML features
        float(html_features.total_tags),
        float(html_features.script_count),
        float(html_features.iframe_count),
        1.0 if html_features.has_password_field else 0.0,
        float(len(html_features.forms)),
        float(len(html_features.input_fields)),
        float(len(html_features.password_inputs)),
        float(len(html_features.buttons)),
        float(len(html_features.links)),
        float(len(html_features.images)),
        float(len(html_features.visible_text)),
        float(len(html_features.title or "")),
    ]

    return np.array(raw_vector, dtype=np.float64)
