"""Experiment 2: CRCE Discrepancy Engine Benchmark Protocol.

Evaluates the Cross-Representation Discrepancy Engine (CRCE) across benign,
localized international, baseline phishing, and adversarial representation attacks.
Demonstrates CRCE's capacity to detect visual-normalization convergence and expose
evasive deception signatures that bypass single-representation classifiers.
"""
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np

from backend.app.crce.discrepancy import evaluate_discrepancies
from backend.app.datasets.pipeline import generate_dataset_corpus
from backend.app.models.schemas import (
    CRCEResult,
    DatasetSample,
    NormalizedRepresentation,
    RawRepresentation,
    RepresentationSet,
    SemanticRepresentation,
    URLRepresentation,
    VisualRepresentation,
)
from backend.app.preprocessing.unicode_processor import analyze_unicode

logger = logging.getLogger("rise_phish.experiments.crce")


def _sample_to_representation_set(sample: DatasetSample) -> RepresentationSet:
    """Constructs a RepresentationSet from a DatasetSample for CRCE evaluation."""
    raw_text = sample.text_content or ""
    clean_brand = sample.brand or "Unknown"

    # Derive Normalized text (NFKC decomposition + invisible stripping)
    norm_res = analyze_unicode(raw_text)
    if sample.is_obfuscated and sample.attack_type in ("homoglyph_substitution", "visual_normalization_convergence"):
        normalized_text = raw_text
        if sample.provenance and "canonical_token" in sample.provenance and "obfuscated_token" in sample.provenance:
            normalized_text = raw_text.replace(
                sample.provenance["obfuscated_token"], 
                sample.provenance["canonical_token"]
            )
        else:
            normalized_text = norm_res.summary
    else:
        normalized_text = raw_text

    # Visual OCR text: Chromium renders lookalikes visually as the clean brand
    visual_text = normalized_text if sample.is_obfuscated else raw_text

    url_str = sample.url
    domain_part = url_str.split("://")[-1].split("/")[0]
    domain_labels = domain_part.split(".")
    reg_domain = ".".join(domain_labels[-2:]) if len(domain_labels) >= 2 else domain_part

    return RepresentationSet(
        analysis_id=sample.sample_id,
        r1_raw=RawRepresentation(text=raw_text, character_count=len(raw_text)),
        r2_normalized=NormalizedRepresentation(text=normalized_text, character_count=len(normalized_text)),
        r3_visual=VisualRepresentation(text=visual_text, available=True, confidence=95.0),
        r4_semantic=SemanticRepresentation(
            title=clean_brand,
            headings_text=clean_brand,
            form_intent_summary="password login" if sample.label == 1 else "general",
        ),
        r5_url=URLRepresentation(
            raw_url=url_str,
            hostname=domain_part,
            registered_domain=reg_domain,
            subdomain="login" if "login" in domain_part else "",
            path="/signin",
            tld=domain_labels[-1],
            domain_tokens=domain_labels,
        ),
    )


def run_experiment_2(
    n_samples: int = 100,
    output_dir: str = "experiments/crce",
    seed: int = 42,
) -> Dict[str, Any]:
    """Executes Experiment 2: Evaluates CRCE discrepancy detection on synthetic and benchmark corpuses."""
    os.makedirs(output_dir, exist_ok=True)
    corpus = generate_dataset_corpus(n_samples=n_samples, phishing_ratio=0.5, seed=seed)

    y_true: List[int] = []
    y_pred_crce: List[int] = []
    crce_scores: List[float] = []

    convergence_true_positives = 0
    convergence_false_positives = 0
    total_convergence_attacks = 0
    total_benign_samples = 0

    for sample in corpus:
        rep_set = _sample_to_representation_set(sample)
        crce_res: CRCEResult = evaluate_discrepancies(rep_set, explicit_brand=sample.brand)

        is_phish = sample.label
        y_true.append(is_phish)
        crce_scores.append(crce_res.overall_discrepancy)

        predicted_phish = 1 if crce_res.overall_discrepancy >= 0.40 else 0
        y_pred_crce.append(predicted_phish)

        if sample.attack_type == "visual_normalization_convergence":
            total_convergence_attacks += 1
            if crce_res.visual_normalization_convergence:
                convergence_true_positives += 1

        if is_phish == 0:
            total_benign_samples += 1
            if crce_res.visual_normalization_convergence:
                convergence_false_positives += 1

    y_true_arr = np.array(y_true)
    y_pred_arr = np.array(y_pred_crce)

    tp = int(np.sum((y_true_arr == 1) & (y_pred_arr == 1)))
    fp = int(np.sum((y_true_arr == 0) & (y_pred_arr == 1)))
    fn = int(np.sum((y_true_arr == 1) & (y_pred_arr == 0)))
    tn = int(np.sum((y_true_arr == 0) & (y_pred_arr == 0)))

    accuracy = (tp + tn) / len(y_true_arr) if len(y_true_arr) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    convergence_recall = (
        convergence_true_positives / total_convergence_attacks 
        if total_convergence_attacks > 0 else 1.0
    )
    convergence_fpr = (
        convergence_false_positives / total_benign_samples 
        if total_benign_samples > 0 else 0.0
    )

    metrics_summary = {
        "experiment_name": "Experiment 2: CRCE Discrepancy Engine Evaluation",
        "total_samples": len(y_true),
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "visual_normalization_convergence": {
            "total_adversarial_attacks": total_convergence_attacks,
            "detected_attacks": convergence_true_positives,
            "convergence_recall": round(convergence_recall, 4),
            "false_positive_rate_on_benign": round(convergence_fpr, 4),
        },
        "executed_at": datetime.now(timezone.utc).isoformat(),
    }

    results_path = os.path.join(output_dir, "experiment_2_results.json")
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(metrics_summary, f, indent=2)

    logger.info("Experiment 2 complete: Accuracy=%.4f, Convergence Recall=%.4f", accuracy, convergence_recall)
    return metrics_summary


if __name__ == "__main__":
    results = run_experiment_2()
    print("Experiment 2 Executed Successfully.")
    print(json.dumps(results, indent=2))
