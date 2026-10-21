"""Unit test suite for Phase 16: Unseen Representation Attack Generalization.

Validates:
1. Synthesizers for novel zero-day attack vectors (math alphanumerics, soft hyphens, combining diacritics, enclosed characters, chameleon).
2. Unseen benchmark corpus generation and stratification.
3. Execution of Experiment 6 protocol and generation of academic reports.
4. Generalization delta verification (RISE-Phish outperforming baseline on unseen vectors).
"""
from pathlib import Path
import pytest

from backend.app.datasets.synthesizers.unseen import (
    generate_unseen_attack_benchmark_corpus,
    inject_combining_diacritics,
    inject_enclosed_alphanumerics,
    inject_math_alphanumerics,
    inject_soft_hyphens,
    synthesize_unseen_chameleon_payload,
)
from experiments.unseen_attack.run_unseen_attack_experiment import run_unseen_attack_experiment


def test_math_alphanumeric_synthesizer():
    """Verify Mathematical Bold character substitution and NFKC recovery."""
    text = "Sign in to your Microsoft Account"
    result = inject_math_alphanumerics(text, target_brand="Microsoft", rate=1.0, seed=42)

    assert result.characters_perturbed_count > 0
    assert "math_alphanumeric_substitution" in result.attack_types_applied
    assert "Microsoft" not in result.obfuscated_text  # Replaced with mathematical characters
    
    # Verify traceable recovery under NFKC normalization
    import unicodedata
    recovered = unicodedata.normalize("NFKC", result.obfuscated_text)
    assert recovered == text


def test_soft_hyphen_synthesizer():
    """Verify Soft Hyphen (U+00AD) injection and character breakdown."""
    text = "Verify your PayPal credentials"
    result = inject_soft_hyphens(text, target_brand="PayPal", frequency=1.0, seed=42)

    assert result.characters_perturbed_count > 0
    assert "soft_hyphen_insertion" in result.attack_types_applied
    assert "\u00ad" in result.obfuscated_text


def test_combining_diacritics_synthesizer():
    """Verify non-spacing combining mark overlay onto target brand."""
    text = "Log into your Apple ID"
    result = inject_combining_diacritics(text, target_brand="Apple", marks_per_char=1, seed=42)

    assert result.characters_perturbed_count > 0
    assert "combining_diacritics_overlay" in result.attack_types_applied
    assert result.obfuscated_text != text


def test_enclosed_alphanumerics_synthesizer():
    """Verify circled enclosed alphanumeric substitution and NFKC normalization."""
    text = "Google Account Security"
    result = inject_enclosed_alphanumerics(text, target_brand="Google", rate=1.0, seed=42)

    assert result.characters_perturbed_count > 0
    assert "enclosed_alphanumeric_substitution" in result.attack_types_applied
    
    import unicodedata
    recovered = unicodedata.normalize("NFKC", result.obfuscated_text)
    assert recovered == text


def test_unseen_chameleon_composite_payload():
    """Verify multi-vector chameleon payload generator."""
    payload = synthesize_unseen_chameleon_payload(
        brand="Netflix",
        spoof_domain="netflix-billing-update.xyz",
        seed=42,
    )

    assert payload["attack_type"] == "unseen_chameleon_composite"
    assert payload["canonical_token"] == "Netflix"
    assert "<form" in payload["raw_html"]
    assert "input type='password'" in payload["raw_html"] or 'type="password"' in payload["raw_html"]
    assert "netflix-billing-update.xyz" in payload["url"]


def test_unseen_attack_benchmark_corpus_generation():
    """Verify unseen benchmark corpus generates balanced benign and adversarial splits."""
    corpus = generate_unseen_attack_benchmark_corpus(n_samples=40, phishing_ratio=0.5, seed=42)
    assert len(corpus) == 40

    phish_samples = [s for s in corpus if s.label == 1]
    benign_samples = [s for s in corpus if s.label == 0]
    assert len(phish_samples) == 20
    assert len(benign_samples) == 20

    # Ensure all novel attack types are represented
    attack_types = {s.attack_type for s in phish_samples}
    assert "math_alphanumerics" in attack_types
    assert "soft_hyphen_break" in attack_types
    assert "combining_diacritics" in attack_types


def test_unseen_attack_experiment_execution(tmp_path):
    """Validates full execution of Experiment 6 and verifies generalization advantage."""
    output_dir = str(tmp_path / "reports")
    results = run_unseen_attack_experiment(n_samples=40, output_dir=output_dir, seed=42)

    assert results["metadata"]["total_samples"] == 40
    configs = results["configurations"]
    assert "baseline_random_forest" in configs
    assert "baseline_augmented_with_crce" in configs
    assert "full_rise_phish_system" in configs

    rise = configs["full_rise_phish_system"]
    base = configs["baseline_random_forest"]

    # Research validation: RISE-Phish must maintain high detection recall on unseen attacks
    assert rise["recall"] >= 0.85
    assert rise["f1_score"] >= 0.85
    assert rise["recall"] >= base["recall"]

    # Verify report files were generated
    assert Path(output_dir, "unseen_attack_results.json").exists()
    assert Path(output_dir, "unseen_attack_summary.md").exists()
