"""Unit test suite for RISE-Phish Dataset Pipeline & Adversarial Synthesizers (Phase 13).

Validates:
1. Homoglyph, zero-width, tag-character, bidi-override, and leetspeak synthesizers.
2. Composite Visual-Normalization Convergence attack generation (R1 != R2, R1 != R3, R2 == R3).
3. Stratified research corpus generation (balanced benign & phishing).
4. Stratified dataset split generation (train, val, test) and JSON disk serialization.
"""
import unicodedata
import pytest

from backend.app.datasets.pipeline import (
    create_stratified_splits,
    generate_dataset_corpus,
    load_split_from_disk,
    save_splits_to_disk,
)
from backend.app.datasets.synthesizers.composite import (
    create_synthetic_sample,
    synthesize_visual_convergence_payload,
)
from backend.app.datasets.synthesizers.homoglyphs import inject_homoglyphs
from backend.app.datasets.synthesizers.invisible_chars import (
    inject_bidi_override,
    inject_tag_characters,
    inject_zero_width,
)
from backend.app.datasets.synthesizers.leetspeak import inject_leetspeak
from backend.app.models.schemas import DatasetSample, DatasetSplit, SynthesizedAttackResult


def test_homoglyph_synthesizer_injection():
    """Validates injection of Cyrillic/Greek lookalikes into target brand names."""
    original = "Microsoft Office 365 Login"
    result = inject_homoglyphs(original, target_brand="Microsoft", rate=0.8, seed=42)

    assert isinstance(result, SynthesizedAttackResult)
    assert result.characters_perturbed_count >= 1
    assert result.obfuscated_text != original
    assert "homoglyph_substitution" in result.attack_types_applied
    assert any(ord(ch) > 127 for ch in result.obfuscated_text)
    assert len(result.metadata["substitutions"]) >= 1


def test_zero_width_synthesizer_injection():
    """Validates injection of zero-width non-printing characters into text."""
    original = "PayPal Security Center"
    result = inject_zero_width(original, target_brand="PayPal", frequency=0.5, seed=42)

    assert isinstance(result, SynthesizedAttackResult)
    assert result.characters_perturbed_count >= 1
    assert result.obfuscated_text != original
    assert "zero_width_insertion" in result.attack_types_applied

    # When zero-width characters are removed, the exact original string is restored
    stripped = "".join(ch for ch in result.obfuscated_text if ch not in ("\u200b", "\u200c", "\u200d", "\ufeff"))
    assert stripped == original


def test_tag_character_and_bidi_synthesizers():
    """Validates Plane 14 tag injection and Bidirectional RLO override injection."""
    original = "Apple Account Security"
    
    # Tag characters
    tag_res = inject_tag_characters(original, target_brand="Apple", seed=42)
    assert "tag_character_injection" in tag_res.attack_types_applied
    assert any(0xE0001 <= ord(ch) <= 0xE007F for ch in tag_res.obfuscated_text)

    # BiDi override
    bidi_res = inject_bidi_override(original)
    assert "bidi_override" in bidi_res.attack_types_applied
    assert "\u202e" in bidi_res.obfuscated_text


def test_leetspeak_synthesizer_injection():
    """Validates symbol/digit substitutions in target brands."""
    original = "Sign in to your Google Account"
    result = inject_leetspeak(original, target_brand="Google", rate=1.0, seed=42)

    assert isinstance(result, SynthesizedAttackResult)
    assert result.characters_perturbed_count >= 1
    assert "0" in result.obfuscated_text or "@" in result.obfuscated_text
    assert "leetspeak" in result.attack_types_applied


def test_composite_visual_convergence_payload():
    """Core Research Validation: Validates that the synthesized payload exhibits
    Visual-Normalization Convergence:
    R1 != R2, R1 != R3, but R2 == R3.
    """
    payload = synthesize_visual_convergence_payload(
        brand="Microsoft",
        spoof_domain="login.microsoft-auth-verify.xyz",
        seed=42,
    )

    r1 = payload["r1_raw_text"]
    r2 = payload["r2_normalized_text"]
    r3 = payload["r3_visual_text"]

    # 1. Raw diverges from Normalized
    assert r1 != r2, "R1 must differ from R2 due to homoglyph injection"

    # 2. Raw diverges from Visual OCR
    assert r1 != r3, "R1 must differ from visual OCR text"

    # 3. Normalized matches Visual (Deception signature)
    assert unicodedata.normalize("NFKC", r2) == unicodedata.normalize("NFKC", r3)

    # 4. Form inputs and credentials present
    assert payload["has_password_field"] is True
    assert "<form" in payload["raw_html"]
    assert 'type="password"' in payload["raw_html"]


def test_create_synthetic_sample_model():
    """Validates typed DatasetSample wrapper for synthesized attack."""
    sample = create_synthetic_sample(
        sample_id="test-phish-01",
        brand="Netflix",
        spoof_domain="netflix-billing-alert.com",
        seed=101,
    )

    assert isinstance(sample, DatasetSample)
    assert sample.label == 1
    assert sample.brand == "Netflix"
    assert sample.is_obfuscated is True
    assert sample.attack_type == "visual_normalization_convergence"
    assert "netflix-billing-alert.com" in sample.url


def test_generate_dataset_corpus_stratification():
    """Validates generation of a balanced, diverse research corpus."""
    n_samples = 40
    corpus = generate_dataset_corpus(n_samples=n_samples, phishing_ratio=0.5, seed=42)

    assert len(corpus) == n_samples
    phishing = [s for s in corpus if s.label == 1]
    benign = [s for s in corpus if s.label == 0]

    assert len(phishing) == 20
    assert len(benign) == 20

    # Ensure diversity of attack types
    attack_types = {s.attack_type for s in phishing if s.attack_type}
    assert "visual_normalization_convergence" in attack_types
    assert "homoglyph_substitution" in attack_types

    # Ensure localized benign domains are present
    assert any(s.provenance.get("is_localized", False) for s in benign)


def test_create_stratified_splits():
    """Validates exact stratified partitioning across train, val, and test splits."""
    corpus = generate_dataset_corpus(n_samples=40, phishing_ratio=0.5, seed=42)
    splits = create_stratified_splits(corpus, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, seed=42)

    assert set(splits.keys()) == {"train", "val", "test"}

    train_split = splits["train"]
    val_split = splits["val"]
    test_split = splits["test"]

    # Total counts: 40 * 0.70 = 28, 40 * 0.15 = 6, 40 * 0.15 = 6
    assert train_split.samples_count == 28
    assert train_split.phishing_count == 14
    assert train_split.benign_count == 14

    assert val_split.samples_count == 6
    assert val_split.phishing_count == 3
    assert val_split.benign_count == 3

    assert test_split.samples_count == 6
    assert test_split.phishing_count == 3
    assert test_split.benign_count == 3


def test_save_and_load_splits_disk(tmp_path):
    """Validates serializing dataset splits to JSON and restoring them with full integrity."""
    corpus = generate_dataset_corpus(n_samples=20, phishing_ratio=0.5, seed=42)
    splits = create_stratified_splits(corpus, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, seed=42)

    output_dir = str(tmp_path / "splits")
    paths = save_splits_to_disk(splits, base_dir=output_dir)

    assert "train" in paths
    assert (tmp_path / "splits" / "train.json").exists()
    assert (tmp_path / "splits" / "val.json").exists()
    assert (tmp_path / "splits" / "test.json").exists()
    assert (tmp_path / "splits" / "summary.json").exists()

    # Load back from disk and verify
    loaded_train = load_split_from_disk("train", base_dir=output_dir)
    assert isinstance(loaded_train, DatasetSplit)
    assert loaded_train.samples_count == splits["train"].samples_count
    assert loaded_train.phishing_count == splits["train"].phishing_count
    assert len(loaded_train.samples) == len(splits["train"].samples)
