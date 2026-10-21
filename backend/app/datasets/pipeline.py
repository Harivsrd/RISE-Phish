"""Dataset Pipeline and Split Management for RISE-Phish.

Generates reproducible research datasets containing clean benign samples,
international localized portals, baseline phishing, and sophisticated adversarial
representation attacks with stratified partitioning and provenance tracking.
"""
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import random
from typing import Any, Dict, List, Optional, Tuple

from backend.app.datasets.synthesizers.composite import synthesize_visual_convergence_payload
from backend.app.datasets.synthesizers.homoglyphs import inject_homoglyphs
from backend.app.datasets.synthesizers.invisible_chars import inject_zero_width
from backend.app.datasets.synthesizers.leetspeak import inject_leetspeak
from backend.app.models.schemas import DatasetSample, DatasetSplit

logger = logging.getLogger("rise_phish.datasets")

# Curated authentic benign domains
BENIGN_SEED_DOMAINS = [
    ("google.com", "Google", "https://www.google.com", "Search the world's information."),
    ("microsoft.com", "Microsoft", "https://www.microsoft.com", "Empower every person and organization to achieve more."),
    ("apple.com", "Apple", "https://www.apple.com", "Discover the innovative world of Apple."),
    ("amazon.com", "Amazon", "https://www.amazon.com", "Online shopping for electronics, apparel, and books."),
    ("wikipedia.org", None, "https://www.wikipedia.org", "The Free Encyclopedia that anyone can edit."),
    ("github.com", "GitHub", "https://github.com", "The AI-powered developer platform."),
    ("netflix.com", "Netflix", "https://www.netflix.com", "Watch TV shows and movies anytime, anywhere."),
    ("paypal.com", "PayPal", "https://www.paypal.com", "Send money, make online payments, and transfer money."),
    ("service-public.fr", None, "https://www.service-public.fr", "Le site officiel de l'administration française (portail sécurisé)."),
    ("spiegel.de", None, "https://www.spiegel.de", "Nachrichten, Analysen und Hintergründe aus Politik und Wirtschaft."),
    ("elpais.com", None, "https://elpais.com", "El periódico global de noticias en español."),
    ("stackoverflow.com", None, "https://stackoverflow.com", "Where developers learn, share, and build careers."),
]

# Targeted brands for synthetic attacks
HIGH_PROFILE_TARGET_BRANDS = [
    ("PayPal", "paypal-account-verify.xyz"),
    ("Microsoft", "office365-security-update.xyz"),
    ("Apple", "icloud-security-center.top"),
    ("Google", "google-account-recovery.support"),
    ("Netflix", "netflix-billing-resolve.info"),
    ("Chase", "chase-online-auth.net"),
]


def generate_dataset_corpus(
    n_samples: int = 100,
    phishing_ratio: float = 0.5,
    seed: int = 42,
) -> List[DatasetSample]:
    """Generates a stratified research corpus with benign and adversarial samples.
    
    Args:
        n_samples: Total number of samples to generate.
        phishing_ratio: Proportion of phishing samples (0.0 to 1.0).
        seed: Random seed for deterministic reproducibility.
        
    Returns:
        List of typed DatasetSample instances with complete provenance metadata.
    """
    rng = random.Random(seed)
    n_phishing = int(n_samples * phishing_ratio)
    n_benign = n_samples - n_phishing

    samples: List[DatasetSample] = []

    # 1. Generate Benign Samples
    for i in range(n_benign):
        domain, brand, url, text = BENIGN_SEED_DOMAINS[i % len(BENIGN_SEED_DOMAINS)]
        sample_id = f"benign-{i+1:04d}"
        path = "" if i % 2 == 0 else f"/item/{i}"
        sample_url = f"{url}{path}"

        sample = DatasetSample(
            sample_id=sample_id,
            url=sample_url,
            label=0,
            brand=brand,
            html_content=f"<html><head><title>{brand or domain}</title></head><body><p>{text}</p></body></html>",
            text_content=text,
            is_obfuscated=False,
            attack_type=None,
            provenance={
                "source": "curated_benign_corpus",
                "registered_domain": domain,
                "is_localized": "fr" in domain or "de" in domain or "es" in domain,
            },
        )
        samples.append(sample)

    # 2. Generate Phishing Samples (Baseline + Adversarial Synthesized)
    for i in range(n_phishing):
        brand, spoof_host = HIGH_PROFILE_TARGET_BRANDS[i % len(HIGH_PROFILE_TARGET_BRANDS)]
        sample_id = f"phish-{i+1:04d}"
        sample_seed = seed + i

        # Assign attack variety:
        # 40% Visual-Normalization Convergence
        # 25% Homoglyph injection
        # 15% Zero-width injection
        # 10% Leetspeak
        # 10% Baseline un-obfuscated phishing
        rand_val = rng.random()

        if rand_val < 0.40:
            # Composite visual convergence attack
            payload = synthesize_visual_convergence_payload(
                brand=brand,
                spoof_domain=f"login-{i}-{spoof_host}",
                seed=sample_seed,
            )
            sample = DatasetSample(
                sample_id=sample_id,
                url=payload["url"],
                label=1,
                brand=brand,
                html_content=payload["raw_html"],
                text_content=payload["r1_raw_text"],
                is_obfuscated=True,
                attack_type="visual_normalization_convergence",
                provenance={
                    "technique": "visual_normalization_convergence",
                    "obfuscated_token": payload["obfuscated_token"],
                    "canonical_token": payload["canonical_token"],
                    "seed": sample_seed,
                },
            )

        elif rand_val < 0.65:
            # Homoglyph attack
            base_text = f"Sign in to your {brand} account to confirm your identity"
            attack = inject_homoglyphs(base_text, target_brand=brand, rate=0.6, seed=sample_seed)
            sample_url = f"https://auth.{spoof_host}/signin"
            sample = DatasetSample(
                sample_id=sample_id,
                url=sample_url,
                label=1,
                brand=brand,
                html_content=f"<html><body><h1>{attack.obfuscated_text}</h1><input type='password' name='p'></body></html>",
                text_content=attack.obfuscated_text,
                is_obfuscated=True,
                attack_type="homoglyph_substitution",
                provenance=attack.metadata,
            )

        elif rand_val < 0.80:
            # Zero-width injection
            base_text = f"Security Alert: Your {brand} access has been suspended"
            attack = inject_zero_width(base_text, target_brand=brand, frequency=0.5, seed=sample_seed)
            sample_url = f"https://security.{spoof_host}/restore"
            sample = DatasetSample(
                sample_id=sample_id,
                url=sample_url,
                label=1,
                brand=brand,
                html_content=f"<html><body><h2>{attack.obfuscated_text}</h2><input type='password'></body></html>",
                text_content=attack.obfuscated_text,
                is_obfuscated=True,
                attack_type="zero_width_insertion",
                provenance=attack.metadata,
            )

        elif rand_val < 0.90:
            # Leetspeak obfuscation
            base_text = f"Verify your {brand} credentials now"
            attack = inject_leetspeak(base_text, target_brand=brand, rate=0.8, seed=sample_seed)
            sample_url = f"https://verify.{spoof_host}/auth"
            sample = DatasetSample(
                sample_id=sample_id,
                url=sample_url,
                label=1,
                brand=brand,
                html_content=f"<html><body><h1>{attack.obfuscated_text}</h1></body></html>",
                text_content=attack.obfuscated_text,
                is_obfuscated=True,
                attack_type="leetspeak",
                provenance=attack.metadata,
            )

        else:
            # Baseline un-obfuscated phishing
            clean_text = f"Official {brand} security verification portal"
            sample_url = f"https://signin-{brand.lower()}.{spoof_host}/login"
            sample = DatasetSample(
                sample_id=sample_id,
                url=sample_url,
                label=1,
                brand=brand,
                html_content=f"<html><body><h1>{clean_text}</h1><input type='password'></body></html>",
                text_content=clean_text,
                is_obfuscated=False,
                attack_type="baseline_phishing",
                provenance={"technique": "lexical_domain_spoofing"},
            )

        samples.append(sample)

    # Deterministic shuffle to interleave labels
    rng.shuffle(samples)
    return samples


def create_stratified_splits(
    samples: List[DatasetSample],
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    seed: int = 42,
) -> Dict[str, DatasetSplit]:
    """Partitions samples into stratified train, validation, and test splits."""
    assert abs((train_ratio + val_ratio + test_ratio) - 1.0) < 1e-4, "Ratios must sum to 1.0"

    rng = random.Random(seed)
    phishing_samples = [s for s in samples if s.label == 1]
    benign_samples = [s for s in samples if s.label == 0]

    rng.shuffle(phishing_samples)
    rng.shuffle(benign_samples)

    def _split_list(lst: List[Any]) -> Tuple[List[Any], List[Any], List[Any]]:
        n = len(lst)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)
        train_part = lst[:n_train]
        val_part = lst[n_train:n_train + n_val]
        test_part = lst[n_train + n_val:]
        return train_part, val_part, test_part

    p_train, p_val, p_test = _split_list(phishing_samples)
    b_train, b_val, b_test = _split_list(benign_samples)

    train_set = p_train + b_train
    val_set = p_val + b_val
    test_set = p_test + b_test

    rng.shuffle(train_set)
    rng.shuffle(val_set)
    rng.shuffle(test_set)

    def _make_split(name: str, subset: List[DatasetSample]) -> DatasetSplit:
        p_count = sum(1 for s in subset if s.label == 1)
        b_count = sum(1 for s in subset if s.label == 0)
        return DatasetSplit(
            split_name=name,
            samples_count=len(subset),
            phishing_count=p_count,
            benign_count=b_count,
            samples=subset,
            created_at=datetime.now(timezone.utc),
        )

    return {
        "train": _make_split("train", train_set),
        "val": _make_split("val", val_set),
        "test": _make_split("test", test_set),
    }


def save_splits_to_disk(
    splits: Dict[str, DatasetSplit],
    base_dir: str = "datasets/splits",
) -> Dict[str, str]:
    """Persists dataset splits as JSON files on disk.
    
    Returns:
        Mapping of split name to local file path.
    """
    out_path = Path(base_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    paths: Dict[str, str] = {}

    for name, split in splits.items():
        file_path = out_path / f"{name}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(split.model_dump(mode="json"), f, indent=2, ensure_ascii=False)
        paths[name] = str(file_path)
        logger.info("Saved %s split with %d samples to %s", name, split.samples_count, file_path)

    # Save summary metadata file
    summary_path = out_path / "summary.json"
    summary_data = {
        "total_samples": sum(s.samples_count for s in splits.values()),
        "splits": {
            name: {
                "samples": s.samples_count,
                "phishing": s.phishing_count,
                "benign": s.benign_count,
            }
            for name, s in splits.items()
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    return paths


def load_split_from_disk(
    split_name: str,
    base_dir: str = "datasets/splits",
) -> DatasetSplit:
    """Loads a previously saved dataset split from disk."""
    file_path = Path(base_dir) / f"{split_name}.json"
    if not file_path.exists():
        raise FileNotFoundError(f"Dataset split file not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return DatasetSplit.model_validate(data)
