"""Unseen Adversarial Representation Attack Synthesizers for RISE-Phish.

Implements novel, out-of-distribution adversarial evasion vectors withheld
during baseline training to evaluate zero-day representation generalization:
1. Mathematical Alphanumeric Symbols (U+1D400 - U+1D7FF)
2. Soft Hyphens / Discretionary Break Splitting (U+00AD)
3. Combining Diacritical Mark Flooding (U+0300 - U+036F)
4. Enclosed / Circled Alphanumerics (U+24B6 - U+24E9)
5. Multi-Vector Chameleon Composite Payloads
"""
import random
from typing import Any, Dict, List, Optional, Tuple
import unicodedata

from backend.app.models.schemas import DatasetSample, SynthesizedAttackResult

# ============================================================
# UNSEEN CODEPOINT MAPPINGS
# ============================================================

# Mathematical Bold Latin Characters (U+1D400 - U+1D433)
MATH_BOLD_MAP: Dict[str, str] = {
    **{chr(ord('A') + i): chr(0x1D400 + i) for i in range(26)},
    **{chr(ord('a') + i): chr(0x1D41A + i) for i in range(26)},
}

# Circled Enclosed Alphanumerics (U+24B6 - U+24E9)
CIRCLED_MAP: Dict[str, str] = {
    **{chr(ord('A') + i): chr(0x24B6 + i) for i in range(26)},
    **{chr(ord('a') + i): chr(0x24D0 + i) for i in range(26)},
}

# Combining Diacritical Overlays
COMBINING_OVERLAYS: List[str] = [
    "\u0336",  # COMBINING LONG STROKE OVERLAY (strikethrough)
    "\u0335",  # COMBINING SHORT STROKE OVERLAY
    "\u0304",  # COMBINING MACRON
    "\u0303",  # COMBINING TILDE
    "\u0308",  # COMBINING DIAERESIS
]

SOFT_HYPHEN = "\u00ad"


def inject_math_alphanumerics(
    text: str,
    target_brand: Optional[str] = None,
    rate: float = 0.8,
    seed: Optional[int] = None,
) -> SynthesizedAttackResult:
    """Replaces standard Latin characters with Mathematical Bold symbols.
    
    Under NFKC normalization, these collapse cleanly to standard Latin,
    and visual OCR renders standard bold font, but tokenizers fail.
    """
    rng = random.Random(seed) if seed is not None else random.Random()
    chars = list(text)
    perturbed: List[Tuple[int, str, str]] = []

    if target_brand and target_brand.lower() in text.lower():
        lower_text = text.lower()
        brand_len = len(target_brand)
        start = 0
        while True:
            idx = lower_text.find(target_brand.lower(), start)
            if idx == -1:
                break
            for i in range(idx, idx + brand_len):
                orig_ch = chars[i]
                if orig_ch in MATH_BOLD_MAP and rng.random() <= rate:
                    rep = MATH_BOLD_MAP[orig_ch]
                    chars[i] = rep
                    perturbed.append((i, orig_ch, rep))
            start = idx + brand_len
    else:
        for i, ch in enumerate(chars):
            if ch in MATH_BOLD_MAP and rng.random() <= rate:
                rep = MATH_BOLD_MAP[ch]
                chars[i] = rep
                perturbed.append((i, ch, rep))

    # Guarantee at least 1 mutation if target exists
    if not perturbed and rate > 0.0:
        for i, ch in enumerate(chars):
            if ch in MATH_BOLD_MAP:
                rep = MATH_BOLD_MAP[ch]
                chars[i] = rep
                perturbed.append((i, ch, rep))
                break

    obfuscated_str = "".join(chars)
    perturbed_count = len(perturbed)
    rate_val = (perturbed_count / max(1, len(text))) if text else 0.0
    return SynthesizedAttackResult(
        original_text=text,
        obfuscated_text=obfuscated_str,
        attack_types_applied=["math_alphanumeric_substitution"],
        characters_perturbed_count=perturbed_count,
        perturbation_rate=round(rate_val, 4),
        metadata={
            "technique": "math_alphanumerics",
            "codepoint_range": "U+1D400-U+1D7FF",
            "perturbed_count": perturbed_count,
            "target_brand": target_brand,
            "seed": seed,
        },
    )


def inject_soft_hyphens(
    text: str,
    target_brand: Optional[str] = None,
    frequency: float = 0.5,
    seed: Optional[int] = None,
) -> SynthesizedAttackResult:
    """Injects discretionary soft hyphens (U+00AD) between syllables or characters.
    
    Soft hyphens are invisible in browser rendering unless text wraps,
    rendering normally in OCR, but breaking token-based ML feature extractors.
    """
    rng = random.Random(seed) if seed is not None else random.Random()
    perturbed_count = 0

    if target_brand and target_brand.lower() in text.lower():
        lower_text = text.lower()
        brand_len = len(target_brand)
        start = 0
        result_parts = []
        last_idx = 0
        while True:
            idx = lower_text.find(target_brand.lower(), start)
            if idx == -1:
                result_parts.append(text[last_idx:])
                break
            result_parts.append(text[last_idx:idx])
            brand_token = text[idx:idx + brand_len]
            # Interleave soft hyphens into the brand token
            fragmented = []
            for j, ch in enumerate(brand_token):
                fragmented.append(ch)
                if j < len(brand_token) - 1 and rng.random() <= frequency:
                    fragmented.append(SOFT_HYPHEN)
                    perturbed_count += 1
            if perturbed_count == 0 and len(brand_token) > 1:
                # Force at least one soft hyphen insertion
                mid = len(brand_token) // 2
                fragmented = list(brand_token[:mid]) + [SOFT_HYPHEN] + list(brand_token[mid:])
                perturbed_count = 1
            result_parts.append("".join(fragmented))
            last_idx = idx + brand_len
            start = last_idx
        obfuscated_str = "".join(result_parts)
    else:
        # Interleave soft hyphens randomly between non-whitespace chars
        result_chars = []
        for i, ch in enumerate(text):
            result_chars.append(ch)
            if i < len(text) - 1 and not ch.isspace() and not text[i+1].isspace() and rng.random() <= frequency:
                result_chars.append(SOFT_HYPHEN)
                perturbed_count += 1
        obfuscated_str = "".join(result_chars)

    rate_val = (perturbed_count / max(1, len(text))) if text else 0.0
    return SynthesizedAttackResult(
        original_text=text,
        obfuscated_text=obfuscated_str,
        attack_types_applied=["soft_hyphen_insertion"],
        characters_perturbed_count=perturbed_count,
        perturbation_rate=round(rate_val, 4),
        metadata={
            "technique": "soft_hyphen_splitting",
            "codepoint": "U+00AD",
            "injected_count": perturbed_count,
            "target_brand": target_brand,
            "seed": seed,
        },
    )


def inject_combining_diacritics(
    text: str,
    target_brand: Optional[str] = None,
    marks_per_char: int = 1,
    seed: Optional[int] = None,
) -> SynthesizedAttackResult:
    """Overlays non-spacing combining marks (e.g. strikethrough U+0336) onto target text.
    
    OCR reads the dominant underlying letter glyph, and NFKD/diacritic filtering
    strips the combining marks to recover clean text, but raw string matching fails.
    """
    rng = random.Random(seed) if seed is not None else random.Random()
    perturbed_count = 0

    if target_brand and target_brand.lower() in text.lower():
        lower_text = text.lower()
        brand_len = len(target_brand)
        start = 0
        result_parts = []
        last_idx = 0
        while True:
            idx = lower_text.find(target_brand.lower(), start)
            if idx == -1:
                result_parts.append(text[last_idx:])
                break
            result_parts.append(text[last_idx:idx])
            brand_token = text[idx:idx + brand_len]
            overlayed = []
            for ch in brand_token:
                overlayed.append(ch)
                for _ in range(marks_per_char):
                    overlayed.append(rng.choice(COMBINING_OVERLAYS))
                    perturbed_count += 1
            result_parts.append("".join(overlayed))
            last_idx = idx + brand_len
            start = last_idx
        obfuscated_str = "".join(result_parts)
    else:
        result_chars = []
        for ch in text:
            result_chars.append(ch)
            if not ch.isspace() and rng.random() <= 0.6:
                result_chars.append(rng.choice(COMBINING_OVERLAYS))
                perturbed_count += 1
        obfuscated_str = "".join(result_chars)

    rate_val = (perturbed_count / max(1, len(text))) if text else 0.0
    return SynthesizedAttackResult(
        original_text=text,
        obfuscated_text=obfuscated_str,
        attack_types_applied=["combining_diacritics_overlay"],
        characters_perturbed_count=perturbed_count,
        perturbation_rate=round(rate_val, 4),
        metadata={
            "technique": "combining_diacritical_marks",
            "codepoint_range": "U+0300-U+036F",
            "injected_count": perturbed_count,
            "target_brand": target_brand,
            "seed": seed,
        },
    )


def inject_enclosed_alphanumerics(
    text: str,
    target_brand: Optional[str] = None,
    rate: float = 0.8,
    seed: Optional[int] = None,
) -> SynthesizedAttackResult:
    """Substitutes standard characters with circled enclosed alphanumerics (U+24B6-U+24E9)."""
    rng = random.Random(seed) if seed is not None else random.Random()
    chars = list(text)
    perturbed: List[Tuple[int, str, str]] = []

    if target_brand and target_brand.lower() in text.lower():
        lower_text = text.lower()
        brand_len = len(target_brand)
        start = 0
        while True:
            idx = lower_text.find(target_brand.lower(), start)
            if idx == -1:
                break
            for i in range(idx, idx + brand_len):
                orig_ch = chars[i]
                if orig_ch in CIRCLED_MAP and rng.random() <= rate:
                    rep = CIRCLED_MAP[orig_ch]
                    chars[i] = rep
                    perturbed.append((i, orig_ch, rep))
            start = idx + brand_len
    else:
        for i, ch in enumerate(chars):
            if ch in CIRCLED_MAP and rng.random() <= rate:
                rep = CIRCLED_MAP[ch]
                chars[i] = rep
                perturbed.append((i, ch, rep))

    if not perturbed and rate > 0.0:
        for i, ch in enumerate(chars):
            if ch in CIRCLED_MAP:
                rep = CIRCLED_MAP[ch]
                chars[i] = rep
                perturbed.append((i, ch, rep))
                break

    obfuscated_str = "".join(chars)
    perturbed_count = len(perturbed)
    rate_val = (perturbed_count / max(1, len(text))) if text else 0.0
    return SynthesizedAttackResult(
        original_text=text,
        obfuscated_text=obfuscated_str,
        attack_types_applied=["enclosed_alphanumeric_substitution"],
        characters_perturbed_count=perturbed_count,
        perturbation_rate=round(rate_val, 4),
        metadata={
            "technique": "enclosed_alphanumerics",
            "codepoint_range": "U+24B6-U+24E9",
            "perturbed_count": perturbed_count,
            "target_brand": target_brand,
            "seed": seed,
        },
    )


def synthesize_unseen_chameleon_payload(
    brand: str,
    spoof_domain: str,
    seed: Optional[int] = None,
) -> Dict[str, Any]:
    """Generates a composite zero-day payload combining math alphanumerics and soft hyphens."""
    rng = random.Random(seed) if seed is not None else random.Random()
    
    # 1. First inject mathematical alphanumerics into brand
    math_res = inject_math_alphanumerics(brand, target_brand=brand, rate=0.7, seed=seed)
    
    # 2. Then inject soft hyphens into the partially perturbed token
    hybrid_res = inject_soft_hyphens(math_res.obfuscated_text, frequency=0.5, seed=(seed + 1) if seed else None)
    
    raw_html = f"""<!DOCTYPE html>
<html>
<head><title>{brand} Authentication Portal</title></head>
<body>
<div class="login-box">
  <h1>Sign In to {hybrid_res.obfuscated_text}</h1>
  <p>Please enter your email and password to verify your account.</p>
  <form action="/login" method="POST">
    <input type="text" name="username" placeholder="Email or Username" />
    <input type="password" name="password" placeholder="Password" />
    <button type="submit">Log In</button>
  </form>
</div>
</body>
</html>"""

    return {
        "url": f"https://security-verify.{spoof_domain}/auth/login",
        "raw_html": raw_html,
        "r1_raw_text": f"Sign In to {hybrid_res.obfuscated_text}\nPlease enter your email and password to verify your account.",
        "obfuscated_token": hybrid_res.obfuscated_text,
        "canonical_token": brand,
        "attack_type": "unseen_chameleon_composite",
        "metadata": {
            "math_perturbed": math_res.characters_perturbed_count,
            "soft_hyphens_inserted": hybrid_res.characters_perturbed_count,
            "seed": seed,
        },
    }


def generate_unseen_attack_benchmark_corpus(
    n_samples: int = 100,
    phishing_ratio: float = 0.5,
    seed: int = 42,
) -> List[DatasetSample]:
    """Generates a dedicated zero-day benchmark corpus containing unseen attacks."""
    from backend.app.datasets.pipeline import BENIGN_SEED_DOMAINS

    # Curated stealthy generic hosts used by adversaries to evade lexical URL filters
    UNSEEN_STEALTH_HOSTS = [
        ("PayPal", "portal-session-sync.net"),
        ("Microsoft", "auth-cdn-assets.com"),
        ("Apple", "cloud-verify-token.org"),
        ("Google", "app-gateway-services.com"),
        ("Netflix", "account-session-ref.net"),
        ("Chase", "client-portal-router.com"),
    ]
    
    rng = random.Random(seed)
    n_phishing = int(n_samples * phishing_ratio)
    n_benign = n_samples - n_phishing

    samples: List[DatasetSample] = []

    # 1. Benign Control Samples (50%)
    for i in range(n_benign):
        domain, brand, url, text = BENIGN_SEED_DOMAINS[i % len(BENIGN_SEED_DOMAINS)]
        sample_id = f"unseen-benign-{i+1:04d}"
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

    # 2. Novel / Unseen Zero-Day Phishing Attacks (50%)
    for i in range(n_phishing):
        brand, spoof_host = UNSEEN_STEALTH_HOSTS[i % len(UNSEEN_STEALTH_HOSTS)]
        sample_id = f"unseen-phish-{i+1:04d}"
        sample_seed = seed + i
        rand_val = rng.random()

        if rand_val < 0.25:
            # Mathematical Alphanumerics
            base_text = f"Sign in to your {brand} Account to keep your session active."
            attack = inject_math_alphanumerics(base_text, target_brand=brand, rate=0.8, seed=sample_seed)
            sample_url = f"https://account-verify.{spoof_host}/auth"
            sample = DatasetSample(
                sample_id=sample_id,
                url=sample_url,
                label=1,
                brand=brand,
                html_content=f"<html><body><h1>{attack.obfuscated_text}</h1><input type='password' name='p'></body></html>",
                text_content=attack.obfuscated_text,
                is_obfuscated=True,
                attack_type="math_alphanumerics",
                provenance={
                    "technique": "math_alphanumerics",
                    "canonical_token": brand,
                    "obfuscated_token": attack.obfuscated_text,
                    "seed": sample_seed,
                },
            )

        elif rand_val < 0.50:
            # Soft-Hyphen Discretionary Breaks
            base_text = f"Urgent: Verify your {brand} account now to prevent suspension."
            attack = inject_soft_hyphens(base_text, target_brand=brand, frequency=0.6, seed=sample_seed)
            sample_url = f"https://security-notice.{spoof_host}/verify"
            sample = DatasetSample(
                sample_id=sample_id,
                url=sample_url,
                label=1,
                brand=brand,
                html_content=f"<html><body><h2>{attack.obfuscated_text}</h2><input type='password'></body></html>",
                text_content=attack.obfuscated_text,
                is_obfuscated=True,
                attack_type="soft_hyphen_break",
                provenance={
                    "technique": "soft_hyphen_break",
                    "canonical_token": brand,
                    "obfuscated_token": attack.obfuscated_text,
                    "seed": sample_seed,
                },
            )

        elif rand_val < 0.75:
            # Combining Diacritical Mark Flooding
            base_text = f"Confirm your {brand} billing details immediately."
            attack = inject_combining_diacritics(base_text, target_brand=brand, marks_per_char=1, seed=sample_seed)
            sample_url = f"https://billing-alert.{spoof_host}/billing"
            sample = DatasetSample(
                sample_id=sample_id,
                url=sample_url,
                label=1,
                brand=brand,
                html_content=f"<html><body><h1>{attack.obfuscated_text}</h1><input type='password'></body></html>",
                text_content=attack.obfuscated_text,
                is_obfuscated=True,
                attack_type="combining_diacritics",
                provenance={
                    "technique": "combining_diacritics",
                    "canonical_token": brand,
                    "obfuscated_token": attack.obfuscated_text,
                    "seed": sample_seed,
                },
            )

        elif rand_val < 0.90:
            # Circled / Enclosed Alphanumerics
            base_text = f"Log in to your {brand} service."
            attack = inject_enclosed_alphanumerics(base_text, target_brand=brand, rate=0.8, seed=sample_seed)
            sample_url = f"https://signin-portal.{spoof_host}/login"
            sample = DatasetSample(
                sample_id=sample_id,
                url=sample_url,
                label=1,
                brand=brand,
                html_content=f"<html><body><h1>{attack.obfuscated_text}</h1><input type='password'></body></html>",
                text_content=attack.obfuscated_text,
                is_obfuscated=True,
                attack_type="enclosed_alphanumerics",
                provenance={
                    "technique": "enclosed_alphanumerics",
                    "canonical_token": brand,
                    "obfuscated_token": attack.obfuscated_text,
                    "seed": sample_seed,
                },
            )

        else:
            # Multi-Vector Zero-Day Chameleon Composite
            payload = synthesize_unseen_chameleon_payload(brand, spoof_host, seed=sample_seed)
            sample = DatasetSample(
                sample_id=sample_id,
                url=payload["url"],
                label=1,
                brand=brand,
                html_content=payload["raw_html"],
                text_content=payload["r1_raw_text"],
                is_obfuscated=True,
                attack_type="unseen_chameleon_composite",
                provenance={
                    "technique": "unseen_chameleon_composite",
                    "canonical_token": payload["canonical_token"],
                    "obfuscated_token": payload["obfuscated_token"],
                    "seed": sample_seed,
                },
            )

        samples.append(sample)

    return samples
