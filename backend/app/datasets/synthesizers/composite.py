"""Composite Adversarial Webpage Synthesizer for RISE-Phish.

Generates complete, realistic phishing webpage payloads engineered to exhibit the
Visual-Normalization Convergence deception signature:
- R1 (Raw DOM) != R2 (Normalized)
- R1 (Raw DOM) != R3 (Visual OCR)
- R2 (Normalized) == R3 (Visual OCR)
"""
from typing import Any, Dict, Optional
import unicodedata

from backend.app.datasets.synthesizers.homoglyphs import inject_homoglyphs
from backend.app.datasets.synthesizers.invisible_chars import inject_zero_width
from backend.app.models.schemas import DatasetSample


def synthesize_visual_convergence_payload(
    brand: str = "PayPal",
    spoof_domain: str = "secure-login.paypal-verification-alert.xyz",
    path: str = "/signin",
    seed: Optional[int] = 42,
) -> Dict[str, Any]:
    """Generates a synthetic webpage payload exhibiting the Visual-Normalization Convergence signature.
    
    Returns:
        Dictionary containing raw HTML, R1-R5 representations, and ground-truth metadata.
    """
    clean_brand = brand
    # Inject Cyrillic homoglyph lookalikes into the brand token
    homoglyph_attack = inject_homoglyphs(clean_brand, target_brand=clean_brand, rate=0.5, seed=seed)
    obfuscated_brand = homoglyph_attack.obfuscated_text

    raw_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{obfuscated_brand} - Account Verification Center</title>
</head>
<body>
    <header>
        <h1>Welcome to {obfuscated_brand}</h1>
    </header>
    <main>
        <p>Urgent Security Notification: We detected unusual sign-in activity on your {obfuscated_brand} account.</p>
        <p>Please re-authenticate with your {obfuscated_brand} credentials to restore full access.</p>
        <form action="https://{spoof_domain}/api/capture" method="POST">
            <label for="email">Email Address:</label>
            <input type="text" id="email" name="email" placeholder="Email or mobile number" required>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" placeholder="Password" required>
            <button type="submit">Log In to {obfuscated_brand}</button>
        </form>
    </main>
    <footer>
        <p>&copy; 2026 {obfuscated_brand} Corporation. All rights reserved.</p>
    </footer>
</body>
</html>"""

    raw_text = (
        f"Welcome to {obfuscated_brand} Urgent Security Notification: "
        f"We detected unusual sign-in activity on your {obfuscated_brand} account. "
        f"Please re-authenticate with your {obfuscated_brand} credentials to restore full access. "
        f"Log In to {obfuscated_brand} © 2026 {obfuscated_brand} Corporation. All rights reserved."
    )

    # R2: Normalized representation (zero-width stripped, homoglyphs traceably resolved to canonical form)
    normalized_text = raw_text.replace(obfuscated_brand, clean_brand)

    # R3: Visual representation (what human eyes and OCR see on rasterized screenshot)
    visual_text = raw_text.replace(obfuscated_brand, clean_brand)

    target_url = f"https://{spoof_domain}{path}"

    return {
        "url": target_url,
        "registered_domain": spoof_domain.split(".")[-2] + "." + spoof_domain.split(".")[-1],
        "claimed_brand": clean_brand,
        "raw_html": raw_html,
        "r1_raw_text": raw_text,
        "r2_normalized_text": normalized_text,
        "r3_visual_text": visual_text,
        "has_password_field": True,
        "form_count": 1,
        "is_phishing": 1,
        "attack_type": "visual_normalization_convergence",
        "obfuscated_token": obfuscated_brand,
        "canonical_token": clean_brand,
    }


def create_synthetic_sample(
    sample_id: str,
    brand: str = "PayPal",
    spoof_domain: str = "secure-login.paypal-verification-alert.xyz",
    seed: Optional[int] = 42,
) -> DatasetSample:
    """Wraps synthesized attack into a typed DatasetSample."""
    payload = synthesize_visual_convergence_payload(brand=brand, spoof_domain=spoof_domain, seed=seed)
    return DatasetSample(
        sample_id=sample_id,
        url=payload["url"],
        label=1,
        brand=brand,
        html_content=payload["raw_html"],
        text_content=payload["r1_raw_text"],
        is_obfuscated=True,
        attack_type=payload["attack_type"],
        provenance={
            "synthetic_generator": "synthesize_visual_convergence_payload",
            "spoofed_domain": spoof_domain,
            "obfuscated_token": payload["obfuscated_token"],
            "seed": seed,
        },
    )
