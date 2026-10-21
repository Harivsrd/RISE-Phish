"""Adversarial Attack Synthesizers package for RISE-Phish.

Provides automated tools to inject homoglyphs, zero-width characters, tag characters,
bi-directional overrides, and composite visual-convergence representation attacks.
"""
from backend.app.datasets.synthesizers.homoglyphs import (
    LATIN_TO_HOMOGLYPH,
    inject_homoglyphs,
)
from backend.app.datasets.synthesizers.invisible_chars import (
    inject_bidi_override,
    inject_tag_characters,
    inject_zero_width,
)
from backend.app.datasets.synthesizers.leetspeak import inject_leetspeak
from backend.app.datasets.synthesizers.composite import (
    create_synthetic_sample,
    synthesize_visual_convergence_payload,
)
from backend.app.datasets.synthesizers.unseen import (
    inject_combining_diacritics,
    inject_enclosed_alphanumerics,
    inject_math_alphanumerics,
    inject_soft_hyphens,
    synthesize_unseen_chameleon_payload,
    generate_unseen_attack_benchmark_corpus,
)

__all__ = [
    "LATIN_TO_HOMOGLYPH",
    "inject_homoglyphs",
    "inject_zero_width",
    "inject_tag_characters",
    "inject_bidi_override",
    "inject_leetspeak",
    "create_synthetic_sample",
    "synthesize_visual_convergence_payload",
    "inject_combining_diacritics",
    "inject_enclosed_alphanumerics",
    "inject_math_alphanumerics",
    "inject_soft_hyphens",
    "synthesize_unseen_chameleon_payload",
    "generate_unseen_attack_benchmark_corpus",
]
