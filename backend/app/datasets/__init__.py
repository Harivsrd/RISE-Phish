"""Datasets module for RISE-Phish.

Provides dataset generators, stratified train/val/test split managers,
and adversarial representation attack synthesizers.
"""
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

__all__ = [
    "create_stratified_splits",
    "generate_dataset_corpus",
    "load_split_from_disk",
    "save_splits_to_disk",
    "create_synthetic_sample",
    "synthesize_visual_convergence_payload",
    "inject_homoglyphs",
    "inject_zero_width",
    "inject_tag_characters",
    "inject_bidi_override",
    "inject_leetspeak",
]
