"""Multi-representation package for RISE-Phish (R1 - R5).
"""
from backend.app.representations.builder import build_representation_set
from backend.app.representations.normalized import build_normalized_representation
from backend.app.representations.raw import build_raw_representation
from backend.app.representations.semantic import build_semantic_representation
from backend.app.representations.url_repr import build_url_representation
from backend.app.representations.visual import build_visual_representation

__all__ = [
    "build_representation_set",
    "build_raw_representation",
    "build_normalized_representation",
    "build_visual_representation",
    "build_semantic_representation",
    "build_url_representation",
]
