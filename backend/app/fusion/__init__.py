"""Evidence Fusion module for RISE-Phish.

Combines representation discrepancies, URL risk, Unicode metrics, brand claims,
and SLM reasoning into calibrated threat assessments.
"""
from backend.app.fusion.evidence_fusion import (
    DEFAULT_FUSION_WEIGHTS,
    EvidenceFusionEngine,
    fuse_evidence,
)

__all__ = [
    "EvidenceFusionEngine",
    "fuse_evidence",
    "DEFAULT_FUSION_WEIGHTS",
]
