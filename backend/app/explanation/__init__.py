"""Explanation module for RISE-Phish.

Produces dual-audience explainability reports (UserAdvisory and AnalystForensicReport).
"""
from backend.app.explanation.explanation_engine import (
    ExplanationEngine,
    generate_explanation,
)

__all__ = [
    "ExplanationEngine",
    "generate_explanation",
]
