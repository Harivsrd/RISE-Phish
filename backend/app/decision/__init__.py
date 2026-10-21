"""Decision Engine module for RISE-Phish.

Translates multi-representation fused evidence into operational verdicts
(SAFE, INVESTIGATE, PHISHING) and automated defensive actions.
"""
from backend.app.decision.risk import (
    POLICY_THRESHOLDS,
    DecisionEngine,
    evaluate_decision,
)

__all__ = [
    "DecisionEngine",
    "evaluate_decision",
    "POLICY_THRESHOLDS",
]
