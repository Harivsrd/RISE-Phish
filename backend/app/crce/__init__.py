"""Cross-Representation Discrepancy Engine (CRCE) package.
"""
from backend.app.crce.brand_detector import (
    calculate_brand_domain_discrepancy,
    identify_claimed_brand,
)
from backend.app.crce.discrepancy import evaluate_discrepancies
from backend.app.crce.similarity import (
    calculate_normalized_edit_distance,
    calculate_token_jaccard_divergence,
    find_pairwise_character_mismatches,
)

__all__ = [
    "evaluate_discrepancies",
    "calculate_normalized_edit_distance",
    "calculate_token_jaccard_divergence",
    "find_pairwise_character_mismatches",
    "identify_claimed_brand",
    "calculate_brand_domain_discrepancy",
]
