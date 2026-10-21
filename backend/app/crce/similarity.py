"""String similarity and character discrepancy metrics for CRCE.

Utilizes RapidFuzz Levenshtein distance, token-level Jaccard divergence,
and character alignment to locate granular representation inconsistencies.
"""
import re
from typing import List, Optional, Set, Tuple
from rapidfuzz.distance import Levenshtein

from backend.app.models.schemas import DiscrepancyFinding


def calculate_normalized_edit_distance(s1: str, s2: str) -> float:
    """Calculates Normalized Edit Distance (NED) between two strings.
    
    Formula: NED(s1, s2) = Levenshtein(s1, s2) / max(len(s1), len(s2), 1)
    Bounded in [0.0, 1.0].
    """
    if not s1 and not s2:
        return 0.0
    if not s1 or not s2:
        return 1.0

    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 0.0

    dist = Levenshtein.distance(s1, s2)
    return round(min(1.0, dist / max_len), 4)


def calculate_token_jaccard_divergence(s1: str, s2: str) -> float:
    """Calculates token-level Jaccard set divergence: 1.0 - Jaccard(T1, T2).
    
    Returns 0.0 when tokens match identically, 1.0 when disjoint.
    """
    t1 = set(re.findall(r"\w+", (s1 or "").lower()))
    t2 = set(re.findall(r"\w+", (s2 or "").lower()))

    if not t1 and not t2:
        return 0.0
    if not t1 or not t2:
        return 1.0

    intersection = len(t1 & t2)
    union = len(t1 | t2)
    if union == 0:
        return 0.0

    jaccard_sim = intersection / union
    return round(1.0 - jaccard_sim, 4)


def find_pairwise_character_mismatches(
    s1: str,
    s2: str,
    source_name: str,
    target_name: str,
    max_findings: int = 25,
) -> List[DiscrepancyFinding]:
    """Pinpoints specific character discrepancies between two representation strings.

    Args:
        s1: Source representation text.
        s2: Target representation text.
        source_name: Name label (e.g., 'r1_raw').
        target_name: Name label (e.g., 'r2_normalized').
        max_findings: Cap on granular findings to prevent flood.

    Returns:
        List of structured DiscrepancyFinding records.
    """
    findings: List[DiscrepancyFinding] = []
    if not s1 and not s2:
        return findings

    # Check for general length divergence
    if abs(len(s1) - len(s2)) > 0:
        findings.append(
            DiscrepancyFinding(
                source=source_name,
                target=target_name,
                discrepancy_type="length_discrepancy",
                severity=round(min(1.0, abs(len(s1) - len(s2)) / max(len(s1), len(s2), 1)), 4),
                supporting_evidence=(
                    f"Length mismatch: {source_name} has {len(s1)} chars, "
                    f"while {target_name} has {len(s2)} chars."
                ),
            )
        )

    # Character-by-character alignment
    min_len = min(len(s1), len(s2))
    for i in range(min_len):
        if len(findings) >= max_findings:
            break

        c1 = s1[i]
        c2 = s2[i]
        if c1 != c2:
            cp1 = f"U+{ord(c1):04X}"
            cp2 = f"U+{ord(c2):04X}"
            findings.append(
                DiscrepancyFinding(
                    source=source_name,
                    target=target_name,
                    discrepancy_type="character_mismatch",
                    position=i,
                    source_character=c1,
                    target_character=c2,
                    severity=0.80,
                    supporting_evidence=(
                        f"Character mismatch at position {i}: '{c1}' ({cp1}) in {source_name} "
                        f"differs from '{c2}' ({cp2}) in {target_name}."
                    ),
                )
            )

    return findings
