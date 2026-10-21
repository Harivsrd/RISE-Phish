"""Cross-Representation Discrepancy Engine (CRCE v1).

Core research module evaluating pairwise divergences between R1 (Raw),
R2 (Normalized), R3 (Visual OCR), and R5 (URL Domain vs Claimed Brand).
"""
from typing import List, Optional

from backend.app.core.logging import logger
from backend.app.crce.brand_detector import (
    calculate_brand_domain_discrepancy,
    identify_claimed_brand,
)
from backend.app.crce.similarity import (
    calculate_normalized_edit_distance,
    calculate_token_jaccard_divergence,
    find_pairwise_character_mismatches,
)
from backend.app.models.schemas import (
    CRCEResult,
    DiscrepancyFinding,
    RepresentationSet,
    UnicodeAnalysisResult,
)


def evaluate_discrepancies(
    rep_set: RepresentationSet,
    unicode_result: Optional[UnicodeAnalysisResult] = None,
    explicit_brand: Optional[str] = None,
) -> CRCEResult:
    """Executes the complete cross-representation discrepancy matrix.

    Evaluates:
    - R1 (Raw) vs R2 (Normalized)
    - R1 (Raw) vs R3 (Visual OCR)
    - R2 (Normalized) vs R3 (Visual OCR)
    - R5 (URL) vs Detected Brand Claims
    - Visual-Normalization Convergence (R1 != R2, R1 != R3, but R2 == R3)

    Args:
        rep_set: Complete 5-layer representation set (R1 - R5).
        unicode_result: Optional pre-computed UnicodeAnalysisResult from Phase 4.
        explicit_brand: Optional explicit brand target to test against.

    Returns:
        Structured CRCEResult containing granular findings and normalized discrepancy metrics.
    """
    logger.info(f"Executing CRCE v1 discrepancy analysis for Job: {rep_set.analysis_id}")
    findings: List[DiscrepancyFinding] = []

    r1_text = rep_set.r1_raw.text or ""
    r2_text = rep_set.r2_normalized.text or ""
    r3_text = rep_set.r3_visual.text or ""
    r3_available = rep_set.r3_visual.available

    # ============================================================
    # 1. PAIRWISE COMPARISON: R1 (Raw) vs R2 (Normalized)
    # ============================================================
    raw_norm_ned = calculate_normalized_edit_distance(r1_text, r2_text)
    raw_norm_jaccard = calculate_token_jaccard_divergence(r1_text, r2_text)
    raw_norm_discrepancy = round(max(raw_norm_ned, raw_norm_jaccard * 0.5), 4)

    if raw_norm_discrepancy > 0.0:
        # Collect character-level mismatch findings
        mismatches = find_pairwise_character_mismatches(
            r1_text, r2_text, "r1_raw", "r2_normalized", max_findings=10
        )
        findings.extend(mismatches)

        for transform in rep_set.r2_normalized.transformations_applied:
            findings.append(
                DiscrepancyFinding(
                    source="r1_raw",
                    target="r2_normalized",
                    discrepancy_type="normalization_divergence",
                    severity=0.75,
                    supporting_evidence=(
                        f"Normalization transformation '{transform}' altered content: "
                        f"{rep_set.r2_normalized.characters_altered_count} character changes recorded."
                    ),
                )
            )

    # ============================================================
    # 2. PAIRWISE COMPARISON: R1 (Raw) vs R3 (Visual OCR)
    # ============================================================
    raw_vis_discrepancy = 0.0
    norm_vis_discrepancy = 0.0
    visual_convergence = False

    if r3_available and r3_text:
        raw_vis_ned = calculate_normalized_edit_distance(r1_text, r3_text)
        raw_vis_jaccard = calculate_token_jaccard_divergence(r1_text, r3_text)
        raw_vis_discrepancy = round(max(raw_vis_ned, raw_vis_jaccard * 0.5), 4)

        # Record findings between raw and visual
        if raw_vis_discrepancy > 0.10:
            mismatches = find_pairwise_character_mismatches(
                r1_text, r3_text, "r1_raw", "r3_visual", max_findings=10
            )
            findings.extend(mismatches)

        # ============================================================
        # 3. PAIRWISE COMPARISON: R2 (Normalized) vs R3 (Visual OCR)
        # ============================================================
        norm_vis_ned = calculate_normalized_edit_distance(r2_text, r3_text)
        norm_vis_jaccard = calculate_token_jaccard_divergence(r2_text, r3_text)
        norm_vis_discrepancy = round(max(norm_vis_ned, norm_vis_jaccard * 0.5), 4)

        # ============================================================
        # 4. RESEARCH HYPOTHESIS: Visual-Normalization Convergence
        # If R1 diverges from R2, and R1 diverges from R3,
        # but R2 closely aligns with R3, this confirms visual spoofing!
        # ============================================================
        if (
            raw_norm_discrepancy > 0.05
            and raw_vis_discrepancy > 0.05
            and norm_vis_discrepancy < 0.20
        ):
            visual_convergence = True
            findings.append(
                DiscrepancyFinding(
                    source="r2_normalized",
                    target="r3_visual",
                    discrepancy_type="visual_normalization_convergence",
                    severity=0.90,
                    supporting_evidence=(
                        f"Cross-Representation Deception Signature Confirmed: "
                        f"Raw DOM diverges from visual rendering (NED: {raw_vis_discrepancy}), "
                        f"but Normalized text converges with Visual OCR (NED: {norm_vis_discrepancy}). "
                        f"The webpage was crafted to appear benign to human eyes while obfuscating DOM tokens."
                    ),
                )
            )

    # ============================================================
    # 5. BRAND vs DOMAIN DISCREPANCY (R5 vs Detected Brand)
    # ============================================================
    # Search across visible text, semantic title, and headings
    searchable_brand_text = f"{rep_set.r4_semantic.title or ''} {rep_set.r4_semantic.headings_text} {r2_text[:500]}"
    detected_brand = identify_claimed_brand(searchable_brand_text, explicit_brand)

    url_brand_discrepancy = 0.0
    if detected_brand:
        url_brand_discrepancy, brand_finding = calculate_brand_domain_discrepancy(
            detected_brand, rep_set.r5_url
        )
        if brand_finding:
            findings.append(brand_finding)

    # Incorporate Phase 4 Unicode anomaly score
    unicode_score = unicode_result.unicode_anomaly_score if unicode_result else 0.0

    # ============================================================
    # 6. OVERALL DISCREPANCY SCORE COMPOSITION
    # Weighted multi-modal synthesis without arbitrary hard-coding
    # ============================================================
    discrepancy_components = [
        raw_norm_discrepancy * 0.25,
        raw_vis_discrepancy * 0.25 if r3_available else 0.0,
        url_brand_discrepancy * 0.30,
        unicode_score * 0.20,
    ]
    base_discrepancy = sum(discrepancy_components)

    # If visual-normalization convergence is proven, elevate discrepancy weight
    if visual_convergence:
        base_discrepancy = min(1.0, base_discrepancy + 0.25)

    overall_discrepancy = round(min(1.0, max(0.0, base_discrepancy)), 4)

    # Generate executive summary
    summary_parts = []
    if raw_norm_discrepancy > 0.0:
        summary_parts.append(f"Raw/Normalized divergence: {raw_norm_discrepancy}")
    if visual_convergence:
        summary_parts.append("Visual-Normalization convergence detected (obfuscation signature)")
    if url_brand_discrepancy > 0.5:
        summary_parts.append(f"Brand/Domain mismatch against '{detected_brand}' ({url_brand_discrepancy})")
    if unicode_score > 0.0:
        summary_parts.append(f"Unicode anomaly density: {unicode_score}")

    summary = (
        "; ".join(summary_parts) 
        if summary_parts 
        else "Representations are consistent across DOM, normalized text, visual rendering, and domain."
    )

    return CRCEResult(
        raw_normalized_discrepancy=raw_norm_discrepancy,
        raw_visual_discrepancy=raw_vis_discrepancy,
        normalized_visual_discrepancy=norm_vis_discrepancy,
        url_brand_discrepancy=url_brand_discrepancy,
        unicode_anomaly_score=unicode_score,
        overall_discrepancy=overall_discrepancy,
        visual_normalization_convergence=visual_convergence,
        findings=findings,
        summary=summary,
    )
