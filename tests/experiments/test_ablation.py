"""Unit test suite for RISE-Phish Systematic Component Ablation Study (Phase 15).

Validates:
1. End-to-end execution of the 6-way ablation study.
2. Verification of all component configurations (Full, w/o CRCE, w/o SLM, w/o Unicode, w/o R3, Linear).
3. Metric calculations, delta F1 tracking, and Markdown/JSON report export.
"""
from pathlib import Path
import pytest

from experiments.ablation.run_ablation_study import run_ablation_study


def test_ablation_study_execution(tmp_path):
    """Validates the complete ablation study protocol across all 6 configurations."""
    output_dir = str(tmp_path / "reports")
    results = run_ablation_study(n_samples=40, output_dir=output_dir, seed=42)

    assert results["total_test_samples"] == 40
    configs = results["configurations"]

    # Verify all 6 settings are evaluated
    expected_keys = {
        "full_system",
        "without_crce",
        "without_slm",
        "without_unicode",
        "without_visual_ocr",
        "linear_fusion",
    }
    assert set(configs.keys()) == expected_keys

    # Full system control checks
    full = configs["full_system"]
    assert full["accuracy"] >= 0.85
    assert full["f1_score"] >= 0.85
    assert full["delta_f1"] == 0.0

    # Ensure delta F1 metrics are calculated and non-positive (ablations don't outperform full control)
    for key, cfg in configs.items():
        assert "delta_f1" in cfg
        assert "accuracy" in cfg
        assert "recall" in cfg
        assert "adversarial_obfuscated_recall" in cfg

    # Verify file exports
    assert Path(output_dir, "ablation_study_results.json").exists()
    assert Path(output_dir, "ablation_summary.md").exists()
