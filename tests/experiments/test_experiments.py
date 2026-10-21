"""Unit test suite for RISE-Phish Experiments 1-4 & Master Benchmark Protocol (Phase 14).

Validates:
1. Experiment 1: Baseline Classifier training and metric evaluation.
2. Experiment 2: CRCE Discrepancy Engine separation metrics and visual convergence recall.
3. Experiment 3: SLM Dual-Task de-obfuscation and phishing reasoning accuracy.
4. Experiment 4: Master benchmark comparing Baseline vs. Baseline+CRCE vs. SLM vs. Full RISE-Phish.
"""
from pathlib import Path
import pytest

from experiments.baseline.run_baseline_experiment import run_experiment_1
from experiments.crce.run_crce_experiment import run_experiment_2
from experiments.slm.run_slm_experiment import run_experiment_3
from experiments.run_full_system_benchmark import run_full_benchmark


def test_experiment_1_baseline_execution(tmp_path):
    """Validates Experiment 1 execution, metric calculation, and artifact persistence."""
    output_dir = str(tmp_path / "exp1")
    metrics, model_path, results_path = run_experiment_1(output_dir=output_dir)

    assert metrics.accuracy >= 0.80
    assert metrics.f1_score >= 0.80
    assert Path(model_path).exists()
    assert Path(results_path).exists()


def test_experiment_2_crce_execution(tmp_path):
    """Validates Experiment 2 CRCE discrepancy separation and convergence detection metrics."""
    output_dir = str(tmp_path / "exp2")
    results = run_experiment_2(n_samples=40, output_dir=output_dir, seed=42)

    assert results["total_samples"] == 40
    assert results["accuracy"] >= 0.75
    assert results["f1_score"] >= 0.75
    convergence_stats = results["visual_normalization_convergence"]
    assert convergence_stats["convergence_recall"] >= 0.80
    assert Path(output_dir, "experiment_2_results.json").exists()


def test_experiment_3_slm_execution(tmp_path):
    """Validates Experiment 3 SLM Task 1 (Semantic Recovery) and Task 2 (Reasoning) metrics."""
    output_dir = str(tmp_path / "exp3")
    results = run_experiment_3(n_samples=30, output_dir=output_dir, seed=42)

    assert results["total_samples"] == 30
    t1 = results["task_1_semantic_recovery"]
    assert t1["f1_score"] >= 0.80
    assert t1["token_recovery_rate"] >= 0.70

    t2 = results["task_2_phishing_reasoning"]
    assert t2["f1_score"] >= 0.80
    assert t2["brand_attribution_accuracy"] >= 0.80
    assert Path(output_dir, "experiment_3_results.json").exists()


def test_experiment_4_full_system_benchmark(tmp_path):
    """Validates Experiment 4 master comparison across all 4 configurations and Markdown export."""
    output_dir = str(tmp_path / "reports")
    report = run_full_benchmark(n_samples=40, output_dir=output_dir, seed=42)

    configs = report["configurations"]
    assert "baseline_random_forest" in configs
    assert "baseline_augmented_with_crce" in configs
    assert "slm_alone" in configs
    assert "full_rise_phish_system" in configs

    rise = configs["full_rise_phish_system"]
    base = configs["baseline_random_forest"]

    # Research validation: RISE-Phish adversarial recall must match or exceed baseline
    assert rise["adversarial_obfuscated_recall"] >= base["adversarial_obfuscated_recall"]
    assert rise["f1_score"] >= 0.85

    # Check report generation
    assert Path(output_dir, "experiment_results.json").exists()
    assert Path(output_dir, "benchmark_summary.md").exists()
