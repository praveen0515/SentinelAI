#!/usr/bin/env python3
"""
SentinelAI Model Training Script
Extracts 30+ cybersecurity features from HTTP training logs,
trains the scikit-learn Isolation Forest model, evaluates performance,
and persists artifacts to disk.
"""

import os
import sys
import json
import argparse
import numpy as np

# Ensure root directory is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.config import settings
from backend.log_processor import log_processor, LogProcessor
from backend.ml_engine import SentinelAnomalyDetector
from scripts.generate_sample_logs import generate_logs


def train_isolation_forest(
    input_file: str = "data/sample_logs.json",
    sample_count: int = 4000,
    contamination: float = 0.08,
    output_model: str = "data/isolation_forest.joblib"
):
    print("=" * 65)
    print("  SentinelAI Isolation Forest Model Training Pipeline")
    print("=" * 65)

    # 1. Acquire or generate training logs
    logs = []
    if os.path.exists(input_file):
        print(f"[*] Loading training dataset from '{input_file}'...")
        with open(input_file, "r") as f:
            logs = json.load(f)
        print(f"[*] Loaded {len(logs)} log records.")
    else:
        print(f"[*] No existing dataset found. Synthesizing {sample_count} training logs...")
        logs = generate_logs(count=sample_count, anomaly_ratio=contamination)
        os.makedirs(os.path.dirname(input_file), exist_ok=True)
        with open(input_file, "w") as f:
            json.dump(logs, f, indent=2)
        print(f"[*] Generated and saved dataset to '{input_file}'.")

    # 2. Feature Extraction
    print(f"[*] Extracting {len(LogProcessor.FEATURE_NAMES)} features per log entry...")
    feature_matrix = []
    labels = []

    for entry in logs:
        # Ground truth label if simulated
        is_sim_threat = 1 if entry.get("simulated_threat") else 0
        labels.append(is_sim_threat)

        # Parse & extract
        normalized = log_processor.parse_raw_log(entry)
        feats = log_processor.extract_features(normalized)
        row = [feats[name] for name in LogProcessor.FEATURE_NAMES]
        feature_matrix.append(row)

    X = np.array(feature_matrix, dtype=np.float64)
    y = np.array(labels, dtype=np.int32)
    print(f"[*] Feature matrix shape: {X.shape}")
    print(f"[*] Simulated ground-truth anomaly count: {np.sum(y)} ({np.mean(y)*100:.2f}%)")

    # 3. Model Training
    detector = SentinelAnomalyDetector()
    settings.CONTAMINATION_RATE = contamination

    print("\n[*] Training Isolation Forest model...")
    meta = detector.fit(X=X, y=y)

    # 4. Save artifacts
    print(f"[*] Saving model artifact to '{output_model}'...")
    detector.save(output_model)

    # 5. Display Evaluation Summary
    metrics = meta.get("metrics", {})
    print("\n" + "-" * 65)
    print("  TRAINING & VALIDATION PERFORMANCE REPORT")
    print("-" * 65)
    print(f"  Training Samples:      {meta.get('training_samples')}")
    print(f"  Feature Dimensions:    {meta.get('feature_count')}")
    print(f"  Contamination Rate:    {settings.CONTAMINATION_RATE}")
    print(f"  Training Time:         {meta.get('train_duration_sec')}s")
    print(f"  Precision:             {metrics.get('precision', 0):.4f}")
    print(f"  Recall:                {metrics.get('recall', 0):.4f}")
    print(f"  F1 Score:              {metrics.get('f1_score', 0):.4f}")
    print("-" * 65)
    print("[+] Model training pipeline completed successfully!")


def main():
    parser = argparse.ArgumentParser(description="SentinelAI Model Training Utility")
    parser.add_argument("--data", default="data/sample_logs.json", help="Path to input logs JSON")
    parser.add_argument("--count", type=int, default=3500, help="Log count if generating synthetic dataset")
    parser.add_argument("--contamination", type=float, default=0.08, help="Expected anomaly ratio")
    parser.add_argument("--output", default="data/isolation_forest.joblib", help="Output model path")
    args = parser.parse_args()

    train_isolation_forest(
        input_file=args.data,
        sample_count=args.count,
        contamination=args.contamination,
        output_model=args.output
    )


if __name__ == "__main__":
    main()
