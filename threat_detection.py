#!/usr/bin/env python3
"""AI-Based Threat Detection and Prevention System.

Reproducible academic demo using synthetic network-flow metadata only.
This script does not inspect live traffic or block network connections.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score
)
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

SEED = 42
LABELS = ["Normal", "DDoS", "PortScan", "BruteForce", "DataExfil", "C2Beacon"]
FEATURES = [
    "duration", "bytes_sent", "bytes_received", "packets", "syn_rate",
    "unique_dst_ports", "failed_logins", "connections_per_minute",
    "beacon_jitter", "dns_entropy", "outbound_mb", "off_hours",
    "destination_risk"
]


def generate_synthetic_flows(n_per_class: dict[str, int], seed: int = SEED) -> pd.DataFrame:
    """Create labelled toy flow data; distributions are illustrative, not realistic."""
    rng = np.random.default_rng(seed)
    frames = []

    def clipped_normal(mean, sd, n, low=0):
        return np.clip(rng.normal(mean, sd, n), low, None)

    for label, n in n_per_class.items():
        if label == "Normal":
            d = {
                "duration": clipped_normal(35, 18, n, 1),
                "bytes_sent": clipped_normal(18000, 9000, n, 100),
                "bytes_received": clipped_normal(26000, 12000, n, 100),
                "packets": clipped_normal(180, 70, n, 2),
                "syn_rate": clipped_normal(2, 1.2, n),
                "unique_dst_ports": rng.poisson(2, n),
                "failed_logins": rng.poisson(0.15, n),
                "connections_per_minute": clipped_normal(8, 4, n),
                "beacon_jitter": clipped_normal(8, 4, n),
                "dns_entropy": clipped_normal(2.5, 0.7, n),
                "outbound_mb": clipped_normal(1.5, 1.0, n),
                "off_hours": rng.binomial(1, 0.14, n),
                "destination_risk": rng.beta(1.2, 8, n),
            }
        elif label == "DDoS":
            d = {
                "duration": clipped_normal(3, 2, n, 0.1),
                "bytes_sent": clipped_normal(90000, 30000, n, 100),
                "bytes_received": clipped_normal(3000, 2000, n, 100),
                "packets": clipped_normal(1800, 500, n, 2),
                "syn_rate": clipped_normal(95, 20, n),
                "unique_dst_ports": rng.poisson(2, n),
                "failed_logins": rng.poisson(0.1, n),
                "connections_per_minute": clipped_normal(500, 120, n),
                "beacon_jitter": clipped_normal(15, 8, n),
                "dns_entropy": clipped_normal(2, 0.6, n),
                "outbound_mb": clipped_normal(8, 4, n),
                "off_hours": rng.binomial(1, 0.25, n),
                "destination_risk": rng.beta(2, 5, n),
            }
        elif label == "PortScan":
            d = {
                "duration": clipped_normal(1.5, 1, n, 0.1),
                "bytes_sent": clipped_normal(1200, 700, n, 50),
                "bytes_received": clipped_normal(500, 350, n, 20),
                "packets": clipped_normal(12, 6, n, 1),
                "syn_rate": clipped_normal(18, 6, n),
                "unique_dst_ports": rng.poisson(35, n),
                "failed_logins": rng.poisson(0.2, n),
                "connections_per_minute": clipped_normal(160, 45, n),
                "beacon_jitter": clipped_normal(20, 10, n),
                "dns_entropy": clipped_normal(2.2, 0.7, n),
                "outbound_mb": clipped_normal(0.2, 0.15, n),
                "off_hours": rng.binomial(1, 0.35, n),
                "destination_risk": rng.beta(2, 5, n),
            }
        elif label == "BruteForce":
            d = {
                "duration": clipped_normal(5, 3, n, 0.1),
                "bytes_sent": clipped_normal(2500, 1200, n, 50),
                "bytes_received": clipped_normal(900, 500, n, 20),
                "packets": clipped_normal(35, 15, n, 1),
                "syn_rate": clipped_normal(5, 3, n),
                "unique_dst_ports": rng.poisson(1, n),
                "failed_logins": rng.poisson(18, n),
                "connections_per_minute": clipped_normal(55, 18, n),
                "beacon_jitter": clipped_normal(12, 6, n),
                "dns_entropy": clipped_normal(2, 0.6, n),
                "outbound_mb": clipped_normal(0.15, 0.1, n),
                "off_hours": rng.binomial(1, 0.45, n),
                "destination_risk": rng.beta(2, 5, n),
            }
        elif label == "DataExfil":
            d = {
                "duration": clipped_normal(95, 35, n, 1),
                "bytes_sent": clipped_normal(900000, 250000, n, 100),
                "bytes_received": clipped_normal(12000, 8000, n, 100),
                "packets": clipped_normal(1200, 350, n, 2),
                "syn_rate": clipped_normal(1.5, 1, n),
                "unique_dst_ports": rng.poisson(1, n),
                "failed_logins": rng.poisson(0.2, n),
                "connections_per_minute": clipped_normal(3, 2, n),
                "beacon_jitter": clipped_normal(18, 8, n),
                "dns_entropy": clipped_normal(3.8, 0.8, n),
                "outbound_mb": clipped_normal(850, 220, n),
                "off_hours": rng.binomial(1, 0.65, n),
                "destination_risk": rng.beta(3, 3, n),
            }
        else:  # C2Beacon
            d = {
                "duration": clipped_normal(12, 4, n, 0.2),
                "bytes_sent": clipped_normal(1800, 500, n, 50),
                "bytes_received": clipped_normal(2200, 600, n, 50),
                "packets": clipped_normal(20, 5, n, 1),
                "syn_rate": clipped_normal(1, 0.5, n),
                "unique_dst_ports": rng.poisson(1, n),
                "failed_logins": rng.poisson(0.1, n),
                "connections_per_minute": clipped_normal(5, 1, n),
                "beacon_jitter": clipped_normal(0.6, 0.25, n, 0.01),
                "dns_entropy": clipped_normal(4.5, 0.7, n),
                "outbound_mb": clipped_normal(0.08, 0.04, n),
                "off_hours": rng.binomial(1, 0.55, n),
                "destination_risk": rng.beta(4, 2, n),
            }
        frame = pd.DataFrame(d)
        frame["label"] = label
        frames.append(frame)

    data = pd.concat(frames, ignore_index=True)
    # Make a small fraction of attack records less separable from normal traffic.
    attack_idx = data.index[data["label"] != "Normal"].to_numpy()
    blend_idx = rng.choice(attack_idx, size=max(1, int(0.12 * len(attack_idx))), replace=False)
    normal = data.loc[data["label"] == "Normal", FEATURES].median()
    for col in FEATURES:
        data.loc[blend_idx, col] = (
            0.55 * data.loc[blend_idx, col] + 0.45 * normal[col]
        )
    return data.sample(frac=1, random_state=seed).reset_index(drop=True)


def binary_metrics(y_true, y_pred) -> dict:
    actual = np.asarray(y_true) != "Normal"
    predicted = np.asarray(y_pred) != "Normal"
    tn, fp, fn, tp = confusion_matrix(actual, predicted, labels=[False, True]).ravel()
    return {
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "precision": float(precision_score(actual, predicted, zero_division=0)),
        "recall": float(recall_score(actual, predicted, zero_division=0)),
        "f1": float(f1_score(actual, predicted, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
    }


def save_confusion_matrix(y_true, y_pred, out: Path) -> None:
    cm = confusion_matrix(y_true, y_pred, labels=LABELS)
    fig, ax = plt.subplots(figsize=(9, 7))
    image = ax.imshow(cm, interpolation="nearest")
    ax.figure.colorbar(image, ax=ax)
    ax.set(xticks=np.arange(len(LABELS)), yticks=np.arange(len(LABELS)),
           xticklabels=LABELS, yticklabels=LABELS,
           ylabel="Actual", xlabel="Predicted", title="Random Forest confusion matrix")
    plt.setp(ax.get_xticklabels(), rotation=35, ha="right")
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center")
    fig.tight_layout()
    fig.savefig(out / "confusion_matrix.png", dpi=160)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="outputs", help="Directory for reports and plots")
    parser.add_argument("--save-csv", action="store_true", help="Also save generated synthetic data")
    args = parser.parse_args()
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    data = generate_synthetic_flows({
        "Normal": 8000, "DDoS": 1000, "PortScan": 1000,
        "BruteForce": 1000, "DataExfil": 600, "C2Beacon": 400
    })
    if args.save_csv:
        data.to_csv(out / "synthetic_network_flows.csv", index=False)

    X, y = data[FEATURES], data["label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=SEED, stratify=y
    )

    rf = RandomForestClassifier(
        n_estimators=250, class_weight="balanced_subsample",
        random_state=SEED, n_jobs=-1
    )
    rf.fit(X_train, y_train)
    rf_pred = rf.predict(X_test)

    mlp = make_pipeline(
        StandardScaler(),
        MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=350,
                      early_stopping=True, random_state=SEED)
    )
    mlp.fit(X_train, y_train)
    mlp_pred = mlp.predict(X_test)

    # Fit the anomaly detector on normal training examples only.
    normal_train = X_train[y_train == "Normal"]
    iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=SEED)
    iso.fit(normal_train)
    iso_scores = -iso.decision_function(X_test)
    anomaly_auc = {}
    for label in LABELS[1:]:
        truth = (y_test == label).astype(int)
        anomaly_auc[label] = float(roc_auc_score(truth, iso_scores))

    # Feature-level evasion: move selected attack features toward the normal median.
    normal_median = normal_train.median()
    attack_mask = y_test != "Normal"
    attack_X = X_test.loc[attack_mask].copy()
    epsilons = [0.0, 0.25, 0.5, 0.75]
    baseline_recall, robust_recall = [], []
    augmented_rows, augmented_labels = [], []
    for epsilon in epsilons:
        perturbed = attack_X.copy()
        perturbed.loc[:, FEATURES] = (
            (1 - epsilon) * perturbed[FEATURES]
            + epsilon * normal_median[FEATURES]
        )
        baseline_recall.append(float(recall_score(
            np.ones(len(perturbed)), (rf.predict(perturbed) != "Normal").astype(int),
            zero_division=0
        )))
        if epsilon > 0:
            augmented_rows.append(perturbed)
            augmented_labels.append(y_test.loc[attack_mask])

    X_aug = pd.concat([X_train] + augmented_rows, ignore_index=True)
    y_aug = pd.concat([y_train] + augmented_labels, ignore_index=True)
    robust_rf = RandomForestClassifier(
        n_estimators=250, class_weight="balanced_subsample",
        random_state=SEED, n_jobs=-1
    )
    robust_rf.fit(X_aug, y_aug)
    for epsilon in epsilons:
        perturbed = attack_X.copy()
        perturbed.loc[:, FEATURES] = (
            (1 - epsilon) * perturbed[FEATURES]
            + epsilon * normal_median[FEATURES]
        )
        robust_recall.append(float(recall_score(
            np.ones(len(perturbed)),
            (robust_rf.predict(perturbed) != "Normal").astype(int),
            zero_division=0
        )))

    # Explanations: permutation importance and one example's deviations.
    perm = permutation_importance(
        rf, X_test, y_test, n_repeats=5, random_state=SEED,
        scoring="f1_macro", n_jobs=-1
    )
    importance = pd.Series(perm.importances_mean, index=FEATURES).sort_values()
    fig, ax = plt.subplots(figsize=(9, 6))
    importance.tail(12).plot(kind="barh", ax=ax)
    ax.set_title("Permutation feature importance (macro-F1)")
    fig.tight_layout()
    fig.savefig(out / "permutation_importance.png", dpi=160)
    plt.close(fig)

    sample = X_test.iloc[[0]]
    z = (sample.iloc[0] - normal_train.mean()) / normal_train.std().replace(0, 1)
    fig, ax = plt.subplots(figsize=(9, 5))
    z.sort_values().plot(kind="barh", ax=ax)
    ax.set_title(f"Example flow deviation from normal profile — predicted {rf.predict(sample)[0]}")
    ax.set_xlabel("Standard deviations from normal-training mean")
    fig.tight_layout()
    fig.savefig(out / "local_explanation.png", dpi=160)
    plt.close(fig)

    save_confusion_matrix(y_test, rf_pred, out)
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(epsilons, baseline_recall, marker="o", label="Baseline")
    ax.plot(epsilons, robust_recall, marker="o", label="Adversarially augmented")
    ax.set(xlabel="Evasion strength (epsilon)", ylabel="Attack recall",
           ylim=(0, 1.05), title="Recall under simulated feature evasion")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "adversarial_recall.png", dpi=160)
    plt.close(fig)

    # Compare false-positive rates for normal records in/out of working hours.
    normal_test = X_test.loc[y_test == "Normal"].copy()
    normal_predictions = rf_pred[y_test.to_numpy() == "Normal"]
    group_metrics = {}
    for group, mask in {
        "working_hours": normal_test["off_hours"].to_numpy() == 0,
        "off_hours": normal_test["off_hours"].to_numpy() == 1
    }.items():
        count = int(mask.sum())
        fp = int(np.sum(normal_predictions[mask] != "Normal"))
        group_metrics[group] = {
            "normal_flows": count,
            "false_positives": fp,
            "false_positive_rate": float(fp / count) if count else 0.0
        }
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(list(group_metrics), [v["false_positive_rate"] for v in group_metrics.values()])
    ax.set(ylabel="False-positive rate", title="Normal-flow false positives by time group")
    fig.tight_layout()
    fig.savefig(out / "fpr_by_time_group.png", dpi=160)
    plt.close(fig)

    results = {
        "student": "Bhaumik Senwal",
        "roll_number": "2301730328",
        "data": {"rows": int(len(data)), "train_rows": int(len(X_train)),
                 "test_rows": int(len(X_test)), "source": "synthetic", "seed": SEED},
        "random_forest": {
            "accuracy": float(accuracy_score(y_test, rf_pred)),
            "macro_f1": float(f1_score(y_test, rf_pred, average="macro")),
            "binary_attack_metrics": binary_metrics(y_test, rf_pred),
            "classification_report": classification_report(
                y_test, rf_pred, labels=LABELS, output_dict=True, zero_division=0
            ),
        },
        "mlp": {
            "accuracy": float(accuracy_score(y_test, mlp_pred)),
            "macro_f1": float(f1_score(y_test, mlp_pred, average="macro")),
        },
        "isolation_forest_roc_auc": anomaly_auc,
        "evasion": {"epsilon": epsilons, "baseline_attack_recall": baseline_recall,
                    "augmented_attack_recall": robust_recall},
        "fairness_diagnostic": group_metrics,
        "caveat": "Synthetic academic demonstration only; not production performance claims."
    }
    (out / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("Random Forest")
    print(classification_report(y_test, rf_pred, zero_division=0))
    print("Binary attack metrics:", json.dumps(results["random_forest"]["binary_attack_metrics"], indent=2))
    print("Isolation Forest ROC-AUC:", json.dumps(anomaly_auc, indent=2))
    print(f"Outputs saved to: {out.resolve()}")


if __name__ == "__main__":
    main()
