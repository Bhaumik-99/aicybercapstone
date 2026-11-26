# AI-Based Threat Detection and Prevention System

**Student:** Bhaumik Senwal  
**Roll Number:** 2301730328  
**Coursework:** AI / Cybersecurity Capstone Lab

A reproducible academic prototype for identifying five illustrative network attack types using synthetic enterprise flow metadata. It compares supervised classification and anomaly detection, tests a simplified evasion scenario, provides model explanations, and demonstrates an analyst-led response workflow with privacy and fairness checks.

> **Important:** All traffic is synthetic. Metrics are specific to this experiment and are not claims about real-world detection performance. This is not a production security control.

## Contents

| File | Description |
|---|---|
| `threat_detection_capstone.ipynb` | End-to-end notebook: synthetic data, feature engineering, models, evaluation, evasion, explainability, response guidance, and privacy/fairness checks |
| `design_report.md` | Design report with objectives, threat model, architecture, method, measured results, limitations, and deployment recommendations |
| `requirements.txt` | Python dependencies |
| `outputs/results.json` | Measured metrics from the executed notebook |

## Threats modelled

- DDoS / traffic flooding
- Port scanning / reconnaissance
- Brute-force authentication attempts
- Suspected data exfiltration
- Command-and-control beaconing

## Measured results

The executed experiment used 12,000 synthetic flows (9,000 train / 3,000 test):

| Metric | Result |
|---|---:|
| Random Forest macro-F1 | 0.9940 |
| MLP macro-F1 | 0.9933 |
| Isolation Forest ROC-AUC range | 0.9623–0.9997 |
| Baseline attack recall at strongest tested evasion | 0.605 |
| Augmented-model attack recall at same evasion level | 0.989 |
| Augmented model clean-data macro-F1 | 0.9949 |

The figures are generated from a controlled synthetic distribution and should not be generalized to real networks.

## Run locally

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
jupyter notebook threat_detection_capstone.ipynb
```

Run all notebook cells from top to bottom. A fixed random seed (42) makes the synthetic dataset and split reproducible. Figures and a refreshed `outputs/results.json` are written during execution.

## Models and evaluation

- **Random Forest:** primary multi-class classifier.
- **MLP:** neural-network baseline with feature standardisation.
- **Isolation Forest:** unsupervised anomaly detector trained on normal-only traffic.

Evaluation includes accuracy, macro-F1, per-class precision/recall/F1, confusion matrix, anomaly ROC-AUC, attack recall under simulated evasion, global permutation importance, a local explanation, and false-positive comparison by time of day.

## Security and privacy notes

The response playbook is advisory and does not make network changes. Any disruptive action requires review and approval by an authorised analyst. The privacy section uses synthetic identifiers and pseudonymisation as a demonstration; production keys must be stored and rotated securely, and pseudonymised records should still be treated as potentially sensitive.

## Limitations

The traffic distributions are simplified, the holdout is random rather than chronological, the evasion simulation covers only a narrow set of features, and model scores are not calibrated incident probabilities. Operational use would require authorised real telemetry, time-based validation, drift monitoring, analyst review, and legal/privacy assessment.

## Reference

This submission follows the broad capstone theme and topic coverage of [Ai-Cyber-Assignment-326](https://github.com/varunkasnia/Ai-Cyber-Assignment-326). The notebook, report, and results in this repository have been rewritten/reworked for this submission; the experiment uses synthetic data.
