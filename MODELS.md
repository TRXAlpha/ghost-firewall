# Models

This project keeps models small and CPU-friendly. It avoids GPU dependencies and is designed to stay under 1GB VRAM.

## Statistical anomaly model (default)
File: `src/ai_firewall/statistical_model.py`

Mechanism:
- Maintains rolling means/variances for each feature.
- Computes per-feature z-scores for a query against the baseline seen so far. Only unusually high values count.
- Without `--model`, the baseline is built from the current log alone and not saved.
- Aggregates z-scores into an anomaly score.
- Applies a light per-domain bias based on feedback.

Pros:
- Very lightweight and explainable.
- No training data required.
- Good for early detection of novel behavior.

Cons:
- Less precise than a trained classifier.
- Sensitive to noisy features if the baseline drifts.

## Online logistic model
File: `src/ai_firewall/online_model.py`

Mechanism:
- Maintains weights updated from user feedback.
- Simple logistic regression with SGD-style updates.

Pros:
- Learns directly from labels.
- Very small footprint.

Cons:
- Needs consistent feedback to converge.
- Still linear.

## TRM/CTM stub
File: `src/ai_firewall/trm_adapter.py`

This is a placeholder for future integration: a fixed-weight linear scorer over features scaled to 0..1, used only when `model_type` is `trm_stub`. It does not learn.

## Configuration
`config/example_config.json`:
- `model_type`: `statistical`, `online_logistic`, or `trm_stub`
- `decision_threshold`: probability threshold for “recommend”
- `zscore_threshold`: baseline sensitivity (statistical)
- `learning_rate`: update size (online logistic)
 - `auto_promote_after`: confirmations required for candidate promotion
 - `auto_promote_decay_days`: decay window for confirmations

## Choosing a model
- Use `statistical` if you want fast, unsupervised anomaly detection.
- Use `online_logistic` if you will regularly label findings.
