# Architecture

This document describes the components, data flow, and design goals of the AI firewall.

## Goals
- Run locally and remain under 1GB VRAM.
- Produce explainable recommendations.
- Learn from explicit user feedback.
- Keep enforcement outside of this project.
- Support endpoint heuristics without invasive actions.

## Components
- Log ingestion: parses Pi-hole/dnsmasq logs into structured DNS queries.
- Feature extraction: computes entropy, length, burstiness, rare TLDs, and per-device novelty.
- Models:
  - Statistical anomaly model (default)
  - Online logistic model (optional)
  - TRM/CTM stub for future integration
- Feedback and policy:
  - Feedback labels update model state
  - Policy state tracks confirmed malicious domains
- Endpoint heuristics:
  - Snapshot ingestion (processes, startup items, tasks, services, connections, event logs)
  - Findings added to report
- Reporting:
  - JSON report for automation
  - Text report for human review

## Data flow
1) Parse DNS log lines into `DNSQuery` events.
2) Compute features and flags.
3) Score each event using the configured model.
4) If feedback is provided and learning is enabled, update the model and policy.
5) Optional endpoint snapshot analysis adds findings to the report.
6) Emit report and optional text output.

## Model selection
`config/example_config.json` controls the model with `model_type`.
- `statistical`: rolling mean/variance and z-score aggregation.
- `online_logistic`: simple, incremental learning.
- `trm_stub`: placeholder, linear scorer.

## Policy and safety
Policy does not enforce blocking. It only emits candidates once they cross confirmation thresholds. Enforce externally after review.

## Files of interest
- `src/ai_firewall/cli.py`: pipeline entry point
- `src/ai_firewall/statistical_model.py`: default model
- `src/ai_firewall/endpoint.py`: endpoint heuristics
- `src/ai_firewall/policy.py`: auto-promotion logic
