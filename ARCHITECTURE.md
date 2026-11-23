# Architecture

This document describes the components, data flow, and design goals of the AI firewall.

## Goals
- Run locally and remain under 1GB VRAM.
- Produce explainable recommendations.
- Learn from explicit user feedback.
- Hand enforcement to Pi-hole through an exported blocklist file.
- Support endpoint heuristics without invasive actions.

## Components
- Log ingestion: parses Pi-hole/dnsmasq logs into structured DNS queries.
- Threat intel: downloads blocklist feeds and matches each query and its parent domains (`intel.py`).
- Blocklist export: merges blocked domains into a file Pi-hole loads (`blocklist.py`).
- Feature extraction: entropy of the most random label, length, distinct-subdomain bursts per parent domain, rare TLDs, and per-device first-seen TLDs.
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
The tool never touches traffic itself. It writes a blocklist file; Pi-hole enforces it. `never_block` domains are excluded from every blocking path.

## Files of interest
- `src/ai_firewall/cli.py`: pipeline entry point
- `src/ai_firewall/statistical_model.py`: default model
- `src/ai_firewall/endpoint.py`: endpoint heuristics
- `src/ai_firewall/policy.py`: auto-promotion logic
