# AI Firewall (TRM-friendly)

A lightweight, local-first AI firewall for DNS and endpoint behavior. It runs on CPU, stays comfortably under 1GB VRAM, and supports gradual learning from your feedback without enabling automatic blocking by default.

This is not a traffic enforcement tool. It is a risk engine that produces recommendations, evidence, and candidate rules you can review before applying in Pi-hole, a firewall, or a routing layer.

## Contents
- `THREAT_MODEL.md`: Threat model and surface analysis.
- `ARCHITECTURE.md`: Components and data flow.
- `MODELS.md`: Model options and how they learn.
- `FEEDBACK.md`: Feedback workflow and labeling.
- `ENDPOINT.md`: Endpoint heuristics and snapshot schema.
- `POLICY.md`: Auto-promotion rules and safety guardrails.
- `OPERATIONS.md`: Runbooks, scheduling, and troubleshooting.
- `SCHEMA.md`: Input/output JSON schemas.
- `SCRIPTS.md`: Helper scripts and utilities.

## What it does
- Treats inbound device communication as untrusted by default.
- Parses Pi-hole/dnsmasq logs for tunneling-like behavior, DGA-like entropy, and bursty query patterns.
- Builds per-device profiles to track new TLDs and behavioral changes.
- Scores anomalies with a low-resource model and produces recommendations.
- Accepts feedback to improve future recommendations.
- Optionally ingests endpoint snapshots to spot suspicious processes, autoruns, and high-signal event log activity.
- Produces candidate blocklists once a domain is repeatedly confirmed, but does not enforce them automatically.

## Quick start (DNS only)
1) Edit `config/example_config.json` as needed.
2) Run analysis:

```bash
python src/ai_firewall/cli.py --log "C:\path\to\pihole.log" --config config\example_config.json --model model.json --out report.json
```

3) Optional text report:

```bash
python src/ai_firewall/cli.py --log "C:\path\to\pihole.log" --config config\example_config.json --model model.json --text report.txt
```

## Prerequisites
- Python 3.10+
- Access to Pi-hole or dnsmasq logs
- Optional: Windows PowerShell for endpoint snapshots

## Configuration reference
Key settings in `config/example_config.json`:
- `model_type`: `statistical` or `online_logistic` (default `statistical`)
- `decision_threshold`: how aggressive recommendations are (0.5-0.9 is typical)
- `zscore_threshold`: baseline sensitivity for the statistical model
- `learning_rate`: update step for the online logistic model
- `burst_threshold` and `burst_window_seconds`: detect DNS burst patterns
- `entropy_threshold` and `long_query_length`: detect DGA-like queries
- `auto_promote_after`: confirmations required for candidate promotion
- `auto_promote_decay_days`: decay window for confirmations

## Report interpretation
The JSON report includes:
- `summary`: counts for total queries, recommendations, learning updates, endpoint findings
- `items`: per-query recommendations with flags and scores
- `endpoint_findings`: optional endpoint heuristic alerts
- `auto_block_candidates`: optional candidates that reached confirmation thresholds

Use the report to:
- Validate whether recommendations are correct.
- Create feedback labels.
- Feed candidate domains into your enforcement layer after review.

## Directory layout
- `config/`: configuration files
- `scripts/`: helper scripts for collection and feedback
- `src/ai_firewall/`: core pipeline and models
- `*.md`: documentation

## Example workflows
DNS-only, no learning:

```bash
python src/ai_firewall/cli.py --log "C:\path\to\pihole.log" --config config\example_config.json --out report.json
```

DNS + learning:

```bash
python src/ai_firewall/cli.py --log "C:\path\to\pihole.log" --config config\example_config.json --model model.json --feedback feedback.json --learn --policy-state policy.json --out report.json
```

DNS + endpoint snapshot + baseline diff:

```bash
python src/ai_firewall/cli.py --log "C:\path\to\pihole.log" --config config\example_config.json --model model.json --endpoint endpoint_snapshot.json --endpoint-baseline endpoint_baseline.json --out report.json
```

## Learning workflow (recommend-only)
Generate a feedback template from a report:

```bash
python scripts/generate_feedback.py --report report.json --out feedback.json
```

Edit `feedback.json`, set labels to `allow` or `block`, then learn:

```bash
python src/ai_firewall/cli.py --log "C:\path\to\pihole.log" --config config\example_config.json --model model.json --feedback feedback.json --learn --policy-state policy.json --out report.json
```

The report includes `auto_block_candidates` based on repeated confirmations. These are not enforced automatically.

## Endpoint heuristics (optional)
Create a snapshot:

```powershell
.\scripts\collect_endpoint.ps1 -OutPath endpoint_snapshot.json
```

Run with endpoint heuristics:

```bash
python src/ai_firewall/cli.py --log "C:\path\to\pihole.log" --config config\example_config.json --model model.json --endpoint endpoint_snapshot.json --out report.json
```

Baseline diffing (autoruns and tasks):

```bash
python src/ai_firewall/cli.py --log "C:\path\to\pihole.log" --config config\example_config.json --model model.json --endpoint endpoint_snapshot.json --endpoint-baseline endpoint_baseline.json --out report.json
```

## Model choices
`model_type` in `config/example_config.json`:
- `statistical` (default): rolling z-score anomaly model with light per-domain biasing.
- `online_logistic`: online logistic learner with feedback-driven updates.
- `trm_stub`: placeholder linear scorer for later TRM/CTM integration (no learning).

## Auto-promotion policy
The system can promote domains to “candidate blocklist” after repeated confirmations. Adjust:
- `auto_promote_after` (default 3)
- `auto_promote_decay_days` (default 30)

Auto-promotion only affects recommendations, not enforcement. See `POLICY.md`.

## Notes and safety
- There is no automatic blocking by default.
- Endpoint heuristics are read-only and conservative.
- This project does not perform malware removal.
- For the full threat model, see `THREAT_MODEL.md`.

## Privacy and data handling
- DNS logs and endpoint snapshots can contain sensitive data.
- Store reports, feedback, model state, and policy state in secured locations.
- Avoid syncing raw logs to untrusted cloud providers.

## Limitations
- DNS-only visibility cannot detect all threats.
- Anomaly scoring can produce false positives, especially early on.
- Endpoint heuristics rely on Windows APIs and require sufficient permissions.

## Roadmap ideas
- Integrate CTI feeds for domain reputation.
- Add optional on-host YARA scans (read-only, not destructive).
- Export candidate blocklists in Pi-hole format.
