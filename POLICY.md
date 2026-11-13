# Policy and Auto-Promotion

The policy layer tracks how many times you confirm a domain as malicious. It does not touch your network. Enforcement happens when Pi-hole loads the exported blocklist file.

## Concepts
- **Confirmation**: a feedback label of `block` for a domain. Counts once per run, however often the domain appears in the log.
- **Candidate**: a domain that has met the confirmation threshold.
- **Decay**: confirmation count decreases over time to prevent stale promotions.

## Configuration
`config/example_config.json`:
- `auto_promote_after`: number of confirmations required before promotion.
- `auto_promote_decay_days`: days after which confirmations decay.

## Output
The report includes:
- `auto_block_candidates`: domains that have met the threshold.

With `--blocklist-out` (or `--state-dir`), candidates are also written to the blocklist file, together with threat-intel hits. Domains in `never_block` and domains you labelled `allow` are never written.

## Storage
The policy state is stored in a JSON file defined by `--policy-state`. It contains:
- `confirmations`: map of domain to count
- `last_seen`: ISO timestamp of last update

## Safety defaults
Anomaly-based auto-blocking is off unless you pass `--auto-block`. Threat-intel hits and domains you confirmed are the only things blocklisted by default.
