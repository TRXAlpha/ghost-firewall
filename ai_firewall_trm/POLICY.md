# Policy and Auto-Promotion

The policy layer tracks how many times you confirm a domain as malicious. It never enforces blocks by itself.

## Concepts
- **Confirmation**: a feedback label of `block` for a domain.
- **Candidate**: a domain that has met the confirmation threshold.
- **Decay**: confirmation count decreases over time to prevent stale promotions.

## Configuration
`config/example_config.json`:
- `auto_promote_after`: number of confirmations required before promotion.
- `auto_promote_decay_days`: days after which confirmations decay.

## Output
The report includes:
- `auto_block_candidates`: domains that have met the threshold.

These are informational only. You decide if and how to enforce them.

## Storage
The policy state is stored in a JSON file defined by `--policy-state`. It contains:
- `confirmations`: map of domain to count
- `last_seen`: ISO timestamp of last update

## Safety defaults
Auto-blocking is off. Recommendations are always human-reviewed.
