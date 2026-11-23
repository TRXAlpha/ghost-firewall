# Ghost Firewall

A local DNS risk engine for a Pi-hole network. It reads your DNS log, decides which domains are dangerous, and writes a blocklist file that Pi-hole enforces. Pure Python standard library, no GPU, no dependencies.

## What it can and cannot block

No tool blocks every virus, and this one does not either. Read this before trusting it.

**It blocks (through Pi-hole):**
- Domains on threat-intelligence feeds: known malware, phishing and command-and-control hosts (about 500,000 domains with the default feeds).
- DNS tunneling: many random-looking subdomains under one parent domain in a short window.
- Domains you confirm as malicious through feedback.

**It cannot see or stop:**
- Malware that never asks DNS: USB sticks, email attachments already on disk, hard-coded IP addresses.
- Devices or apps that bypass Pi-hole with their own encrypted DNS (DoH/DoT) or a VPN.
- Brand-new malicious domains that are not on a feed yet and look ordinary.
- Malicious content on legitimate domains (a bad file hosted on a mainstream cloud service).
- Anything already running on a machine. It does not remove malware.

Treat it as one layer. Keep an endpoint antivirus (Microsoft Defender is built into Windows), keep systems patched, and block outbound DoH/DoT on your router if you want devices forced through Pi-hole.

## How it works

1. **Threat intel match.** Every queried domain (and its parent domains) is checked against downloaded feeds. A hit is a `block`.
2. **Anomaly scoring.** A small statistical model scores each query on name randomness, length, rare TLD, subdomain burst and first-seen TLD. A high score is a `recommend`.
3. **Feedback.** You label recommendations `allow` or `block`. A domain you confirm `auto_promote_after` times (default 3 runs) becomes a `block`.
4. **Blocklist export.** Blocked domains are merged into `blocklist.txt`, which Pi-hole loads.

`never_block` in the config protects major platforms from ever landing on the blocklist, whatever a feed or the model says.

## Quick start

Requires Python 3.10+ and a Pi-hole (or dnsmasq) query log.

```bash
python src/ai_firewall/cli.py --log /var/log/pihole/pihole.log --config config/example_config.json --state-dir state --update-intel
```

That one command downloads the feeds, analyzes the log, and writes everything into `state/`:

| File | Purpose |
|---|---|
| `report.json`, `report.txt` | What was blocked or recommended, and why |
| `blocklist.txt` | The list Pi-hole enforces |
| `model.json`, `profiles.json`, `policy.json` | Learned state, kept between runs |
| `intel/` | Downloaded feeds |

Optional install, which gives you a `ghost-firewall` command:

```bash
pip install -e .
```

## Make Pi-hole enforce it

1. In the Pi-hole admin page, open **Lists** and add `file:///full/path/to/state/blocklist.txt` as a blocklist.
2. Make sure the file and its folders are readable by the `pihole` user. If gravity reports the list as inaccessible, this is why.
3. Run `pihole -g` after each analysis so Pi-hole reloads the file.

The default format is Adblock style (`||domain^`), which blocks the domain and all its subdomains and needs a current Pi-hole (v5.22 FTL or later). Use `--blocklist-format domains` for a plain list or `--blocklist-format dnsmasq` for a dnsmasq config file.

**Shortcut worth knowing:** Pi-hole can subscribe to the threat feeds directly (add the URLs from `intel_feeds` in the config as lists). That covers step 1 above without this tool. What this tool adds is the tunneling detection, the feedback loop, and a report of which device asked for what.

## Automatic blocking (opt-in)

By default only threat-intel hits and domains you confirmed are blocked. To also block high-scoring anomalies without review:

```bash
python src/ai_firewall/cli.py --log /var/log/pihole/pihole.log --config config/example_config.json --state-dir state --update-intel --auto-block
```

This blocks anything scoring at or above `auto_block_threshold` (default 0.95). Trade-off: you catch tunneling the same day, and you accept that a false positive breaks a site until you label it `allow`. An `allow` label removes a domain from the blocklist on the next run.

## Feedback workflow

```bash
python scripts/generate_feedback.py --report state/report.json --out feedback.json
```

Edit `feedback.json`: change `"review"` to `"allow"` or `"block"`. Entries left as `"review"` are ignored. Then:

```bash
python src/ai_firewall/cli.py --log /var/log/pihole/pihole.log --config config/example_config.json --state-dir state --feedback feedback.json --learn
```

Each labelled domain counts once per run, however many times it appears in the log.

## Endpoint snapshot (optional, Windows)

```powershell
.\scripts\collect_endpoint.ps1 -OutPath endpoint_snapshot.json
```

```bash
python src/ai_firewall/cli.py --log /var/log/pihole/pihole.log --config config/example_config.json --state-dir state --endpoint endpoint_snapshot.json
```

Read-only heuristics: unsigned programs in user folders, unsigned programs talking to the internet, new autoruns versus a baseline (`--endpoint-baseline`), and high-signal event log entries. This is a hint list, not an antivirus.

## Configuration

Key settings in `config/example_config.json`:

- `model_type`: `statistical` (default), `online_logistic`, or `trm_stub` (fixed weights, no learning)
- `decision_threshold`: score needed for a recommendation
- `auto_block_threshold`: score needed for `--auto-block`
- `entropy_threshold`, `long_query_length`, `burst_threshold`, `burst_window_seconds`: detection sensitivity
- `auto_promote_after`, `auto_promote_decay_days`: confirmations needed, and how they fade
- `intel_feeds`: list of `{name, url}` blocklists to download (https only)
- `never_block`: domains that can never be blocked

## Tests

```bash
python -m unittest discover -s tests
```

## More documentation

`ARCHITECTURE.md`, `MODELS.md`, `FEEDBACK.md`, `POLICY.md`, `ENDPOINT.md`, `OPERATIONS.md`, `SCHEMA.md`, `SCRIPTS.md`. `THREAT_MODEL.md` describes the wider home-lab vision; most of it is not implemented in this repository.

## Privacy

DNS logs, reports and state files reveal browsing behavior. Keep `state/` private. The only network traffic this tool makes is downloading the feeds.
