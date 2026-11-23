# Implementation Plan: Beyond DNS

Goal: extend Ghost Firewall past DNS without rebuilding tools that already exist. Three code features (Part A) and one setup guide (Part B).

Status of the base: the DNS pipeline, threat-intel matching, blocklist export and tests are in place (see `README.md`). This plan builds on that code.

## Rules for whoever implements this

- **Standard library only.** No new dependencies.
- **One pull request per task.** Tasks A1, A2 and A3 are independent and can run in parallel. Each touches different modules, except `cli.py` and `config.py`, where each task only adds lines.
- **Reuse, do not duplicate.** Feed download goes through `intel.update_feeds`. File writing follows the atomic pattern in `blocklist.write_blocklist`. Domain helpers live in `domains.py`.
- **Every task ships tests** in `tests/`, runnable with `python -m unittest discover -s tests`. Tests must not touch the network.
- **Nothing blocks by default.** New blocking output is a file the user chooses to load. Anything that acts on a guess (not a feed hit) is report-only.
- **No secrets in config or the repo.** API keys come from environment variables.
- **Feed URLs below were checked on 2026-11-13.** Re-check each one before relying on it. Two abuse.ch download URLs died without notice earlier this year.

## Part A: code

### A1. IP blocklist export

**Why:** malware that connects to a hard-coded IP never asks DNS. A router can drop those connections if it has a list.

**What to build**

1. `src/ai_firewall/ip_intel.py`
   - `parse_ip_line(line) -> ipaddress.IPv4Network | IPv6Network | None`. Accept a bare IP, a CIDR, and trailing comments starting with `#` or `;`. Reject anything else.
   - `load_ip_dir(directory) -> set[network]` reading `*.txt` and `*.netset`.
   - `sanitize(networks, never_block_ips) -> list[network]`. This is the safety core. Drop every network that is not global (`not net.is_global`), every network that overlaps an entry in `never_block_ips`, and any IPv4 network wider than `/8`. Then collapse with `ipaddress.collapse_addresses`.
2. `src/ai_firewall/ip_blocklist.py`
   - `write_ip_blocklist(path, networks, fmt)` with formats `plain` (one CIDR per line, loads as an OPNsense/pfSense URL-table alias or an ipset) and `nftables` (a complete `table inet ghost_firewall` file with one IPv4 set, one IPv6 set, and a drop rule on forward and output).
   - Unlike the domain blocklist, this file is **rebuilt from the feeds each run, not merged**. IPs get reassigned, so stale entries must expire.
3. `config.py`: add `ip_feeds` (list of `{name, url}`) and `never_block_ips` (list of CIDRs; default includes the user's likely resolvers `1.1.1.1`, `8.8.8.8`, `9.9.9.9`).
4. `cli.py`: `--ip-intel-dir`, `--ip-blocklist-out`, `--ip-blocklist-format`. `--state-dir` defaults them to `ip_intel/` and `ip_blocklist.txt`. `--update-intel` also refreshes `ip_feeds`.
5. `intel.update_feeds`: take the line validator as a parameter so the "at least 10 valid entries or keep the old copy" check works for IP feeds too.

**Default feeds**

| Name | URL | Note |
|---|---|---|
| spamhaus-drop | `https://www.spamhaus.org/drop/drop.txt` | Hijacked and criminal networks. Very low false positive rate. |
| feodo-c2 | `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` | Botnet command servers. Small list. |
| et-block | `https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt` | Emerging Threats compromised hosts. |

Do **not** add `firehol_level1` as a default. It contains private ranges such as `10.0.0.0/8` and `192.168.0.0/16`. Loaded raw on a router, it cuts off the whole home network. `sanitize` must make even that list safe, and a test must prove it.

**Tests (acceptance)**

- Parser handles `1.2.3.4`, `1.2.3.0/24`, `1.2.3.0/24 ; SBL123`, `1.0.0.1   # comment`, and rejects `<html>` and hostnames.
- `sanitize` removes `10.0.0.0/8`, `192.168.0.0/16`, `127.0.0.0/8`, `0.0.0.0/8`, `100.64.0.0/10`, `169.254.0.0/16`, `fe80::/10`, `0.0.0.0/0`, and anything overlapping `never_block_ips`.
- A feed containing only private ranges produces an empty blocklist, not an error.
- The `nftables` output parses as valid syntax in a string-level test (balanced braces, one element per network). State in the PR that it was not loaded into a real kernel unless it was.

### A2. Malware hash lookup for endpoint findings

**Why:** the endpoint snapshot says "unsigned program in a user folder". A hash lookup upgrades that to "this file is a known trojan" or leaves it as a hint.

**What to build**

1. `scripts/collect_endpoint.ps1`: for each process and startup item whose signature status is not `Valid` and whose file exists, add `sha256` using `Get-FileHash -Algorithm SHA256`. Skip files over 100 MB. Do not hash signed files, it is slow and pointless.
2. `src/ai_firewall/hash_intel.py`
   - `lookup(sha256, api_key, cache) -> dict | None` calling MalwareBazaar: `POST https://mb-api.abuse.ch/api/v1/` with form fields `query=get_info` and `hash=<sha256>`, header `Auth-Key: <key>`. The API returns `Unauthorized` without a key (verified).
   - Validate that the hash is 64 hex characters before sending anything.
   - Cache results in `hash_cache.json` in the state dir. Known-bad entries never expire. Not-found entries expire after 7 days.
   - Limit to 50 lookups per run and a 15 second timeout. A network failure returns `None` and never fails the run.
3. `endpoint.py`: `analyze_endpoint` accepts an optional lookup function. A match adds a finding with category `known_malware`, severity `critical`, and the malware family name from the response.
4. `cli.py`: `--hash-lookup` flag. The key is read from the environment variable `MALWAREBAZAAR_AUTH_KEY`. If the flag is set and the key is missing, exit with a clear message. Never accept the key as a command-line argument or config value.
5. `report.py`: sort endpoint findings so `critical` prints first.

**Privacy rule:** only the hash leaves the machine. Never upload a file, a path, a hostname or a username. Say this in `ENDPOINT.md`.

**Tests (acceptance)**

- With a fake lookup function: a matching hash yields one `critical` finding, a non-matching hash yields none, a lookup that raises yields none and the run completes.
- Cache: a second run with the same hash makes zero lookup calls.
- An invalid hash string is never passed to the lookup function.
- No test calls the real API.

### A3. Beacon detection

**Why:** malware often phones home on a timer. A steady rhythm stands out even when the domain is on no feed and looks ordinary.

**What to build**

1. `src/ai_firewall/beacon.py`
   - Input: the parsed `DNSQuery` list. Group timestamps by `(client, registered_domain)`.
   - For each group with at least `beacon_min_queries` (default 12) spanning at least `beacon_min_span_minutes` (default 60): compute the gaps between consecutive queries. Use the median gap and the median absolute deviation (MAD), which survive a few outliers where mean and standard deviation do not.
   - Score `1 - (MAD / median)`, clamped to 0..1. Flag when the score is at least `beacon_threshold` (default 0.85) and the median gap is between 10 seconds and 24 hours.
   - Output: `BeaconFinding(client, domain, interval_seconds, count, score)`.
2. `cli.py` and `report.py`: add a `beacons` section to the JSON and text reports, and `beacons` to the summary.
3. `config.py`: the three settings above plus `beacon_ignore`, a list of domains that beacon legitimately. Default: `ntp.org`, `time.windows.com`, `time.apple.com`, `msftconnecttest.com`, `connectivitycheck.gstatic.com`, `captive.apple.com`. Also skip anything covered by `never_block`.

**Report-only. A beacon finding never reaches a blocklist, including with `--auto-block`.** Update checks, telemetry and smart-home devices beacon all day. The user reviews, then labels `block` through the normal feedback flow.

**Known limit, state it in `MODELS.md`:** Pi-hole caches answers, so repeat lookups inside the DNS record's time-to-live may never reach the log. Beacons faster than the TTL can look slower or irregular. This detector finds some beacons, not all.

**Tests (acceptance)**

- 30 queries exactly 300 seconds apart are flagged with an interval near 300.
- The same 30 queries with up to 5% random jitter (fixed seed) are flagged.
- 30 queries at random times over the same span (fixed seed) are not flagged.
- A group of 5 queries is not flagged. A group on a `beacon_ignore` domain is not flagged.
- A beacon finding with `--auto-block` on leaves the blocklist file unchanged.

## Part B: setup guide (documentation, no code)

**Deliverable:** one new file, `HARDENING.md`, linked from `README.md`. It covers the layers that existing tools already do well. Keep each section to: what it stops, the steps, how to check it worked.

| Section | Content |
|---|---|
| Force DNS through Pi-hole | Router rules: allow ports 53 and 853 outbound only from the Pi-hole address, drop the rest. Add `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-onlydomains.txt` to Pi-hole so known DoH servers do not resolve. Check: `nslookup example.com 8.8.8.8` from a PC must time out. |
| Load the IP blocklist | How to load `ip_blocklist.txt` from task A1 on OPNsense/pfSense (URL-table alias plus a block rule) and on Linux or OpenWrt (the nftables file). |
| Windows Defender hardening | Turn on Attack Surface Reduction rules and Controlled Folder Access. Link to the Microsoft docs rather than copying rule IDs that change. |
| Network IDS | Suricata or CrowdSec, and when a home network needs one. Point to their install docs. |
| Segmentation | Put IoT devices on a separate VLAN with no route to PCs. |
| Tripwire | OpenCanary on a spare Pi. |
| Backups and patching | One offline or versioned backup, automatic updates on. |

The router-specific steps depend on the owner's router model, which is not known yet. Write the generic rule first, then add exact steps once the model is known. Do not invent menu paths for a router nobody has checked.

## Out of scope

- Packet inspection, YARA scanning, any antivirus engine. Suricata and Defender exist.
- Uploading files anywhere.
- Pushing rules to a router over its API. The tool writes files and the owner loads them.
- Auto-blocking from beacon or anomaly findings beyond the existing opt-in `--auto-block`.

## Order and effort

| Order | Task | Size | Why this order |
|---|---|---|---|
| 1 | A1 IP blocklist | Medium | Closes the largest gap (hard-coded IPs) |
| 2 | Part B guide | Small | Makes A1 and the existing DNS blocking hard to bypass |
| 3 | A3 beacon detection | Medium | Uses data already collected, no external service |
| 4 | A2 hash lookup | Medium | Needs a free API key and a Windows machine to test the collector |

## Done means

- All new and existing tests pass on Python 3.10 and 3.13 in CI.
- `README.md` and the relevant topic file describe each new flag and config key.
- Each PR description says what was tested for real and what was not (PowerShell changes and router loading cannot be tested in CI).
