# Cybersecurity Threat Model and Surface Analysis

The AI assistant treats all inbound device communication as potentially untrusted. A simplified threat model includes:

- Local DNS spoofing or poisoning attempts (handled via Pi-hole + DNSSEC + logging to the assistant)
- Malicious rogue APs or device clones (especially relevant given the ESP-NOW communications)
- Exfiltration attempts via unexpected DNS lookups from apps or background tasks
- Social engineering through content (handled by the behavioral gating layer)
- Insider threats (unmonitored bypasses via known admin devices)
- Model poisoning attempts (e.g., feeding specific prompts that could bias future actions if learned via local LLM)
- Replay attacks or unverified ESP-NOW pings from spoofed MACs

The assistant continuously cross-checks behavior logs, device presence, and user activity patterns to flag anomalies.

## DNS Surveillance and Tunneling Detection

The assistant tracks and parses all DNS logs via Pi-hole and embedded Wireshark-compatible sensors (Pico W or ESP32s). Each night, logs are parsed to:

- Detect DNS tunneling by tracking:
  - Unusually long TXT or NULL queries
  - Burst DNS queries to uncommonly used TLDs
- Identify domains with entropy above a threshold (possible DGA)
- Score domains against known CTI feeds (VirusTotal, if available)

Future plans include integrating a basic anomaly model that scores DNS patterns by device context.

## Firmware Hardening and OTA Logic

The ESP32-based assistant uses:

- MAC whitelist checks per-ping
- Rolling challenge-responses (nonces + HMAC derived via SHA256) for high-trust pings
- No default OTA; updates require USB flashing via pogo or a station module

Plans to implement ESP32 Secure Boot and Flash Encryption, with per-device keys stored on the host.

## Log Protection and Tamper Evidence

All device logs are appended to encrypted rotating buffers. At the end of each day:

- A SHA256 hash is computed and stored on a hardened ESP32 node with no internet access
- Logs are archived to cold storage via Syncthing

Plan to include GPG signing or hash-chain linking to prevent tampering or forgery.

## Subnet Intelligence and Passive Discovery

The assistant scans the LAN using passive ARP sniffing and nmap-lite probes during low-usage hours. Devices are profiled based on:

- Consistent traffic patterns
- TTL values
- MAC vendor prefixes
- DNS query types

Results are matched against the assistant's known-device database to infer device roles and mark anomalies.

## Network Routing Enforcement

The assistant monitors default routes and DNS servers for public profiles (e.g., cafe or LTE). If an unknown DNS or gateway is detected:

- Automatically tunnels traffic via Tailscale
- Enforces DNS-over-TLS via cloudflared
- In untrusted networks, disables auto software updates or Git pulls

Plans for a WireGuard-like kill switch to prevent fallback to unencrypted routes.

## Internal Penetration Simulation

The assistant is tested against internal red team behaviors, such as:

- Simulated rogue APs
- DNS spoofing via MITMf
- Traffic interception using Bettercap
- ESP spoofing via fake ESP-NOW packets

The assistant logs, correlates, and optionally disables parts of the system (e.g., YouTube access) if the threat persists.
