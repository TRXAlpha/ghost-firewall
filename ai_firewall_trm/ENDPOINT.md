# Endpoint Heuristics

Endpoint heuristics provide additional context for suspicious behavior on the local machine. They are read-only and do not remove or quarantine files.

## Snapshot collection
The Windows collector script gathers:
- Running processes (path, owner, signature status)
- Startup items (registry and startup folder entries)
- Scheduled tasks
- Services
- TCP connections (with process ownership)
- High-signal Windows event logs

Collect a snapshot:

```powershell
.\scripts\collect_endpoint.ps1 -OutPath endpoint_snapshot.json -SinceHours 24
```

Note: reading Security logs may require Administrator privileges.

## Baseline diffing
Capture a known-good baseline and compare later snapshots to detect new autoruns, tasks, or services.

```bash
python src/ai_firewall/cli.py --log "C:\path\to\pihole.log" --config config\example_config.json --model model.json --endpoint endpoint_snapshot.json --endpoint-baseline endpoint_baseline.json --out report.json
```

## Heuristic rules
- Unsigned binaries running from user-writable paths.
- Startup entries pointing to user-writable paths.
- Scheduled tasks running from user-writable paths.
- Public network connections by unsigned processes.
- Event logs for high-signal security events.
- New startup items, tasks, or services compared to baseline.

## Event log IDs
By default, the collector looks for:
- 7045: New service installed
- 4698: Scheduled task created
- 4720: New user account created
- 4625: Failed logon
- 1102: Security log cleared
- 4104: PowerShell script block logging

## Snapshot schema (simplified)
The JSON schema is documented in `SCHEMA.md`.
