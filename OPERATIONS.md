# Operations

Runbook and operational guidance for the AI firewall.

## Typical daily flow
1) Collect DNS logs (Pi-hole/dnsmasq).
2) Optionally collect endpoint snapshot.
3) Run analysis and generate report.
4) Generate feedback template and label findings.
5) Re-run with `--learn` to update model and policy state.

## Scheduling
Use Task Scheduler to run:
- `scripts/collect_endpoint.ps1` (optional)
- `scripts/run_daily.ps1` to refresh threat feeds, analyze the log, and update the blocklist

After each run, reload Pi-hole with `pihole -g` so it picks up the new `blocklist.txt`.

## Example scheduled run

```powershell
.\scripts\collect_endpoint.ps1 -OutPath C:\path\endpoint_snapshot.json -SinceHours 24
.\scripts\run_daily.ps1 -LogPath C:\path\pihole.log -ConfigPath .\config\example_config.json -StateDir C:\path\state
```

## Troubleshooting
- `total=0`: the log has no `query[...]` lines. Enable query logging in Pi-hole.
- No findings: Check `decision_threshold` and `zscore_threshold`.
- Too many findings: Increase `decision_threshold` or add feedback labels.
- Endpoint snapshot empty: run PowerShell as Administrator to access Security logs.

## Data retention
Store reports, model state, feedback, and policy state with access control. Avoid syncing with untrusted cloud providers if logs contain sensitive domains.
