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
- `scripts/run_daily.ps1` for DNS log analysis

## Example scheduled run

```powershell
.\scripts\collect_endpoint.ps1 -OutPath C:\path\endpoint_snapshot.json -SinceHours 24
python C:\Users\chris\Documents\Ghost\codex\ai_firewall_trm\src\ai_firewall\cli.py --log C:\path\pihole.log --config C:\Users\chris\Documents\Ghost\codex\ai_firewall_trm\config\example_config.json --model C:\path\model.json --endpoint C:\path\endpoint_snapshot.json --out C:\path\report.json
```

## Troubleshooting
- No findings: Check `decision_threshold` and `zscore_threshold`.
- Too many findings: Increase `decision_threshold` or add feedback labels.
- Endpoint snapshot empty: run PowerShell as Administrator to access Security logs.

## Data retention
Store reports, model state, feedback, and policy state with access control. Avoid syncing with untrusted cloud providers if logs contain sensitive domains.
