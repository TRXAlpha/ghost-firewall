# Scripts

Utility scripts for daily operations.

## `scripts/run_daily.ps1`
Runs DNS analysis.

Usage:

```powershell
.\scripts\run_daily.ps1 -LogPath C:\path\pihole.log -ConfigPath C:\Users\chris\Documents\Ghost\codex\ai_firewall_trm\config\example_config.json -OutJson C:\path\report.json -OutText C:\path\report.txt
```

## `scripts/collect_endpoint.ps1`
Collects endpoint snapshot data from Windows.

Usage:

```powershell
.\scripts\collect_endpoint.ps1 -OutPath C:\path\endpoint_snapshot.json -SinceHours 24
```

Notes:
- Security log access may require Administrator privileges.
- If event logs are empty, run PowerShell as Administrator.

## `scripts/generate_feedback.py`
Creates a feedback template from an existing report.

Usage:

```bash
python scripts/generate_feedback.py --report report.json --out feedback.json
```
