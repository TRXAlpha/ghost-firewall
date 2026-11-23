# Scripts

Utility scripts for daily operations.

## `scripts/run_daily.ps1`
Refreshes threat feeds, runs DNS analysis, and writes the report, state and `blocklist.txt` into one folder. Add `-AutoBlock` to blocklist high-scoring anomalies without review.

Usage:

```powershell
.\scripts\run_daily.ps1 -LogPath C:\path\pihole.log -ConfigPath .\config\example_config.json -StateDir C:\path\state
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
