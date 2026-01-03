# Data Schemas

This is a simplified reference for JSON inputs/outputs.

## DNS report (output)
`report.json`:

```json
{
  "summary": {
    "total": 1200,
    "recommended": 12,
    "learned": 8,
    "endpoint_findings": 3
  },
  "items": [
    {
      "timestamp": "2025-12-25T16:22:13",
      "client": "192.168.1.10",
      "domain": "suspicious.example",
      "qtype": "A",
      "flags": {
        "entropy": true,
        "length": false,
        "rare_tld": true,
        "burst": false,
        "new_tld": true
      },
      "score": 0.84,
      "decision": "recommend"
    }
  ],
  "endpoint_findings": [
    {
      "category": "process",
      "severity": "high",
      "description": "Unsigned process in user path: bad.exe (C:\\Users\\...)"
    }
  ],
  "auto_block_candidates": [
    "bad.example"
  ]
}
```

## Feedback input

```json
{
  "labels": [
    { "domain": "example.com", "client": "192.168.1.10", "label": "allow" },
    { "domain": "bad.example", "label": "block" }
  ]
}
```

## Endpoint snapshot input
Produced by `scripts/collect_endpoint.ps1`.

```json
{
  "generated_at": "2025-12-25T16:15:00Z",
  "hostname": "WORKSTATION",
  "processes": [
    { "name": "chrome.exe", "pid": 1234, "path": "C:\\Program Files\\...", "signature_status": "Valid" }
  ],
  "startup_items": [
    { "name": "Updater", "command": "C:\\Users\\...\\update.exe", "signature_status": "Unknown" }
  ],
  "scheduled_tasks": [
    { "name": "DailyJob", "action": "C:\\Users\\...\\job.exe" }
  ],
  "services": [
    { "name": "svc", "display_name": "Service", "status": "Running" }
  ],
  "tcp_connections": [
    { "remote_address": "8.8.8.8", "process_name": "app", "signature_status": "Unknown" }
  ],
  "event_logs": [
    { "log": "System", "id": 7045, "message": "Service installed" }
  ]
}
```

## Policy state

```json
{
  "confirmations": {
    "bad.example": 3
  },
  "last_seen": {
    "bad.example": "2025-12-25T16:30:00"
  }
}
```

## Model state (statistical)

```json
{
  "stats": {
    "entropy": { "count": 1200, "mean": 2.4, "m2": 345.6 }
  },
  "domain_bias": {
    "bad.example": 1.0
  },
  "zscore_threshold": 2.5
}
```
