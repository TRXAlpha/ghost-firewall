# Feedback and Learning

The system learns from explicit feedback. This keeps control in your hands and avoids risky automatic blocking.

## Workflow
1) Generate a report from DNS logs.
2) Generate a feedback template from the report.
3) Edit labels to `allow` or `block`.
4) Run again with `--learn` to update model state.

## Generate template

```bash
python scripts/generate_feedback.py --report report.json --out feedback.json
```

## Example feedback file

```json
{
  "labels": [
    { "domain": "example.com", "client": "192.168.1.10", "label": "allow" },
    { "domain": "bad.example", "client": "192.168.1.50", "label": "block" }
  ]
}
```

## Apply feedback

```bash
python src/ai_firewall/cli.py --log "C:\path\to\pihole.log" --config config\example_config.json --model model.json --feedback feedback.json --learn --policy-state policy.json --out report.json
```

## Label meaning
- `allow`: reduce suspicion and lower future scores.
- `block`: increase suspicion and track confirmations.

## Safety
Feedback never directly blocks traffic. It only influences future recommendations and the policy candidate list.
