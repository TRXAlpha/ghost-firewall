import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate feedback template from report.")
    parser.add_argument("--report", required=True, help="Path to report.json")
    parser.add_argument("--out", required=True, help="Path to feedback.json")
    args = parser.parse_args()

    payload = json.loads(Path(args.report).read_text(encoding="utf-8"))

    # One entry per domain. "review" is a placeholder the analyzer ignores:
    # change it to "allow" or "block", or leave it to skip the domain.
    labels, seen = [], set()
    for item in payload.get("items", []):
        domain = item.get("domain")
        if not domain or domain in seen or item.get("decision") == "block":
            continue
        seen.add(domain)
        labels.append({"domain": domain, "label": "review", "score": item.get("score")})

    Path(args.out).write_text(json.dumps({"labels": labels}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
