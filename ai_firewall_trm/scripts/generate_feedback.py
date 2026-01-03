import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate feedback template from report.")
    parser.add_argument("--report", required=True, help="Path to report.json")
    parser.add_argument("--out", required=True, help="Path to feedback.json")
    args = parser.parse_args()

    payload = json.loads(Path(args.report).read_text(encoding="utf-8"))
    items = payload.get("items", [])

    labels = []
    for item in items:
        labels.append(
            {
                "domain": item.get("domain"),
                "client": item.get("client"),
                "label": "review",
            }
        )

    feedback = {"labels": labels}
    Path(args.out).write_text(json.dumps(feedback, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
