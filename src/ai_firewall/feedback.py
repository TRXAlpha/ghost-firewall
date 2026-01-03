import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class FeedbackItem:
    domain: str
    client: str | None
    label: int


def _normalize_label(value) -> int:
    if isinstance(value, int):
        return 1 if value != 0 else 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"block", "malicious", "deny", "bad", "flag"}:
            return 1
    return 0


def load_feedback(path: str) -> list[FeedbackItem]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    items = []
    for entry in payload.get("labels", []):
        items.append(
            FeedbackItem(
                domain=entry.get("domain", ""),
                client=entry.get("client"),
                label=_normalize_label(entry.get("label", 0)),
            )
        )
    return items


def build_feedback_map(items: list[FeedbackItem]) -> dict[tuple[str, str | None], int]:
    mapping = {}
    for item in items:
        if not item.domain:
            continue
        mapping[(item.domain.lower(), item.client)] = item.label
    return mapping
