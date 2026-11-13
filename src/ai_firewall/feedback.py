import json
from dataclasses import dataclass
from pathlib import Path

from ai_firewall.domains import normalize

BLOCK_WORDS = {"block", "malicious", "deny", "bad", "flag"}
ALLOW_WORDS = {"allow", "benign", "good", "safe", "ok"}


@dataclass
class FeedbackItem:
    domain: str
    client: str | None
    label: int


def _normalize_label(value) -> int | None:
    """1 = block, 0 = allow, None = not a decision (e.g. the template's
    'review' placeholder or a typo). Unknown labels must never count as allow."""
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int):
        return 1 if value != 0 else 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in BLOCK_WORDS:
            return 1
        if lowered in ALLOW_WORDS:
            return 0
    return None


def load_feedback(path: str) -> list[FeedbackItem]:
    payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    items = []
    for entry in payload.get("labels", []):
        label = _normalize_label(entry.get("label"))
        domain = normalize(entry.get("domain") or "")
        if label is None or not domain:
            continue
        items.append(FeedbackItem(domain=domain, client=entry.get("client"), label=label))
    return items


def build_feedback_map(items: list[FeedbackItem]) -> dict[tuple[str, str | None], int]:
    return {(item.domain, item.client): item.label for item in items}
