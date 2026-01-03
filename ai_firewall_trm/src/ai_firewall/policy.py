import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path


@dataclass
class PolicyConfig:
    auto_promote_after: int = 3
    auto_promote_decay_days: int = 30


class PolicyState:
    def __init__(self, confirmations: dict[str, int], last_seen: dict[str, str]) -> None:
        self.confirmations = confirmations
        self.last_seen = last_seen

    def decay(self, now: datetime, decay_days: int) -> None:
        if decay_days <= 0:
            return
        cutoff = now - timedelta(days=decay_days)
        for domain, ts in list(self.last_seen.items()):
            try:
                last = datetime.fromisoformat(ts)
            except ValueError:
                continue
            if last < cutoff and domain in self.confirmations:
                self.confirmations[domain] = max(0, self.confirmations[domain] - 1)

    def update(self, domain: str, label: int, now: datetime) -> None:
        if not domain:
            return
        key = domain.lower()
        current = self.confirmations.get(key, 0)
        if label == 1:
            self.confirmations[key] = current + 1
        else:
            self.confirmations[key] = max(0, current - 1)
        self.last_seen[key] = now.isoformat()

    def candidates(self, threshold: int) -> list[str]:
        return [domain for domain, count in self.confirmations.items() if count >= threshold]


def load_policy_state(path: str) -> PolicyState:
    state_path = Path(path)
    if not state_path.exists():
        return PolicyState(confirmations={}, last_seen={})
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    return PolicyState(
        confirmations=payload.get("confirmations", {}),
        last_seen=payload.get("last_seen", {}),
    )


def save_policy_state(path: str, state: PolicyState) -> None:
    payload = {
        "confirmations": state.confirmations,
        "last_seen": state.last_seen,
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
