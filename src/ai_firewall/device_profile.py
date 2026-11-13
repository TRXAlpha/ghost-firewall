import json
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path


@dataclass
class DeviceProfile:
    total_queries: int = 0
    tlds: set[str] = field(default_factory=set)


class DeviceProfiler:
    """Tracks which TLDs each device has used. Persist it between runs, or
    every device's first '.com' of the day looks new."""

    # A device needs some history before "new TLD" means anything.
    MIN_HISTORY = 50

    def __init__(self) -> None:
        self.profiles: dict[str, DeviceProfile] = defaultdict(DeviceProfile)

    def update(self, client: str, tld: str) -> bool:
        profile = self.profiles[client]
        is_new = bool(tld) and tld not in profile.tlds and profile.total_queries >= self.MIN_HISTORY
        profile.total_queries += 1
        if tld:
            profile.tlds.add(tld)
        return is_new


def load_profiles(path: str) -> DeviceProfiler:
    profiler = DeviceProfiler()
    p = Path(path)
    if p.exists():
        data = json.loads(p.read_text(encoding="utf-8"))
        for client, item in data.get("profiles", {}).items():
            profiler.profiles[client] = DeviceProfile(
                total_queries=item.get("total_queries", 0), tlds=set(item.get("tlds", []))
            )
    return profiler


def save_profiles(path: str, profiler: DeviceProfiler) -> None:
    payload = {
        "profiles": {
            client: {"total_queries": p.total_queries, "tlds": sorted(p.tlds)}
            for client, p in profiler.profiles.items()
        }
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
