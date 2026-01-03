from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class DeviceProfile:
    total_queries: int = 0
    tlds: set[str] = field(default_factory=set)
    avg_entropy: float = 0.0


class DeviceProfiler:
    def __init__(self) -> None:
        self.profiles: dict[str, DeviceProfile] = defaultdict(DeviceProfile)

    def update(self, client: str, tld: str, entropy: float) -> bool:
        profile = self.profiles[client]
        profile.total_queries += 1
        profile.avg_entropy = (
            (profile.avg_entropy * (profile.total_queries - 1)) + entropy
        ) / profile.total_queries
        is_new_tld = tld not in profile.tlds
        if is_new_tld:
            profile.tlds.add(tld)
        return is_new_tld
