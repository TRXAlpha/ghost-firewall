from collections import defaultdict, deque
from dataclasses import dataclass

from .entropy import shannon_entropy


@dataclass
class AnomalyFlags:
    entropy: bool = False
    length: bool = False
    rare_tld: bool = False
    burst: bool = False
    new_tld: bool = False


class AnomalyDetector:
    def __init__(self, config) -> None:
        self.config = config
        self.query_windows: dict[tuple[str, str], deque] = defaultdict(deque)

    def _tld(self, domain: str) -> str:
        parts = domain.split(".")
        return parts[-1].lower() if len(parts) > 1 else ""

    def score(
        self,
        query,
        is_new_tld: bool,
        entropy: float | None = None,
        tld: str | None = None,
    ) -> tuple[AnomalyFlags, dict[str, float]]:
        domain = query.domain
        tld = tld if tld is not None else self._tld(domain)
        entropy = entropy if entropy is not None else shannon_entropy(domain)
        flags = AnomalyFlags(
            entropy=entropy >= self.config.entropy_threshold,
            length=len(domain) >= self.config.long_query_length,
            rare_tld=tld in self.config.rare_tlds if tld else False,
            burst=self._is_burst(query),
            new_tld=is_new_tld,
        )
        features = {
            "entropy": entropy,
            "length": float(len(domain)),
            "rare_tld": 1.0 if flags.rare_tld else 0.0,
            "burst": 1.0 if flags.burst else 0.0,
            "new_tld": 1.0 if flags.new_tld else 0.0,
        }
        return flags, features

    def _is_burst(self, query) -> bool:
        key = (query.client, query.domain)
        window = self.query_windows[key]
        now = query.timestamp
        window.append(now)
        while window and (now - window[0]).total_seconds() > self.config.burst_window_seconds:
            window.popleft()
        return len(window) >= self.config.burst_threshold
