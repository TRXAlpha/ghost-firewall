from collections import defaultdict, deque
from dataclasses import dataclass

from ai_firewall.domains import registered_domain, subdomain, tld as domain_tld
from ai_firewall.entropy import shannon_entropy


@dataclass
class AnomalyFlags:
    entropy: bool = False
    length: bool = False
    rare_tld: bool = False
    burst: bool = False
    new_tld: bool = False
    intel: bool = False


def name_entropy(domain: str) -> float:
    """Entropy of the most random-looking label we control for.

    Whole-FQDN entropy flags ordinary long names (outlook.office365.com), so
    measure the longest subdomain label, or the registered name when there is
    no subdomain (DGA domains like x7f3kq9zq1.com)."""
    sub = subdomain(domain)
    if sub:
        label = max(sub.split("."), key=len)
    else:
        label = registered_domain(domain).split(".")[0]
    return shannon_entropy(label)


class AnomalyDetector:
    def __init__(self, config) -> None:
        self.config = config
        # (client, registered domain) -> deque of (timestamp, full name)
        self.windows: dict[tuple[str, str], deque] = defaultdict(deque)

    def score(self, query, is_new_tld: bool) -> tuple[AnomalyFlags, dict[str, float]]:
        domain = query.domain
        tld = domain_tld(domain)
        entropy = name_entropy(domain)
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
        """Many DISTINCT names under one registered domain from one client in a
        short window. That is the DNS-tunneling signature (each query carries a
        new chunk of data as a subdomain). Repeats of one name do not count."""
        key = (query.client, registered_domain(query.domain))
        window = self.windows[key]
        now = query.timestamp
        window.append((now, query.domain))
        while window and (now - window[0][0]).total_seconds() > self.config.burst_window_seconds:
            window.popleft()
        return len({name for _, name in window}) >= self.config.burst_threshold
