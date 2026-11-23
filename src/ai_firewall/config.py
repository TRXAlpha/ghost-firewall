from dataclasses import dataclass, field
import json
from pathlib import Path

DEFAULT_FEEDS = [
    {
        "name": "hagezi-tif-medium",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt",
    },
    {
        "name": "urlhaus-malware",
        "url": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt",
    },
    {
        "name": "phishing-army",
        "url": "https://phishing.army/download/phishing_army_blocklist.txt",
    },
]

DEFAULT_NEVER_BLOCK = [
    "google.com", "googleapis.com", "gstatic.com", "microsoft.com", "windows.com",
    "windowsupdate.com", "office.com", "office365.com", "live.com", "apple.com",
    "icloud.com", "amazon.com", "amazonaws.com", "cloudfront.net", "cloudflare.com",
    "akamai.net", "akamaiedge.net", "github.com", "githubusercontent.com",
]


@dataclass
class FirewallConfig:
    entropy_threshold: float = 3.5
    long_query_length: int = 60
    burst_threshold: int = 12
    burst_window_seconds: int = 30
    model_type: str = "statistical"
    decision_threshold: float = 0.7
    auto_block_threshold: float = 0.95
    learning_rate: float = 0.1
    zscore_threshold: float = 2.5
    auto_promote_after: int = 3
    auto_promote_decay_days: int = 30
    rare_tlds: list[str] = field(default_factory=list)
    never_block: list[str] = field(default_factory=lambda: list(DEFAULT_NEVER_BLOCK))
    intel_feeds: list[dict] = field(default_factory=lambda: list(DEFAULT_FEEDS))
    trm_weights: dict[str, float] = field(default_factory=dict)


def load_config(path: str) -> FirewallConfig:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    known = FirewallConfig.__dataclass_fields__
    return FirewallConfig(**{k: v for k, v in data.items() if k in known})
