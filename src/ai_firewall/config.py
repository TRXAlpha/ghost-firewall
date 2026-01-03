from dataclasses import dataclass
import json
from pathlib import Path


@dataclass
class FirewallConfig:
    entropy_threshold: float = 3.5
    long_query_length: int = 60
    burst_threshold: int = 12
    burst_window_seconds: int = 30
    model_type: str = "statistical"
    decision_threshold: float = 0.7
    learning_rate: float = 0.1
    zscore_threshold: float = 2.5
    auto_promote_after: int = 3
    auto_promote_decay_days: int = 30
    rare_tlds: list[str] = None
    common_tlds: list[str] = None
    device_anomaly_score: float = 0.65
    trm_weights: dict[str, float] = None


def load_config(path: str) -> FirewallConfig:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return FirewallConfig(
        entropy_threshold=data.get("entropy_threshold", 3.5),
        long_query_length=data.get("long_query_length", 60),
        burst_threshold=data.get("burst_threshold", 12),
        burst_window_seconds=data.get("burst_window_seconds", 30),
        model_type=data.get("model_type", "statistical"),
        decision_threshold=data.get("decision_threshold", 0.7),
        learning_rate=data.get("learning_rate", 0.1),
        zscore_threshold=data.get("zscore_threshold", 2.5),
        auto_promote_after=data.get("auto_promote_after", 3),
        auto_promote_decay_days=data.get("auto_promote_decay_days", 30),
        rare_tlds=data.get("rare_tlds", []),
        common_tlds=data.get("common_tlds", []),
        device_anomaly_score=data.get("device_anomaly_score", 0.65),
        trm_weights=data.get("trm_weights", {}),
    )
