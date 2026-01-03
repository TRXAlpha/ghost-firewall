import json
import math
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RunningStat:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)


@dataclass
class StatisticalModel:
    stats: dict[str, RunningStat]
    domain_bias: dict[str, float]
    zscore_threshold: float = 2.5

    def score(self, features: dict[str, float], domain: str) -> float:
        zscores = []
        for key, value in features.items():
            stat = self.stats.get(key)
            if not stat or stat.count < 2 or stat.stddev == 0.0:
                continue
            zscores.append(abs((value - stat.mean) / stat.stddev))
        avg_z = sum(zscores) / len(zscores) if zscores else 0.0
        domain_adjust = self.domain_bias.get(domain.lower(), 0.0)
        combined = avg_z + domain_adjust
        scaled = combined / self.zscore_threshold if self.zscore_threshold > 0 else combined
        return max(0.0, min(1.0, scaled))

    def update(self, features: dict[str, float]) -> None:
        for key, value in features.items():
            stat = self.stats.setdefault(key, RunningStat())
            stat.update(value)

    def apply_feedback(self, domain: str, label: int) -> None:
        if not domain:
            return
        current = self.domain_bias.get(domain.lower(), 0.0)
        if label == 1:
            self.domain_bias[domain.lower()] = current + 0.5
        else:
            self.domain_bias[domain.lower()] = max(-1.0, current - 0.2)


def load_statistical_model(path: str, zscore_threshold: float) -> StatisticalModel:
    model_path = Path(path)
    if not model_path.exists():
        return StatisticalModel(stats={}, domain_bias={}, zscore_threshold=zscore_threshold)
    data = json.loads(model_path.read_text(encoding="utf-8"))
    stats = {}
    for key, payload in data.get("stats", {}).items():
        stats[key] = RunningStat(
            count=payload.get("count", 0),
            mean=payload.get("mean", 0.0),
            m2=payload.get("m2", 0.0),
        )
    return StatisticalModel(
        stats=stats,
        domain_bias=data.get("domain_bias", {}),
        zscore_threshold=data.get("zscore_threshold", zscore_threshold),
    )


def save_statistical_model(path: str, model: StatisticalModel) -> None:
    payload = {
        "stats": {
            key: {"count": stat.count, "mean": stat.mean, "m2": stat.m2}
            for key, stat in model.stats.items()
        },
        "domain_bias": model.domain_bias,
        "zscore_threshold": model.zscore_threshold,
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
