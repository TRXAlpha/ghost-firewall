from dataclasses import dataclass


@dataclass
class TinyModelResult:
    score: float
    decision: str


class TinyRecursiveModel:
    """Fixed-weight linear scorer. It is a placeholder for a future TRM/CTM
    model and does not learn. Inputs must be normalized to 0..1."""

    def __init__(self, weights: dict[str, float], threshold: float = 0.7) -> None:
        self.weights = weights
        self.threshold = threshold

    def infer(self, features: dict[str, float]) -> TinyModelResult:
        total = sum(self.weights.values()) or 1.0
        score = sum(self.weights.get(k, 0.0) * min(1.0, max(0.0, v)) for k, v in features.items())
        score /= total
        return TinyModelResult(score=score, decision="flag" if score >= self.threshold else "allow")


def load_trm(weights: dict[str, float], threshold: float = 0.7) -> TinyRecursiveModel:
    return TinyRecursiveModel(weights or {}, threshold)
