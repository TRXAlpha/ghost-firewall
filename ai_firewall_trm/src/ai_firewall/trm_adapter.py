from dataclasses import dataclass


@dataclass
class TinyModelResult:
    score: float
    decision: str


class TinyRecursiveModel:
    """Lightweight linear scorer as a placeholder for TRM/CTM models."""

    def __init__(self, weights: dict[str, float]) -> None:
        self.weights = weights

    def infer(self, features: dict[str, float]) -> TinyModelResult:
        score = 0.0
        for key, value in features.items():
            weight = self.weights.get(key, 0.0)
            score += weight * value
        decision = "flag" if score >= 1.0 else "allow"
        return TinyModelResult(score=score, decision=decision)


def load_trm(weights: dict[str, float]) -> TinyRecursiveModel:
    return TinyRecursiveModel(weights or {})
