import json
import math
from dataclasses import dataclass
from pathlib import Path


@dataclass
class OnlineLogisticModel:
    weights: dict[str, float]
    bias: float = 0.0
    learning_rate: float = 0.1

    def predict_proba(self, features: dict[str, float]) -> float:
        score = self.bias
        for key, value in features.items():
            score += self.weights.get(key, 0.0) * value
        return 1.0 / (1.0 + math.exp(-score))

    def update(self, features: dict[str, float], label: int) -> float:
        prediction = self.predict_proba(features)
        error = label - prediction
        for key, value in features.items():
            self.weights[key] = self.weights.get(key, 0.0) + (self.learning_rate * error * value)
        self.bias += self.learning_rate * error
        return prediction


def load_model(path: str, learning_rate: float) -> OnlineLogisticModel:
    model_path = Path(path)
    if not model_path.exists():
        return OnlineLogisticModel(weights={}, bias=0.0, learning_rate=learning_rate)
    data = json.loads(model_path.read_text(encoding="utf-8"))
    return OnlineLogisticModel(
        weights=data.get("weights", {}),
        bias=data.get("bias", 0.0),
        learning_rate=data.get("learning_rate", learning_rate),
    )


def save_model(path: str, model: OnlineLogisticModel) -> None:
    payload = {
        "weights": model.weights,
        "bias": model.bias,
        "learning_rate": model.learning_rate,
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
