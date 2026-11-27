"""Optional ML profiler (the comparison arm for the profiling-accuracy metric).

The evaluation plan measures profiling precision and recall against "a
rule-based baseline without the ML component", so both classifiers must be
available and interchangeable. This module stays entirely optional: if
scikit-learn is missing or no model file has been trained, the profiler
silently falls back to heuristics.

Labels are binary (``benign`` / ``attacker``) and come from either the
synthetic generators or a public corpus such as CSIC 2010. Training is not
distilled from heuristic decisions, so the forest can disagree with the rules.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegistrap.logging_setup import get_logger
from aegistrap.models import AttackerPersona
from aegistrap.profiler.features import SessionFeatures, extract_features
from aegistrap.store import Event

log = get_logger("profiler.ml")

DEFAULT_MODEL_PATH = Path("data/profiler_model.joblib")


def sklearn_available() -> bool:
    try:
        import sklearn  # noqa: F401
    except ImportError:
        return False
    return True


@dataclass
class MLVerdict:
    persona: AttackerPersona
    confidence: float
    probabilities: dict[str, float]


class MLProfiler:
    """Thin wrapper around a scikit-learn classifier over session features."""

    def __init__(self, model: Any = None, classes: Sequence[str] | None = None) -> None:
        self._model = model
        self._classes = list(classes or [])

    # -- lifecycle -----------------------------------------------------------

    @property
    def is_ready(self) -> bool:
        return self._model is not None

    @classmethod
    def train(
        cls,
        *,
        per_persona: int = 300,
        seed: int = 20260831,
        n_estimators: int = 300,
        labelled_sessions: Sequence[tuple[AttackerPersona, list[Event]]] | None = None,
        source: str = "synthetic",
    ) -> tuple[MLProfiler, dict[str, Any]]:
        """Train on labelled sessions; returns the model and holdout metrics.

        ``labelled_sessions`` is a list of ``(benign|attacker, events)``. When
        omitted, synthetic generators supply the data. Pass CSIC 2010 sessions
        from ``profiler.public_data`` to train on a public corpus.
        """
        if not sklearn_available():
            raise RuntimeError("scikit-learn is not installed")

        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import classification_report
        from sklearn.model_selection import train_test_split

        from aegistrap.profiler.synthetic import generate_dataset

        dataset = (
            list(labelled_sessions)
            if labelled_sessions is not None
            else generate_dataset(per_persona=per_persona, seed=seed)
        )
        if not dataset:
            raise ValueError("no labelled sessions to train on")
        X = [extract_features(events).to_vector() for _, events in dataset]
        y = [persona.value for persona, _ in dataset]

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=seed, stratify=y
        )
        model = RandomForestClassifier(
            n_estimators=n_estimators,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=seed,
            n_jobs=-1,
        )
        model.fit(X_train, y_train)
        report = classification_report(
            y_test, model.predict(X_test), output_dict=True, zero_division=0
        )
        importances = sorted(
            zip(SessionFeatures.vector_names(), model.feature_importances_, strict=False),
            key=lambda kv: kv[1],
            reverse=True,
        )
        majority_class, majority_count = Counter(y_test).most_common(1)[0]
        metrics = {
            "source": source,
            "samples": len(dataset),
            "train_size": len(X_train),
            "test_size": len(X_test),
            "majority_class": majority_class,
            "majority_baseline": round(majority_count / len(y_test), 4),
            "holdout_report": report,
            "top_features": [
                {"feature": name, "importance": round(float(value), 4)}
                for name, value in importances[:12]
            ],
        }
        return cls(model=model, classes=list(model.classes_)), metrics

    def save(self, path: Path | str = DEFAULT_MODEL_PATH) -> Path:
        import joblib

        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self._model, "classes": self._classes}, target)
        return target

    @classmethod
    def load(cls, path: Path | str = DEFAULT_MODEL_PATH) -> MLProfiler | None:
        target = Path(path)
        if not target.exists() or not sklearn_available():
            return None
        try:
            import joblib

            bundle = joblib.load(target)
            return cls(model=bundle["model"], classes=bundle.get("classes", []))
        except Exception as exc:  # pragma: no cover - corrupt or version-skewed model
            log.warning("could not load ML profiler from %s: %s", target, exc)
            return None

    # -- inference -----------------------------------------------------------

    def classify(self, features: SessionFeatures) -> MLVerdict | None:
        if self._model is None:
            return None
        vector = [features.to_vector()]
        try:
            probabilities = self._model.predict_proba(vector)[0]
        except Exception as exc:  # pragma: no cover - shape drift after refactor
            log.warning("ML profiler inference failed: %s", exc)
            return None
        classes = list(getattr(self._model, "classes_", self._classes))
        scored = dict(zip(classes, (float(p) for p in probabilities), strict=False))
        best_label = max(scored, key=lambda k: scored[k])
        try:
            persona = AttackerPersona(best_label)
        except ValueError:
            persona = AttackerPersona.UNKNOWN
        return MLVerdict(
            persona=persona,
            confidence=round(scored[best_label], 4),
            probabilities={k: round(v, 4) for k, v in scored.items()},
        )
