"""Profiler service: turns a session's history into a persona and a policy.

Called once per request, before the response is generated, so the current
request influences the deception surface it is answered with. The in-flight
request is passed in as a pending event because it has not been persisted yet
(its status code is not known until after generation).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from aegistrap.decoy.policy import policy_for
from aegistrap.logging_setup import get_logger
from aegistrap.models import AttackerPersona, DeceptionPolicy
from aegistrap.profiler.features import SessionFeatures, extract_features
from aegistrap.profiler.heuristic import HeuristicVerdict
from aegistrap.profiler.heuristic import classify as heuristic_classify
from aegistrap.profiler.ml import DEFAULT_MODEL_PATH, MLProfiler
from aegistrap.store import Event, StateStore

log = get_logger("profiler")

ProfilerMode = Literal["heuristic", "ml", "hybrid"]

#: Only the tail of a session is used for feature extraction. Long-running
#: sessions change behaviour (recon, then exploitation), and averaging over
#: hundreds of requests washes that out.
FEATURE_WINDOW = 60


@dataclass
class ProfileResult:
    persona: AttackerPersona
    confidence: float
    policy: DeceptionPolicy
    features: SessionFeatures
    scores: dict[str, float]
    probabilities: dict[str, float]
    signals: list[str]
    source: str = "heuristic"
    ml_probabilities: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "persona": self.persona.value,
            "persona_label": self.persona.label,
            "confidence": round(self.confidence, 4),
            "source": self.source,
            "scores": self.scores,
            "probabilities": self.probabilities,
            "ml_probabilities": self.ml_probabilities,
            "signals": self.signals,
            "policy": {
                "error_verbosity": self.policy.error_verbosity.value,
                "idor_leak_probability": self.policy.idor_leak_probability,
                "use_llm": self.policy.use_llm,
                "narrative_richness": self.policy.narrative_richness,
                "rationale": self.policy.rationale,
            },
            "features": self.features.to_dict(),
        }


class AttackerProfiler:
    def __init__(
        self,
        store: StateStore,
        *,
        mode: ProfilerMode = "heuristic",
        adaptive: bool = True,
        model_path: Path | str = DEFAULT_MODEL_PATH,
    ) -> None:
        self.store = store
        self.mode: ProfilerMode = mode
        self.adaptive = adaptive
        self._ml: MLProfiler | None = None
        if mode in ("ml", "hybrid"):
            self._ml = MLProfiler.load(model_path)
            if self._ml is None:
                log.warning(
                    "profiler mode %r requested but no trained model at %s; "
                    "falling back to heuristics",
                    mode,
                    model_path,
                )
                self.mode = "heuristic"

    def profile(self, session_id: str, pending: Event | None = None) -> ProfileResult:
        history = self.store.get_events(session_id, limit=FEATURE_WINDOW)
        if pending is not None:
            history = [*history[-(FEATURE_WINDOW - 1) :], pending]
        features = extract_features(history, session_id=session_id)
        return self.classify_features(features, session_id=session_id)

    def classify_features(
        self, features: SessionFeatures, *, session_id: str | None = None
    ) -> ProfileResult:
        verdict = heuristic_classify(features)
        persona = verdict.persona
        confidence = verdict.confidence
        probabilities = dict(verdict.probabilities)
        ml_probabilities: dict[str, float] = {}
        source = "heuristic"

        if self._ml is not None and self._ml.is_ready:
            ml_verdict = self._ml.classify(features)
            if ml_verdict is not None:
                ml_probabilities = ml_verdict.probabilities
                if self.mode == "ml":
                    persona, confidence = ml_verdict.persona, ml_verdict.confidence
                    probabilities = ml_verdict.probabilities
                    source = "ml"
                elif self.mode == "hybrid":
                    persona, confidence, probabilities = _blend(verdict, ml_verdict.probabilities)
                    source = "hybrid"

        policy = policy_for(persona, adaptive=self.adaptive, confidence=confidence)
        result = ProfileResult(
            persona=persona,
            confidence=confidence,
            policy=policy,
            features=features,
            scores=verdict.scores,
            probabilities=probabilities,
            signals=verdict.signals,
            source=source,
            ml_probabilities=ml_probabilities,
        )
        if session_id:
            self.store.update_persona(
                session_id, persona, confidence, probabilities, result.signals
            )
        return result


def _blend(
    verdict: HeuristicVerdict, ml_probabilities: dict[str, float]
) -> tuple[AttackerPersona, float, dict[str, float]]:
    """Average the two classifiers' distributions.

    Equal weighting is deliberate: the heuristics encode domain knowledge the
    model cannot see, and the model catches feature combinations no single rule
    covers. Neither has earned the right to override the other.
    """
    keys = set(verdict.probabilities) | set(ml_probabilities)
    blended = {
        key: 0.5 * verdict.probabilities.get(key, 0.0) + 0.5 * ml_probabilities.get(key, 0.0)
        for key in keys
    }
    total = sum(blended.values()) or 1.0
    blended = {k: v / total for k, v in blended.items()}
    best = max(blended, key=lambda k: blended[k])
    try:
        persona = AttackerPersona(best)
    except ValueError:
        persona = AttackerPersona.UNKNOWN
    if blended[best] < 0.3:
        persona = AttackerPersona.UNKNOWN
    return persona, round(blended[best], 4), {k: round(v, 4) for k, v in blended.items()}
