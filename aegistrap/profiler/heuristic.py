"""Heuristic (rule-based) benign-vs-attacker classifier.

The synopsis allows either a lightweight ML classifier or pure heuristics, and
notes that heuristics are easier to explain and justify. Every rule here
carries a human-readable label; the labels of the rules that fired are stored
with the session and shown on the dashboard.

The ML classifier in ``profiler.ml`` is trained against generator labels
(benign / attacker), not against these rule decisions, so it can disagree.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass

from aegistrap.models import CLASSIFIABLE_PERSONAS, AttackerPersona
from aegistrap.profiler.features import SessionFeatures
from aegistrap.profiler.signatures import ClientClass

Predicate = Callable[[SessionFeatures], bool]


@dataclass(frozen=True)
class Rule:
    persona: AttackerPersona
    weight: float
    label: str
    test: Predicate


def _rules() -> tuple[Rule, ...]:
    A = AttackerPersona.ATTACKER
    B = AttackerPersona.BENIGN

    return (
        # --- attacker ---
        Rule(
            A, 3.5, "offensive tool in User-Agent", lambda f: f.client_class is ClientClass.SCANNER
        ),
        Rule(A, 3.0, "attack payloads present", lambda f: bool(f.payload_families)),
        Rule(A, 2.5, "paths drawn from discovery wordlists", lambda f: f.wordlist_path_ratio > 0.15),
        Rule(A, 2.0, "cheat-sheet or stronger payloads", lambda f: f.max_sophistication >= 1),
        Rule(A, 2.0, "walks object IDs deliberately", lambda f: f.sequential_id_probes >= 2),
        Rule(A, 1.5, "high unknown-route ratio", lambda f: f.not_found_ratio > 0.3),
        Rule(A, 1.5, "request rate above 5/s", lambda f: f.requests_per_second > 5),
        Rule(
            A,
            1.5,
            "almost every request hits a new path",
            lambda f: f.distinct_path_ratio > 0.85 and f.request_count >= 10,
        ),
        Rule(
            A,
            1.5,
            "reuses identifiers learned from responses",
            lambda f: f.reactive_request_ratio >= 0.2,
        ),
        Rule(A, 1.5, "chains multiple payload families", lambda f: f.payload_family_count >= 3),
        Rule(
            A,
            1.0,
            "GraphQL introspection",
            lambda f: f.graphql_introspection,
        ),
        Rule(A, 2.0, "echoed a response-embedded canary", lambda f: f.canary_echo),
        Rule(A, 1.0, "prompt-injection style text in requests", lambda f: f.prompt_injection_echo),
        Rule(
            A,
            -2.5,
            "clean documented browsing with no attack signal",
            lambda f: (
                not f.payload_families
                and f.wordlist_path_ratio < 0.05
                and f.not_found_ratio < 0.15
                and f.client_class is not ClientClass.SCANNER
                and f.sequential_id_probes == 0
            ),
        ),
        # --- benign ---
        Rule(B, 2.5, "no attack payloads observed", lambda f: not f.payload_families),
        Rule(B, 1.5, "requests resolve to documented routes", lambda f: f.not_found_ratio < 0.15),
        Rule(B, 1.5, "browser-consistent header set", lambda f: f.browser_header_score > 0.35),
        Rule(B, 1.0, "low request rate", lambda f: 0 < f.requests_per_second < 1.5),
        Rule(
            B,
            0.5,
            "short, narrow session",
            lambda f: 0 < f.request_count <= 15 and f.distinct_methods <= 2,
        ),
        Rule(B, -6.0, "attack payloads present", lambda f: bool(f.payload_families)),
        Rule(B, -4.0, "offensive tool in User-Agent", lambda f: f.client_class is ClientClass.SCANNER),
        Rule(B, -4.0, "echoed a response-embedded canary", lambda f: f.canary_echo),
        Rule(B, -3.0, "wordlist-driven enumeration", lambda f: f.wordlist_path_ratio > 0.15),
        Rule(B, -2.0, "walks object IDs deliberately", lambda f: f.sequential_id_probes >= 2),
        Rule(B, -1.5, "elevated unknown-route ratio", lambda f: f.not_found_ratio > 0.3),
    )


RULES: tuple[Rule, ...] = _rules()

#: Below this the session stays UNCLASSIFIED rather than acting on noise.
MIN_CONFIDENCE = 0.30
#: Two classes within this probability margin are treated as indistinguishable.
MIN_MARGIN = 0.06
SOFTMAX_TEMPERATURE = 1.25


@dataclass
class HeuristicVerdict:
    persona: AttackerPersona
    confidence: float
    scores: dict[str, float]
    probabilities: dict[str, float]
    signals: list[str]


def classify(features: SessionFeatures) -> HeuristicVerdict:
    """Score benign vs attacker, then pick the better-supported class."""
    scores: dict[AttackerPersona, float] = dict.fromkeys(CLASSIFIABLE_PERSONAS, 0.0)
    fired: dict[AttackerPersona, list[str]] = {p: [] for p in CLASSIFIABLE_PERSONAS}

    if features.request_count == 0:
        return HeuristicVerdict(
            persona=AttackerPersona.UNKNOWN,
            confidence=0.0,
            scores={p.value: 0.0 for p in CLASSIFIABLE_PERSONAS},
            probabilities={p.value: 0.0 for p in CLASSIFIABLE_PERSONAS},
            signals=[],
        )

    for rule in RULES:
        try:
            hit = rule.test(features)
        except (TypeError, ValueError, ZeroDivisionError):
            continue
        if not hit:
            continue
        scores[rule.persona] += rule.weight
        if rule.weight > 0:
            fired[rule.persona].append(rule.label)

    probabilities = _softmax(scores)
    ranked = sorted(probabilities.items(), key=lambda kv: kv[1], reverse=True)
    top_persona, top_prob = ranked[0]
    runner_up_prob = ranked[1][1] if len(ranked) > 1 else 0.0

    evidence = min(1.0, 0.45 + 0.11 * features.request_count)
    confidence = top_prob * evidence

    persona = top_persona
    if (
        scores[top_persona] <= 0
        or confidence < MIN_CONFIDENCE
        or (top_prob - runner_up_prob) < MIN_MARGIN
    ):
        persona = AttackerPersona.UNKNOWN

    signals = _ordered_signals(fired.get(persona) or fired.get(top_persona) or [], features)
    return HeuristicVerdict(
        persona=persona,
        confidence=round(confidence, 4),
        scores={p.value: round(v, 3) for p, v in scores.items()},
        probabilities={p.value: round(v, 4) for p, v in probabilities.items()},
        signals=signals,
    )


def _softmax(scores: dict[AttackerPersona, float]) -> dict[AttackerPersona, float]:
    clamped = {p: max(0.0, v) for p, v in scores.items()}
    if not any(clamped.values()):
        return dict.fromkeys(scores, 0.0)
    peak = max(clamped.values())
    exps = {
        p: math.exp((v - peak) / SOFTMAX_TEMPERATURE) if v > 0 else 0.0 for p, v in clamped.items()
    }
    total = sum(exps.values()) or 1.0
    return {p: v / total for p, v in exps.items()}


def _ordered_signals(rule_labels: list[str], features: SessionFeatures) -> list[str]:
    """Merge the rules that fired with the descriptive feature notes."""
    combined: list[str] = []
    for item in [*rule_labels, *features.notes]:
        if item not in combined:
            combined.append(item)
    return combined[:12]
