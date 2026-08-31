"""Heuristic (rule-based) attacker classifier.

The synopsis allows either a lightweight ML classifier or pure heuristics, and
notes that heuristics are easier to explain and justify. That argument is
stronger than it first looks: the classifier's output feeds the deception
policy, so when a session is misclassified we need to know *which signal*
caused it. Every rule here therefore carries a human-readable label, and the
labels of the rules that fired are stored with the session and shown on the
dashboard.

The ML classifier in ``profiler.ml`` is trained against this one's labels and
is treated as the comparison arm in the evaluation plan, not the default.
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
    K = AttackerPersona.SCRIPT_KIDDIE
    S = AttackerPersona.SCANNER
    H = AttackerPersona.SKILLED_HUMAN
    A = AttackerPersona.AI_AGENT
    B = AttackerPersona.BENIGN

    return (
        # --- automated scanner ---
        Rule(
            S, 3.5, "offensive tool in User-Agent", lambda f: f.client_class is ClientClass.SCANNER
        ),
        Rule(S, 2.0, "request rate above 5/s", lambda f: f.requests_per_second > 5),
        Rule(S, 1.0, "request rate above 15/s", lambda f: f.requests_per_second > 15),
        Rule(
            S,
            1.5,
            "almost every request hits a new path",
            lambda f: f.distinct_path_ratio > 0.85 and f.request_count >= 10,
        ),
        Rule(S, 1.5, "high unknown-route ratio", lambda f: f.not_found_ratio > 0.45),
        Rule(S, 2.0, "paths drawn from discovery wordlists", lambda f: f.wordlist_path_ratio > 0.2),
        Rule(
            S,
            1.5,
            "machine-regular inter-request timing",
            lambda f: 0 < f.interval_cv < 0.3 and f.request_count >= 6,
        ),
        Rule(
            S,
            1.0,
            "never reuses values from responses",
            lambda f: f.reactive_request_ratio < 0.05 and f.request_count >= 10,
        ),
        Rule(S, -3.0, "echoed a response-embedded canary", lambda f: f.canary_echo),
        Rule(S, -2.0, "adapts to response content", lambda f: f.reactive_request_ratio > 0.25),
        # --- script kiddie ---
        Rule(
            K,
            1.5,
            "generic HTTP client or absent User-Agent",
            lambda f: (
                f.client_class in (ClientClass.LIBRARY, ClientClass.EMPTY, ClientClass.UNKNOWN)
            ),
        ),
        Rule(
            K,
            2.5,
            "attack payloads present but unsophisticated",
            lambda f: bool(f.payload_families) and f.max_sophistication <= 2,
        ),
        Rule(K, 1.5, "cheat-sheet grade payloads only", lambda f: f.max_sophistication == 1),
        Rule(K, 1.0, "short session", lambda f: 0 < f.request_count <= 30),
        Rule(K, 1.0, "narrow payload repertoire", lambda f: 0 < f.payload_family_count <= 2),
        Rule(
            K,
            1.0,
            "hand-driven pacing",
            lambda f: f.interval_cv > 0.4 and f.requests_per_second < 3,
        ),
        Rule(K, -3.0, "blind or evasion-aware payloads", lambda f: f.max_sophistication >= 4),
        Rule(
            K, -2.5, "offensive tool in User-Agent", lambda f: f.client_class is ClientClass.SCANNER
        ),
        Rule(K, -2.0, "echoed a response-embedded canary", lambda f: f.canary_echo),
        Rule(
            K, -1.0, "systematically adapts to responses", lambda f: f.reactive_request_ratio > 0.3
        ),
        Rule(K, -1.5, "wordlist-driven enumeration", lambda f: f.wordlist_path_ratio > 0.3),
        # --- skilled human ---
        Rule(
            H,
            3.0,
            "blind or inferential exploitation attempts",
            lambda f: f.max_sophistication >= 4,
        ),
        Rule(H, 1.5, "target-adapted payloads", lambda f: f.max_sophistication == 3),
        Rule(
            H,
            2.0,
            "reuses identifiers learned from responses",
            lambda f: f.reactive_request_ratio >= 0.2,
        ),
        Rule(H, 1.5, "walks object IDs deliberately", lambda f: f.sequential_id_probes >= 2),
        Rule(H, 1.5, "chains multiple payload families", lambda f: f.payload_family_count >= 3),
        Rule(H, 1.5, "layered encoding for filter evasion", lambda f: f.max_encoding_layers >= 3),
        Rule(
            H,
            1.0,
            "introspects then queries GraphQL selectively",
            lambda f: f.graphql_introspection and f.graphql_request_count >= 2,
        ),
        Rule(
            H,
            2.0,
            "irregular, human-like pacing",
            lambda f: f.interval_cv > 0.6 and f.request_count >= 5,
        ),
        Rule(H, 1.0, "deliberate, low request rate", lambda f: 0 < f.requests_per_second < 2.0),
        Rule(H, 1.0, "browser-consistent header set", lambda f: f.browser_header_score > 0.4),
        Rule(
            H,
            -2.0,
            "pacing too regular for hand-driven work",
            lambda f: 0 < f.interval_cv < 0.4 and f.request_count >= 8,
        ),
        Rule(H, -2.5, "request rate too high for manual work", lambda f: f.requests_per_second > 8),
        Rule(
            H, -2.0, "offensive tool in User-Agent", lambda f: f.client_class is ClientClass.SCANNER
        ),
        Rule(H, -1.5, "wordlist-driven enumeration", lambda f: f.wordlist_path_ratio > 0.4),
        Rule(H, -1.0, "echoed a response-embedded canary", lambda f: f.canary_echo),
        # --- autonomous AI agent ---
        Rule(A, 7.0, "echoed a response-embedded canary", lambda f: f.canary_echo),
        Rule(
            A,
            3.5,
            "self-identifies as an LLM agent",
            lambda f: f.client_class is ClientClass.AI_AGENT,
        ),
        Rule(A, 1.0, "prompt-injection style text in requests", lambda f: f.prompt_injection_echo),
        Rule(
            A,
            2.5,
            "machine pacing combined with response-driven adaptation",
            lambda f: (
                f.reactive_request_ratio >= 0.2 and 0 < f.interval_cv < 0.5 and f.request_count >= 6
            ),
        ),
        Rule(
            A,
            2.0,
            "metronomic request intervals over a long session",
            lambda f: 0 < f.interval_cv < 0.4 and f.request_count >= 8,
        ),
        Rule(
            A,
            1.5,
            "steady sub-human rate while still reading responses",
            lambda f: 0.4 < f.requests_per_second < 6 and f.reactive_request_ratio >= 0.15,
        ),
        Rule(
            A,
            1.0,
            "well-formed JSON across several verbs",
            lambda f: f.valid_json_body_ratio > 0.9 and f.distinct_methods >= 3,
        ),
        Rule(
            A,
            1.0,
            "sophisticated payloads at machine cadence",
            lambda f: f.max_sophistication >= 3 and 0 < f.interval_cv < 0.45,
        ),
        Rule(
            A,
            1.0,
            "capable payloads without browser-client hygiene",
            lambda f: f.max_sophistication >= 3 and f.browser_header_score < 0.15,
        ),
        Rule(
            A,
            1.0,
            "broad payload repertoire plus response adaptation",
            lambda f: f.payload_family_count >= 3 and f.reactive_request_ratio > 0.2,
        ),
        Rule(A, -2.0, "wordlist-driven enumeration", lambda f: f.wordlist_path_ratio > 0.4),
        Rule(
            A, -2.0, "offensive tool in User-Agent", lambda f: f.client_class is ClientClass.SCANNER
        ),
        # --- benign ---
        Rule(B, 2.5, "no attack payloads observed", lambda f: not f.payload_families),
        Rule(B, 1.0, "requests resolve to documented routes", lambda f: f.not_found_ratio < 0.15),
        Rule(B, 1.5, "browser-consistent header set", lambda f: f.browser_header_score > 0.35),
        Rule(B, 1.0, "low request rate", lambda f: 0 < f.requests_per_second < 1.5),
        Rule(
            B,
            0.5,
            "short, narrow session",
            lambda f: 0 < f.request_count <= 15 and f.distinct_methods <= 2,
        ),
        Rule(B, -5.0, "attack payloads present", lambda f: bool(f.payload_families)),
        Rule(B, -4.0, "echoed a response-embedded canary", lambda f: f.canary_echo),
        Rule(B, -2.5, "wordlist-driven enumeration", lambda f: f.wordlist_path_ratio > 0.15),
        Rule(B, -2.0, "walks object IDs deliberately", lambda f: f.sequential_id_probes >= 2),
        Rule(B, -1.5, "elevated unknown-route ratio", lambda f: f.not_found_ratio > 0.3),
    )


RULES: tuple[Rule, ...] = _rules()

#: Below this the session stays UNCLASSIFIED rather than acting on noise.
MIN_CONFIDENCE = 0.30
#: Two personas within this probability margin are treated as indistinguishable.
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
    """Score every persona, then pick the best-supported one."""
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

    # A single request carries real information (a sqlmap User-Agent is a
    # sqlmap User-Agent) but not enough to justify opening the deep surface,
    # so confidence ramps with the amount of behaviour observed.
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
    # Negative totals mean "actively contradicted", so they are floored rather
    # than allowed to compete on the exponential scale.
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
