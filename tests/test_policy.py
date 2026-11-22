"""Benign-vs-attacker deception policy and its ablation arm."""

from __future__ import annotations

from aegistrap.decoy.policy import (
    BASELINE_POLICY,
    all_policies,
    policy_for,
    unlocked_weaknesses,
    weakness_unlocked,
)
from aegistrap.intel.catalogue import WEAKNESSES
from aegistrap.models import AttackerPersona, ErrorVerbosity


def test_benign_traffic_gets_no_bait() -> None:
    policy = policy_for(AttackerPersona.BENIGN)
    assert policy.idor_leak_probability == 0.0
    assert policy.expose_admin_hints is False
    assert policy.plant_honey_credentials is False
    assert policy.use_llm is False
    assert unlocked_weaknesses(policy) == []


def test_attackers_get_generation_budget() -> None:
    policy = policy_for(AttackerPersona.ATTACKER)
    assert policy.use_llm is True
    assert policy.narrative_richness == "high"
    assert policy.error_verbosity is ErrorVerbosity.DEBUG


def test_attackers_see_a_deeper_surface_than_benign() -> None:
    benign = unlocked_weaknesses(policy_for(AttackerPersona.BENIGN))
    attacker = unlocked_weaknesses(policy_for(AttackerPersona.ATTACKER))
    assert benign == []
    assert "DEBUG_ENDPOINT" in attacker
    assert "SQL_INJECTION" in attacker
    assert "JWT_ALG_NONE" in attacker
    assert "SSRF_WEBHOOK" in attacker
    assert len(attacker) > len(unlocked_weaknesses(policy_for(AttackerPersona.UNKNOWN)))


def test_low_confidence_falls_back_to_the_neutral_tier() -> None:
    """One odd header must not be enough to open the attack surface."""
    guessed = policy_for(AttackerPersona.ATTACKER, confidence=0.2)
    assert guessed.persona is AttackerPersona.UNKNOWN

    confident = policy_for(AttackerPersona.ATTACKER, confidence=0.9)
    assert confident.persona is AttackerPersona.ATTACKER


def test_benign_classification_is_trusted_even_when_unsure() -> None:
    assert policy_for(AttackerPersona.BENIGN, confidence=0.1).persona is AttackerPersona.BENIGN


def test_ablation_arm_ignores_the_profiler() -> None:
    for persona in AttackerPersona:
        assert policy_for(persona, adaptive=False) is BASELINE_POLICY


def test_ablation_arm_exposes_the_attack_surface() -> None:
    baseline = set(unlocked_weaknesses(BASELINE_POLICY))
    assert baseline
    assert all(WEAKNESSES[wid].min_persona_rank <= 2 for wid in baseline)
    assert "SSRF_WEBHOOK" in baseline


def test_no_weakness_is_reachable_at_the_benign_rank() -> None:
    """Structural guarantee, not a convention: rank 0 must stay empty."""
    assert all(w.min_persona_rank >= 1 for w in WEAKNESSES.values())


def test_unknown_weakness_ids_are_never_unlocked() -> None:
    assert (
        weakness_unlocked("NOT_A_REAL_WEAKNESS", policy_for(AttackerPersona.ATTACKER)) is False
    )


def test_every_persona_has_a_policy_and_a_rationale() -> None:
    published = all_policies()
    for persona in AttackerPersona:
        assert persona.value in published, persona
        assert published[persona.value].rationale.strip()
