"""Persona-adaptive deception policy and its ablation arm."""

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


def test_scanners_are_served_from_templates() -> None:
    """Spending model tokens on a wordlist scan is pure cost (Section 13)."""
    assert policy_for(AttackerPersona.SCANNER).use_llm is False


def test_high_skill_sessions_get_generation_budget() -> None:
    for persona in (AttackerPersona.SKILLED_HUMAN, AttackerPersona.AI_AGENT):
        policy = policy_for(persona)
        assert policy.use_llm is True
        assert policy.narrative_richness == "high"
        assert policy.error_verbosity is ErrorVerbosity.DEBUG


def test_surface_depth_increases_with_skill() -> None:
    ordered = [
        AttackerPersona.BENIGN,
        AttackerPersona.UNKNOWN,
        AttackerPersona.SCRIPT_KIDDIE,
        AttackerPersona.SCANNER,
        AttackerPersona.SKILLED_HUMAN,
    ]
    counts = [len(unlocked_weaknesses(policy_for(p))) for p in ordered]
    assert counts == sorted(counts), counts
    assert counts[-1] > counts[0]


def test_script_kiddies_get_cheap_bait_but_not_critical_flaws() -> None:
    policy = policy_for(AttackerPersona.SCRIPT_KIDDIE)
    unlocked = set(unlocked_weaknesses(policy))
    assert "DEBUG_ENDPOINT" in unlocked
    assert "SQL_INJECTION" in unlocked
    # Rank-4 flaws stay out of reach: a novice landing a critical finding
    # smells like a trap.
    assert "SSRF_WEBHOOK" not in unlocked
    assert "JWT_ALG_NONE" not in unlocked


def test_low_confidence_falls_back_to_the_neutral_tier() -> None:
    """One odd header must not be enough to open the deep surface."""
    guessed = policy_for(AttackerPersona.SKILLED_HUMAN, confidence=0.2)
    assert guessed.persona is AttackerPersona.UNKNOWN

    confident = policy_for(AttackerPersona.SKILLED_HUMAN, confidence=0.9)
    assert confident.persona is AttackerPersona.SKILLED_HUMAN


def test_benign_classification_is_trusted_even_when_unsure() -> None:
    # Erring toward "boring API" is the safe direction.
    assert policy_for(AttackerPersona.BENIGN, confidence=0.1).persona is AttackerPersona.BENIGN


def test_ablation_arm_ignores_the_profiler() -> None:
    for persona in AttackerPersona:
        assert policy_for(persona, adaptive=False) is BASELINE_POLICY


def test_ablation_arm_exposes_a_fixed_mid_tier_surface() -> None:
    baseline = set(unlocked_weaknesses(BASELINE_POLICY))
    assert baseline
    assert all(WEAKNESSES[wid].min_persona_rank <= 3 for wid in baseline)
    assert "SSRF_WEBHOOK" not in baseline


def test_no_weakness_is_reachable_at_the_benign_rank() -> None:
    """Structural guarantee, not a convention: rank 0 must stay empty."""
    assert all(w.min_persona_rank >= 1 for w in WEAKNESSES.values())


def test_unknown_weakness_ids_are_never_unlocked() -> None:
    assert (
        weakness_unlocked("NOT_A_REAL_WEAKNESS", policy_for(AttackerPersona.SKILLED_HUMAN)) is False
    )


def test_every_persona_has_a_policy_and_a_rationale() -> None:
    published = all_policies()
    for persona in AttackerPersona:
        assert persona.value in published, persona
        assert published[persona.value].rationale.strip()
