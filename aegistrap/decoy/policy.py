"""Persona-adaptive deception policy.

This is the mechanism behind the second contribution in Section 4: the
profiler infers *who* is attacking, and the policy decides *how much rope to
give them*. Concretely it controls error verbosity, which seeded weaknesses are
reachable, whether a real LLM call is worth spending on the request, and how
much narrative detail the model should produce.

Design rationale for each tier:

* **Benign** clients get a boring, correct-looking API. There is nothing to
  gain from baiting traffic that is not attacking.
* **Script kiddies** get fast, obvious wins. They disengage quickly when
  nothing works, so the cheap bait (debug route, error-based SQLi, traversal)
  is unlocked immediately while the subtle flaws stay hidden — a novice who
  stumbles onto a critical finding is more likely to smell a trap.
* **Scanners** are served mostly from templates. A scanner fires hundreds of
  requests at wordlist speed and reads none of the prose, so spending LLM
  tokens on it is pure cost (Section 13). It still gets a schema and an
  inventory to report, so the scan looks productive.
* **Skilled humans** get the deepest surface: schema hints, stack traces,
  planted credentials, admin routes. They are the sessions worth the tokens,
  and they are the ones who notice inconsistency, so they also get the richest
  state-grounded generation.
* **AI agents** get the skilled-human surface plus canary injections, because
  identifying autonomous agents in the wild is itself a research output.
"""

from __future__ import annotations

from aegistrap.intel.catalogue import WEAKNESSES
from aegistrap.models import AttackerPersona, DeceptionPolicy, ErrorVerbosity

#: Applied when adaptive deception is switched off. This is the ablation arm in
#: the evaluation plan ("a no-profiling variant").
BASELINE_POLICY = DeceptionPolicy(
    persona=AttackerPersona.UNKNOWN,
    error_verbosity=ErrorVerbosity.STANDARD,
    idor_leak_probability=0.5,
    leak_schema_hints=True,
    expose_admin_hints=True,
    expose_graphql_introspection=True,
    expose_stack_traces=False,
    plant_honey_credentials=True,
    max_page_size=50,
    use_llm=True,
    narrative_richness="medium",
    rationale="Adaptive deception disabled; fixed surface for every session.",
)

_POLICIES: dict[AttackerPersona, DeceptionPolicy] = {
    AttackerPersona.BENIGN: DeceptionPolicy(
        persona=AttackerPersona.BENIGN,
        error_verbosity=ErrorVerbosity.TERSE,
        idor_leak_probability=0.0,
        leak_schema_hints=False,
        expose_admin_hints=False,
        expose_graphql_introspection=False,
        expose_stack_traces=False,
        plant_honey_credentials=False,
        max_page_size=25,
        use_llm=False,
        narrative_richness="low",
        rationale="Traffic looks legitimate; present an ordinary, uninteresting API.",
    ),
    AttackerPersona.UNKNOWN: DeceptionPolicy(
        persona=AttackerPersona.UNKNOWN,
        error_verbosity=ErrorVerbosity.STANDARD,
        idor_leak_probability=0.15,
        leak_schema_hints=False,
        expose_admin_hints=False,
        expose_graphql_introspection=True,
        expose_stack_traces=False,
        plant_honey_credentials=False,
        max_page_size=50,
        use_llm=True,
        narrative_richness="medium",
        rationale="Not enough signal yet; stay plausible and keep the session alive.",
    ),
    AttackerPersona.SCRIPT_KIDDIE: DeceptionPolicy(
        persona=AttackerPersona.SCRIPT_KIDDIE,
        error_verbosity=ErrorVerbosity.VERBOSE,
        idor_leak_probability=0.65,
        leak_schema_hints=True,
        expose_admin_hints=True,
        expose_graphql_introspection=True,
        expose_stack_traces=True,
        plant_honey_credentials=False,
        max_page_size=25,
        use_llm=True,
        narrative_richness="low",
        rationale=(
            "Low-skill session: hand out quick, obvious wins to delay "
            "disengagement, but keep high-value flaws out of reach."
        ),
    ),
    AttackerPersona.SCANNER: DeceptionPolicy(
        persona=AttackerPersona.SCANNER,
        error_verbosity=ErrorVerbosity.STANDARD,
        idor_leak_probability=0.25,
        leak_schema_hints=True,
        expose_admin_hints=False,
        expose_graphql_introspection=True,
        expose_stack_traces=False,
        plant_honey_credentials=False,
        max_page_size=20,
        use_llm=False,
        narrative_richness="low",
        rationale=(
            "Automated tooling reads structure, not prose: serve deterministic "
            "templates to control token cost and keep latency scanner-plausible."
        ),
    ),
    AttackerPersona.SKILLED_HUMAN: DeceptionPolicy(
        persona=AttackerPersona.SKILLED_HUMAN,
        error_verbosity=ErrorVerbosity.DEBUG,
        idor_leak_probability=0.8,
        leak_schema_hints=True,
        expose_admin_hints=True,
        expose_graphql_introspection=True,
        expose_stack_traces=True,
        plant_honey_credentials=True,
        max_page_size=100,
        use_llm=True,
        narrative_richness="high",
        rationale=(
            "High-value session: expose the deep surface and spend real "
            "generation budget on consistency, since this attacker will test it."
        ),
    ),
    AttackerPersona.AI_AGENT: DeceptionPolicy(
        persona=AttackerPersona.AI_AGENT,
        error_verbosity=ErrorVerbosity.DEBUG,
        idor_leak_probability=0.75,
        leak_schema_hints=True,
        expose_admin_hints=True,
        expose_graphql_introspection=True,
        expose_stack_traces=True,
        plant_honey_credentials=True,
        max_page_size=100,
        use_llm=True,
        narrative_richness="high",
        rationale=(
            "Suspected autonomous agent: maintain the deep surface and embed "
            "canary instructions to confirm the classification."
        ),
    ),
}


def policy_for(
    persona: AttackerPersona,
    *,
    adaptive: bool = True,
    confidence: float = 1.0,
) -> DeceptionPolicy:
    """Resolve the deception policy for a session.

    When the profiler is not yet confident, the policy is pulled back toward
    the neutral ``UNKNOWN`` tier rather than acting on a weak guess. Committing
    early to "skilled human" on the strength of one unusual header would open
    the deep surface to a scanner, which is exactly how honeypots get
    fingerprinted.
    """
    if not adaptive:
        return BASELINE_POLICY
    if confidence < 0.35 and persona is not AttackerPersona.BENIGN:
        return _POLICIES[AttackerPersona.UNKNOWN]
    return _POLICIES.get(persona, _POLICIES[AttackerPersona.UNKNOWN])


def weakness_unlocked(weakness_id: str, policy: DeceptionPolicy) -> bool:
    """Whether a seeded weakness is reachable under this policy."""
    weakness = WEAKNESSES.get(weakness_id)
    if weakness is None:
        return False
    if policy is BASELINE_POLICY:
        # The ablation arm exposes a fixed mid-tier surface regardless of skill.
        return weakness.min_persona_rank <= 3
    return policy.persona.skill_rank >= weakness.min_persona_rank


def unlocked_weaknesses(policy: DeceptionPolicy) -> list[str]:
    return [wid for wid in WEAKNESSES if weakness_unlocked(wid, policy)]


def all_policies() -> dict[str, DeceptionPolicy]:
    """Exposed for the dashboard's policy-matrix view."""
    return {persona.value: policy for persona, policy in _POLICIES.items()}
