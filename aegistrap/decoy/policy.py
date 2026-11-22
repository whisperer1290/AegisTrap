"""Benign-vs-attacker deception policy.

The profiler infers whether a session is attacking, and the policy decides how
much of the seeded vulnerability surface to expose. Concretely it controls
error verbosity, which seeded weaknesses are reachable, whether a real LLM
call is worth spending, and how much narrative detail the model should produce.

* **Benign** clients get a boring, correct-looking API. There is nothing to
  gain from baiting traffic that is not attacking.
* **Unknown** sessions stay plausible: a little introspection, no deep bait.
* **Attackers** get the deep surface: schema hints, stack traces, planted
  credentials, admin routes. They are the sessions worth the tokens.
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
    AttackerPersona.ATTACKER: DeceptionPolicy(
        persona=AttackerPersona.ATTACKER,
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
            "Session is attacking: expose the seeded vulnerability surface and "
            "spend generation budget on consistent, bait-rich responses."
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
    the neutral ``UNKNOWN`` tier rather than opening the attack surface on a
    weak guess.
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
        return weakness.min_persona_rank <= 2
    return policy.persona.skill_rank >= weakness.min_persona_rank


def unlocked_weaknesses(policy: DeceptionPolicy) -> list[str]:
    return [wid for wid in WEAKNESSES if weakness_unlocked(wid, policy)]


def all_policies() -> dict[str, DeceptionPolicy]:
    """Exposed for the dashboard's policy-matrix view."""
    return {persona.value: policy for persona, policy in _POLICIES.items()}
