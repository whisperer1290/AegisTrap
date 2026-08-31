"""Shared domain types: attacker personas, deception policy, captured events."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class AttackerPersona(StrEnum):
    """Skill tiers the profiler assigns to a session (Section 4)."""

    BENIGN = "benign"
    SCRIPT_KIDDIE = "script_kiddie"
    SCANNER = "scanner"
    SKILLED_HUMAN = "skilled_human"
    AI_AGENT = "ai_agent"
    UNKNOWN = "unknown"

    @property
    def label(self) -> str:
        return {
            AttackerPersona.BENIGN: "Benign client",
            AttackerPersona.SCRIPT_KIDDIE: "Script kiddie",
            AttackerPersona.SCANNER: "Automated scanner",
            AttackerPersona.SKILLED_HUMAN: "Skilled human",
            AttackerPersona.AI_AGENT: "Autonomous AI agent",
            AttackerPersona.UNKNOWN: "Unclassified",
        }[self]

    @property
    def skill_rank(self) -> int:
        """Rough ordering used when deciding how much rope to give a session."""
        return {
            AttackerPersona.BENIGN: 0,
            AttackerPersona.UNKNOWN: 1,
            AttackerPersona.SCRIPT_KIDDIE: 2,
            AttackerPersona.SCANNER: 3,
            AttackerPersona.SKILLED_HUMAN: 4,
            AttackerPersona.AI_AGENT: 5,
        }[self]


#: Personas the profiler is allowed to emit as a positive classification.
CLASSIFIABLE_PERSONAS: tuple[AttackerPersona, ...] = (
    AttackerPersona.BENIGN,
    AttackerPersona.SCRIPT_KIDDIE,
    AttackerPersona.SCANNER,
    AttackerPersona.SKILLED_HUMAN,
    AttackerPersona.AI_AGENT,
)


class ErrorVerbosity(StrEnum):
    TERSE = "terse"
    STANDARD = "standard"
    VERBOSE = "verbose"
    DEBUG = "debug"


@dataclass(frozen=True)
class DeceptionPolicy:
    """How much of the fake vulnerability surface to expose to a session.

    This is the mechanism behind the "adapts the LLM's vulnerability surface"
    contribution: the profiler picks a persona, the persona picks a policy, and
    the policy is fed to both the deterministic decoy handlers and the LLM
    prompt.
    """

    persona: AttackerPersona
    error_verbosity: ErrorVerbosity = ErrorVerbosity.STANDARD
    #: Chance a broken-object-level-authorization probe actually returns data.
    idor_leak_probability: float = 0.0
    #: Leak schema/table/field names in error messages.
    leak_schema_hints: bool = False
    #: Advertise the decoy /admin surface in headers or error bodies.
    expose_admin_hints: bool = False
    #: Answer GraphQL introspection queries.
    expose_graphql_introspection: bool = True
    #: Include a fake Python/SQL traceback in 500 responses.
    expose_stack_traces: bool = False
    #: Plant fake credentials or tokens to bait deeper exploitation.
    plant_honey_credentials: bool = False
    #: Cap on list sizes, so cheap enumeration stays cheap.
    max_page_size: int = 50
    #: Whether to spend a real LLM call on this class of session.
    use_llm: bool = True
    #: Extra narrative detail requested from the LLM (field richness).
    narrative_richness: str = "medium"
    #: Human-readable justification, surfaced on the dashboard.
    rationale: str = ""

    def as_prompt_dict(self) -> dict[str, Any]:
        return {
            "attacker_persona": self.persona.value,
            "error_verbosity": self.error_verbosity.value,
            "may_leak_schema_hints": self.leak_schema_hints,
            "may_expose_admin_hints": self.expose_admin_hints,
            "may_include_stack_trace": self.expose_stack_traces,
            "narrative_richness": self.narrative_richness,
            "max_page_size": self.max_page_size,
        }


@dataclass
class CapturedRequest:
    """One attacker request, as seen by the honeypot."""

    session_id: str
    method: str
    path: str
    query_string: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    source_ip: str = ""
    received_at: float = 0.0

    @property
    def user_agent(self) -> str:
        for key, value in self.headers.items():
            if key.lower() == "user-agent":
                return value
        return ""

    @property
    def is_graphql(self) -> bool:
        return self.path.rstrip("/").endswith("/graphql") or self.path.rstrip("/") == "/graphql"


@dataclass
class DecoyResponse:
    """A response produced by the decoy layer, before HTTP serialisation."""

    status_code: int
    payload: Any
    headers: dict[str, str] = field(default_factory=dict)
    #: "template" (deterministic) or "llm" — tracked for the latency/cost metric.
    generator: str = "template"
    #: Names of the seeded weaknesses this response actually exercised.
    exercised_weaknesses: list[str] = field(default_factory=list)
    llm_tokens: int = 0
    llm_latency_ms: float = 0.0
    #: Populated when a state-grounding violation was detected and repaired.
    consistency_violations: list[str] = field(default_factory=list)
