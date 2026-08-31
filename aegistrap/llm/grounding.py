"""State grounding: reconcile generated output against authoritative state.

Section 13 identifies inconsistent invented state as the main failure mode of
LLM honeypots and prescribes the fix: "The LLM should render state, never
invent it." Prompting alone cannot guarantee that, so grounding is enforced
mechanically rather than trusted.

The contract between the decoy layer and the model is:

* the decoy handler computes an **authoritative payload** from the session
  store — every fact an attacker could later re-check,
* the model may **add** plausible sibling fields, prose, and metadata,
* the model may **not** change or drop any authoritative value.

Anything the model alters is reverted and counted. Those counts are exactly the
"number of self-contradictions in fake state across a session" metric in
Section 9, measured directly rather than estimated by hand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_MISSING = object()

#: Keys the model is allowed to own outright, because they are presentation
#: rather than state. Grounded values still win where both supply one.
NARRATIVE_KEYS: frozenset[str] = frozenset(
    {
        "message",
        "detail",
        "hint",
        "description",
        "documentation_url",
        "docs",
        "_debug",
        "trace",
        "suggestion",
        "error_description",
    }
)


@dataclass
class Reconciliation:
    payload: Any
    violations: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.violations


def _scalar_equal(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return abs(float(a) - float(b)) < 1e-9
    return a == b


def _describe(value: Any, limit: int = 40) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def reconcile(grounded: Any, generated: Any, *, path: str = "$") -> Reconciliation:
    """Force authoritative values back into generated output.

    Returns the repaired payload plus a description of every divergence, so a
    session's consistency record explains *what* the model tried to change.
    """
    violations: list[str] = []

    if isinstance(grounded, dict):
        if not isinstance(generated, dict):
            if generated is not _MISSING:
                violations.append(f"{path}: object replaced by {type(generated).__name__}")
            else:
                violations.append(f"{path}: object omitted")
            return Reconciliation(_deepcopy(grounded), violations)

        merged: dict[str, Any] = dict(generated)
        for key, grounded_value in grounded.items():
            supplied = generated.get(key, _MISSING)
            # Prose keys are the model's to rewrite: an error *message* is
            # presentation, so a reworded one is not a factual contradiction.
            # Anything non-textual, or an omission, still falls back to state.
            if (
                key in NARRATIVE_KEYS
                and isinstance(grounded_value, str)
                and isinstance(supplied, str)
                and supplied.strip()
            ):
                merged[key] = supplied
                continue
            child = reconcile(grounded_value, supplied, path=f"{path}.{key}")
            merged[key] = child.payload
            violations.extend(child.violations)
        return Reconciliation(merged, violations)

    if isinstance(grounded, list):
        if not isinstance(generated, list):
            if generated is not _MISSING:
                violations.append(f"{path}: array replaced by {type(generated).__name__}")
            else:
                violations.append(f"{path}: array omitted")
            return Reconciliation(_deepcopy(grounded), violations)
        if len(generated) != len(grounded):
            violations.append(f"{path}: array length changed {len(grounded)} -> {len(generated)}")
        merged_list: list[Any] = []
        for index, grounded_item in enumerate(grounded):
            supplied = generated[index] if index < len(generated) else _MISSING
            child = reconcile(grounded_item, supplied, path=f"{path}[{index}]")
            merged_list.append(child.payload)
            violations.extend(child.violations)
        return Reconciliation(merged_list, violations)

    # Scalar leaf: the authoritative value always wins.
    if generated is _MISSING:
        violations.append(f"{path}: dropped (expected {_describe(grounded)})")
    elif not _scalar_equal(grounded, generated):
        violations.append(f"{path}: {_describe(generated)} contradicts state {_describe(grounded)}")
    return Reconciliation(grounded, violations)


def _deepcopy(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _deepcopy(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_deepcopy(v) for v in value]
    return value


def flatten_facts(payload: Any, *, prefix: str = "$", limit: int = 400) -> dict[str, Any]:
    """Flatten a payload to scalar dot-paths, for prompts and assertions."""
    facts: dict[str, Any] = {}

    def walk(value: Any, path: str) -> None:
        if len(facts) >= limit:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{path}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]")
        else:
            facts[path] = value

    walk(payload, prefix)
    return facts


def contradiction_count(grounded: Any, generated: Any) -> int:
    return len(reconcile(grounded, generated).violations)
