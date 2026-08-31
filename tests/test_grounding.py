"""State grounding: the mechanism that stops the LLM inventing state."""

from __future__ import annotations

from aegistrap.llm.grounding import contradiction_count, flatten_facts, reconcile


def test_additive_enrichment_is_allowed() -> None:
    grounded = {"id": "1004", "balance_minor": 481233}
    generated = {
        "id": "1004",
        "balance_minor": 481233,
        "balance_formatted": "4812.33",
        "request_id": "req_abc",
    }
    result = reconcile(grounded, generated)
    assert result.clean
    assert result.payload["balance_formatted"] == "4812.33"
    assert result.payload["balance_minor"] == 481233


def test_altered_value_is_reverted_and_reported() -> None:
    grounded = {"balance_minor": 481233}
    result = reconcile(grounded, {"balance_minor": 481000})
    assert result.payload["balance_minor"] == 481233
    assert len(result.violations) == 1
    assert "contradicts state" in result.violations[0]


def test_dropped_key_is_restored() -> None:
    grounded = {"id": "1004", "status": "open"}
    result = reconcile(grounded, {"id": "1004"})
    assert result.payload["status"] == "open"
    assert any("dropped" in v for v in result.violations)


def test_reformatting_a_number_counts_as_a_contradiction() -> None:
    """A currency-formatted string is a contradiction, not a presentation choice.

    An attacker who reads ``balance_minor`` twice must see the same integer.
    """
    result = reconcile({"balance_minor": 481233}, {"balance_minor": "4,812.33 EUR"})
    assert result.payload["balance_minor"] == 481233
    assert len(result.violations) == 1


def test_int_float_equivalence_is_not_a_violation() -> None:
    assert reconcile({"n": 5}, {"n": 5.0}).clean


def test_booleans_are_compared_strictly() -> None:
    # 1 == True numerically, but a JSON API returning 1 for a boolean field is
    # a visible inconsistency.
    assert not reconcile({"mfa_enabled": True}, {"mfa_enabled": 1}).clean
    assert reconcile({"mfa_enabled": False}, {"mfa_enabled": False}).clean


def test_nested_structures_are_walked() -> None:
    grounded = {"principal": {"id": "usr_1", "role": "customer"}}
    result = reconcile(grounded, {"principal": {"id": "usr_1", "role": "admin"}})
    assert result.payload["principal"]["role"] == "customer"
    assert "$.principal.role" in result.violations[0]


def test_privilege_escalation_via_generation_is_blocked() -> None:
    """The model must not be able to grant a role the state does not give."""
    grounded = {"role": "customer", "scopes": ["accounts:read"]}
    generated = {"role": "admin", "scopes": ["admin"]}
    result = reconcile(grounded, generated)
    assert result.payload["role"] == "customer"
    assert result.payload["scopes"] == ["accounts:read"]


def test_array_length_and_items_are_enforced() -> None:
    grounded = {"items": [{"id": "1"}, {"id": "2"}], "total": 2}
    result = reconcile(grounded, {"items": [{"id": "1"}], "total": 2})
    assert len(result.payload["items"]) == 2
    assert result.payload["items"][1]["id"] == "2"
    assert any("array length changed" in v for v in result.violations)


def test_invented_records_are_removed() -> None:
    grounded = {"items": [{"id": "1001"}], "total": 1}
    generated = {"items": [{"id": "1001"}, {"id": "9999"}], "total": 1}
    result = reconcile(grounded, generated)
    assert [item["id"] for item in result.payload["items"]] == ["1001"]


def test_type_substitution_is_repaired() -> None:
    result = reconcile({"items": [1, 2]}, {"items": "none"})
    assert result.payload["items"] == [1, 2]
    assert any("array replaced" in v for v in result.violations)

    result = reconcile({"meta": {"a": 1}}, {"meta": 7})
    assert result.payload["meta"] == {"a": 1}


def test_prose_keys_may_be_rewritten_freely() -> None:
    """Rewording an error message is presentation, not a contradiction."""
    grounded = {"error": "not_found", "message": "Account 1004 does not exist."}
    result = reconcile(
        grounded,
        {
            "error": "not_found",
            "message": "We could not locate account 1004 on this tenant.",
        },
    )
    assert result.clean
    assert result.payload["message"].startswith("We could not locate")
    # The machine-readable code is state and is still pinned.
    assert result.payload["error"] == "not_found"


def test_prose_keys_fall_back_to_state_when_omitted_or_blank() -> None:
    grounded = {"message": "Account 1004 does not exist."}
    assert reconcile(grounded, {}).payload["message"] == grounded["message"]
    assert reconcile(grounded, {"message": "   "}).payload["message"] == grounded["message"]
    assert reconcile(grounded, {"message": 404}).payload["message"] == grounded["message"]


def test_flatten_facts_produces_scalar_paths() -> None:
    facts = flatten_facts({"a": {"b": [1, {"c": "x"}]}})
    assert facts["$.a.b[0]"] == 1
    assert facts["$.a.b[1].c"] == "x"


def test_contradiction_count_is_the_consistency_metric() -> None:
    grounded = {"a": 1, "b": 2, "c": {"d": 3}}
    assert contradiction_count(grounded, grounded) == 0
    assert contradiction_count(grounded, {"a": 9, "c": {"d": 8}}) == 3
