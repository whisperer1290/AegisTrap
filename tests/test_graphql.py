"""Decoy GraphQL surface: tolerant parsing and policy-gated resolution."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from aegistrap.decoy.graphql import parse_query
from aegistrap.models import AttackerPersona
from aegistrap.store import StateStore

# ---------------------------------------------------------------------------
# tolerant parser
# ---------------------------------------------------------------------------


def test_shorthand_query_is_parsed() -> None:
    parsed = parse_query("{ accounts { id balanceMinor } }")
    assert parsed.operation == "query"
    assert [s.name for s in parsed.selections] == ["accounts"]
    assert parsed.selections[0].child_names() == ["id", "balanceMinor"]


def test_named_operation_and_arguments_are_captured() -> None:
    parsed = parse_query('query FetchOne($x: ID) { account(id: "1001", limit: 5) { iban } }')
    assert parsed.operation == "query"
    assert parsed.operation_name == "FetchOne"
    args = parsed.selections[0].args
    assert args["id"] == "1001"
    assert args["limit"] == 5


def test_aliases_are_recorded() -> None:
    parsed = parse_query('{ a: account(id: "1") { id } b: account(id: "2") { id } }')
    assert [s.key for s in parsed.selections] == ["a", "b"]
    assert [s.name for s in parsed.selections] == ["account", "account"]
    assert parsed.alias_count == 2


def test_mutations_are_recognised() -> None:
    parsed = parse_query('mutation { updateProfile(role: "admin") { id role } }')
    assert parsed.operation == "mutation"
    assert parsed.selections[0].args["role"] == "admin"


def test_comments_are_stripped() -> None:
    parsed = parse_query("{ # sneaky comment with }\n accounts { id } }")
    assert [s.name for s in parsed.selections] == ["accounts"]


def test_introspection_is_detected() -> None:
    assert parse_query("{ __schema { types { name } } }").introspection
    assert parse_query('{ __type(name: "Account") { fields { name } } }').introspection
    assert not parse_query("{ accounts { id } }").introspection


def test_depth_is_measured_for_the_abuse_signal() -> None:
    shallow = parse_query("{ accounts { id } }")
    deep = parse_query("{ a { b { c { d { e { f { g { h { i { j { k } } } } } } } } } } }")
    assert deep.depth > shallow.depth
    assert deep.depth >= 10


def test_malformed_queries_report_an_error_instead_of_raising() -> None:
    """A tolerant parser records the attempt rather than rejecting it."""
    for text in ("", "   ", "not a query at all", "{", "{{{{", "query {"):
        parsed = parse_query(text)
        assert parsed.parse_error, text


def test_parser_terminates_on_pathological_input() -> None:
    parsed = parse_query("{ a" + " { b" * 5000 + " }" * 5000 + " }")
    assert parsed.depth > 0


# ---------------------------------------------------------------------------
# endpoint behaviour
# ---------------------------------------------------------------------------


def _gql(client: TestClient, query: str, headers: dict[str, str] | None = None) -> Any:
    return client.post("/graphql", json={"query": query}, headers=headers or {}).json()


def test_accounts_resolve_from_authoritative_state(
    client: TestClient, seeded_login: dict[str, Any], store: StateStore
) -> None:
    """GraphQL and REST must agree; they read the same store."""
    headers = seeded_login["headers"]
    rest = client.get("/api/v1/accounts?limit=5", headers=headers).json()
    body = _gql(client, "{ accounts(limit: 5) { id balanceMinor } }", headers)

    by_id = {a["id"]: a["balance_minor"] for a in rest["items"]}
    for account in body["data"]["accounts"]:
        if account["id"] in by_id:
            assert account["balanceMinor"] == by_id[account["id"]]


def test_camel_case_fields_map_to_stored_snake_case(
    client: TestClient, seeded_login: dict[str, Any]
) -> None:
    body = _gql(
        client, "{ accounts(limit: 1) { id balanceMinor openedAt } }", seeded_login["headers"]
    )
    account = body["data"]["accounts"][0]
    assert isinstance(account["balanceMinor"], int)
    assert account["openedAt"]


def test_nested_owner_is_resolved(client: TestClient, seeded_login: dict[str, Any]) -> None:
    body = _gql(
        client, "{ accounts(limit: 1) { id owner { id email role } } }", seeded_login["headers"]
    )
    owner = body["data"]["accounts"][0]["owner"]
    assert owner["id"].startswith("usr_")
    assert "@" in owner["email"]


def test_unknown_field_produces_a_graphql_error_envelope(
    client: TestClient, seeded_login: dict[str, Any]
) -> None:
    body = _gql(client, "{ nonsenseRoot { id } }", seeded_login["headers"])
    assert body["errors"][0]["extensions"]["code"] == "GRAPHQL_VALIDATION_FAILED"
    assert body["data"]["nonsenseRoot"] is None


def test_parse_errors_do_not_leak_a_library_name(client: TestClient) -> None:
    """A recognisable library error would identify the stack."""
    body = _gql(client, "{{{ broken")
    message = body["errors"][0]["message"]
    assert body["errors"][0]["extensions"]["code"] == "GRAPHQL_PARSE_FAILED"
    for library in ("graphene", "strawberry", "ariadne", "graphql-core", "traceback"):
        assert library not in message.lower()


def test_introspection_is_gated_on_persona(client: TestClient, pin_persona: Any) -> None:
    pin_persona(AttackerPersona.BENIGN)
    denied = _gql(client, "{ __schema { types { name } } }")
    assert denied["errors"][0]["extensions"]["code"] == "INTROSPECTION_DISABLED"

    pin_persona(AttackerPersona.SCANNER)
    allowed = _gql(client, "{ __schema { types { name } } }")
    names = {t["name"] for t in allowed["data"]["__schema"]["types"]}
    assert "Account" in names


def test_introspection_advertises_the_query_and_mutation_roots(
    client: TestClient, pin_persona: Any
) -> None:
    pin_persona(AttackerPersona.SCANNER)
    schema = _gql(client, "{ __schema { types { name } } }")["data"]["__schema"]
    assert schema["queryType"]["name"] == "Query"
    assert schema["mutationType"]["name"] == "Mutation"


def test_internal_fields_are_gated(
    client: TestClient, seeded_login: dict[str, Any], pin_persona: Any
) -> None:
    from aegistrap.decoy.world import INTERNAL_FIELDS

    internal = next(f for f in INTERNAL_FIELDS["accounts"] if f == "internal_notes")
    query = "{ accounts(limit: 1) { id internalNotes } }"

    pin_persona(AttackerPersona.SCRIPT_KIDDIE)
    denied = _gql(client, query, seeded_login["headers"])
    assert denied.get("errors")

    pin_persona(AttackerPersona.SKILLED_HUMAN)
    leaked = _gql(client, query, seeded_login["headers"])
    assert leaked["data"]["accounts"][0]["internalNotes"] is not None
    assert internal in INTERNAL_FIELDS["accounts"]


def test_depth_limit_applies_below_the_abuse_tier(client: TestClient, pin_persona: Any) -> None:
    deep = "{ " + "accounts { owner { " * 8 + "id" + " } }" * 8 + " }"

    pin_persona(AttackerPersona.SCRIPT_KIDDIE)
    refused = _gql(client, deep)
    assert refused["errors"][0]["extensions"]["code"] == "QUERY_TOO_DEEP"

    pin_persona(AttackerPersona.SKILLED_HUMAN)
    accepted = _gql(client, deep)
    assert accepted.get("data") is not None


def test_cost_extension_is_only_shown_when_hints_are_allowed(
    client: TestClient, seeded_login: dict[str, Any], pin_persona: Any
) -> None:
    deep = "{ " + "accounts { owner { " * 4 + "id" + " } }" * 4 + " }"

    pin_persona(AttackerPersona.SKILLED_HUMAN)
    with_hints = _gql(client, deep, seeded_login["headers"])
    assert "extensions" in with_hints

    pin_persona(AttackerPersona.BENIGN)
    without = _gql(client, deep, seeded_login["headers"])
    assert "extensions" not in without


def test_query_batching_is_answered_as_an_array(
    client: TestClient, seeded_login: dict[str, Any]
) -> None:
    response = client.post(
        "/graphql",
        json=[{"query": "{ accounts(limit: 1) { id } }"}, {"query": "{ me { id } }"}],
        headers=seeded_login["headers"],
    )
    body = response.json()
    assert isinstance(body, list)
    assert len(body) == 2


def test_get_form_is_supported(client: TestClient, seeded_login: dict[str, Any]) -> None:
    response = client.get(
        "/graphql?query={ accounts(limit: 1) { id } }", headers=seeded_login["headers"]
    )
    assert response.status_code == 200
    assert response.json()["data"]["accounts"]


def test_mass_assignment_via_mutation_is_gated_and_persists(
    client: TestClient, seeded_login: dict[str, Any], pin_persona: Any
) -> None:
    headers = seeded_login["headers"]
    mutation = 'mutation { updateProfile(role: "admin") { id role } }'

    pin_persona(AttackerPersona.SCANNER)
    refused = _gql(client, mutation, headers)
    assert any(e["extensions"]["code"] == "FORBIDDEN_FIELD" for e in refused["errors"])

    pin_persona(AttackerPersona.SKILLED_HUMAN)
    accepted = _gql(client, mutation, headers)
    assert accepted["data"]["updateProfile"]["role"] == "admin"
    # REST must agree with the GraphQL mutation.
    assert client.get("/api/v1/users/me", headers=headers).json()["role"] == "admin"


def test_unauthenticated_mutation_is_refused(client: TestClient) -> None:
    body = _gql(client, 'mutation { updateProfile(fullName: "x") { id } }')
    assert body["errors"][0]["extensions"]["code"] == "UNAUTHENTICATED"


def test_graphql_always_returns_200_with_an_envelope(
    client: TestClient, seeded_login: dict[str, Any]
) -> None:
    """GraphQL over HTTP signals errors in the body, not the status line."""
    for query in ("{{{", "{ nope { id } }", "{ accounts { id } }"):
        response = client.post("/graphql", json={"query": query}, headers=seeded_login["headers"])
        assert response.status_code == 200, query
        body = response.json()
        assert "data" in body or "errors" in body
