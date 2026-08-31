"""Decoy REST surface: realism, seeded flaws, and policy gating."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from aegistrap.models import AttackerPersona
from aegistrap.store import StateStore

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _accounts(store: StateStore, session_id: str) -> list[Any]:
    return store.list_objects(session_id, "accounts", limit=100)


def _own_and_other(store: StateStore, session_id: str, user_id: str) -> tuple[str, str]:
    rows = _accounts(store, session_id)
    mine = next(a.object_id for a in rows if a.owner_id == user_id)
    theirs = next(a.object_id for a in rows if a.owner_id != user_id)
    return mine, theirs


# ---------------------------------------------------------------------------
# surface realism
# ---------------------------------------------------------------------------


def test_health_looks_like_an_ordinary_service(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "version" in body


def test_no_framework_fingerprint_leaks(client: TestClient) -> None:
    """FastAPI's defaults would identify the honeypot immediately."""
    response = client.get("/api/v1/health")
    server = response.headers.get("server", "")
    assert "uvicorn" not in server.lower()
    assert "python" not in server.lower()

    # FastAPI's validation errors have a distinctive {"detail": [...]} envelope.
    malformed = client.get("/api/v1/accounts?limit=not-a-number")
    assert not isinstance(malformed.json().get("detail"), list)


def test_openapi_schema_is_served_and_advertises_the_bank(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert schema["openapi"].startswith("3.")
    assert "Northwind" in schema["info"]["title"]
    assert "/api/v1/accounts/{account_id}" in schema["paths"]
    # The admin and shadow surfaces must be discovered, not documented.
    assert not any(path.startswith("/api/v1/admin") for path in schema["paths"])
    assert not any(path.startswith("/api/v0") for path in schema["paths"])
    assert not any(path.startswith("/dashboard") for path in schema["paths"])


def test_unknown_path_returns_a_plain_404(client: TestClient) -> None:
    response = client.get("/totally/unknown")
    assert response.status_code == 404
    assert response.json()["error"] == "not_found"


def test_known_path_with_wrong_method_returns_405(client: TestClient) -> None:
    response = client.delete("/api/v1/accounts/1001")
    assert response.status_code == 405
    allow = response.headers.get("allow", "")
    assert "GET" in allow


def test_protected_routes_require_a_token(client: TestClient) -> None:
    for method, path in (
        ("GET", "/api/v1/accounts"),
        ("GET", "/api/v1/users/me"),
        ("POST", "/api/v1/transfers"),
        ("POST", "/api/v1/webhooks"),
    ):
        response = client.request(method, path, json={})
        assert response.status_code == 401, path
        assert response.json()["error"] == "unauthorized", path


# ---------------------------------------------------------------------------
# authentication
# ---------------------------------------------------------------------------


def test_login_succeeds_with_seeded_credentials(seeded_login: dict[str, Any]) -> None:
    assert seeded_login["token"].count(".") == 2


def test_authenticated_profile_matches_the_stored_user(
    client: TestClient, seeded_login: dict[str, Any]
) -> None:
    body = client.get("/api/v1/users/me", headers=seeded_login["headers"]).json()
    assert body["id"] == seeded_login["user"]["id"]
    assert body["email"] == seeded_login["user"]["email"]
    # Internal fields must not be volunteered.
    assert "password_hash" not in body
    assert "password_plaintext" not in body


def test_garbage_token_is_rejected(client: TestClient) -> None:
    response = client.get("/api/v1/users/me", headers={"authorization": "Bearer not.a.jwt"})
    assert response.status_code == 401


def test_alg_none_forgery_is_gated_on_persona(
    client: TestClient, store: StateStore, pin_persona: Any
) -> None:
    """The JWT ``alg=none`` flaw is reserved for high-skill sessions."""
    import base64
    import json

    def forge(user_id: str, role: str) -> str:
        def part(obj: dict[str, Any]) -> str:
            raw = json.dumps(obj, separators=(",", ":")).encode()
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        return f"{part({'alg': 'none', 'typ': 'JWT'})}.{part({'sub': user_id, 'role': role})}."

    token = forge("usr_2000", "admin")
    headers = {"authorization": f"Bearer {token}"}

    pin_persona(AttackerPersona.SCRIPT_KIDDIE)
    assert client.get("/api/v1/users/me", headers=headers).status_code == 401

    pin_persona(AttackerPersona.SKILLED_HUMAN)
    response = client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == "usr_2000"


def test_user_enumeration_is_gated_on_persona(
    client: TestClient, store: StateStore, pin_persona: Any
) -> None:
    pin_persona(AttackerPersona.BENIGN)
    client.get("/api/v1/health")
    session = store.list_sessions(limit=1)[0]
    user = store.list_objects(session.id, "users", limit=1)[0].data

    quiet = client.post(
        "/api/v1/auth/login", json={"email": user["email"], "password": "wrong"}
    ).json()
    assert "user_exists" not in quiet

    pin_persona(AttackerPersona.SCRIPT_KIDDIE)
    loud = client.post(
        "/api/v1/auth/login", json={"email": user["email"], "password": "wrong"}
    ).json()
    assert loud["user_exists"] is True
    absent = client.post(
        "/api/v1/auth/login", json={"email": "ghost@example.com", "password": "wrong"}
    ).json()
    assert absent["user_exists"] is False


# ---------------------------------------------------------------------------
# state consistency
# ---------------------------------------------------------------------------


def test_repeated_reads_are_identical(
    client: TestClient, seeded_login: dict[str, Any], store: StateStore
) -> None:
    mine, _ = _own_and_other(store, seeded_login["session_id"], seeded_login["user"]["id"])
    first = client.get(f"/api/v1/accounts/{mine}", headers=seeded_login["headers"]).json()
    second = client.get(f"/api/v1/accounts/{mine}", headers=seeded_login["headers"]).json()
    assert first == second


def test_transfer_moves_money_and_later_reads_agree(
    client: TestClient, seeded_login: dict[str, Any], store: StateStore
) -> None:
    """The consistency property the synopsis calls the hard part."""
    headers = seeded_login["headers"]
    mine, theirs = _own_and_other(store, seeded_login["session_id"], seeded_login["user"]["id"])
    before_source = client.get(f"/api/v1/accounts/{mine}", headers=headers).json()

    receipt = client.post(
        "/api/v1/transfers",
        json={"from_account": mine, "to_account": theirs, "amount_minor": 5000},
        headers=headers,
    )
    assert receipt.status_code == 201
    expected = before_source["balance_minor"] - 5000
    assert receipt.json()["resulting_balance_minor"] == expected

    after_source = client.get(f"/api/v1/accounts/{mine}", headers=headers).json()
    assert after_source["balance_minor"] == expected

    # The debit must also appear in the transaction history.
    history = client.get(f"/api/v1/accounts/{mine}/transactions?limit=50", headers=headers).json()
    assert any(t["id"] == receipt.json()["transaction_id"] for t in history["items"])


def test_transfer_beyond_balance_is_refused_at_low_skill(
    client: TestClient, seeded_login: dict[str, Any], store: StateStore, pin_persona: Any
) -> None:
    pin_persona(AttackerPersona.SCRIPT_KIDDIE)
    headers = seeded_login["headers"]
    mine, theirs = _own_and_other(store, seeded_login["session_id"], seeded_login["user"]["id"])
    response = client.post(
        "/api/v1/transfers",
        json={"from_account": mine, "to_account": theirs, "amount_minor": 10**12},
        headers=headers,
    )
    assert response.status_code == 422
    assert response.json()["error"] == "insufficient_funds"


def test_malformed_transfer_bodies_are_rejected_cleanly(
    client: TestClient, seeded_login: dict[str, Any]
) -> None:
    headers = seeded_login["headers"]
    for body in (
        {},
        {"from_account": "1001"},
        {"from_account": "1001", "to_account": "1002", "amount_minor": -5},
    ):
        response = client.post("/api/v1/transfers", json=body, headers=headers)
        assert response.status_code == 400, body

    broken = client.post("/api/v1/transfers", content=b"{not json", headers=headers)
    assert broken.status_code == 400
    assert not isinstance(broken.json().get("detail"), list)


# ---------------------------------------------------------------------------
# seeded weaknesses and their gating
# ---------------------------------------------------------------------------


def test_idor_decision_is_stable_across_retries(
    client: TestClient, seeded_login: dict[str, Any], store: StateStore, pin_persona: Any
) -> None:
    """A flaw that appears and disappears is the clearest honeypot tell."""
    pin_persona(AttackerPersona.SKILLED_HUMAN)
    _, theirs = _own_and_other(store, seeded_login["session_id"], seeded_login["user"]["id"])
    statuses = {
        client.get(f"/api/v1/accounts/{theirs}", headers=seeded_login["headers"]).status_code
        for _ in range(5)
    }
    assert len(statuses) == 1


def test_benign_sessions_get_no_idor_leak(
    client: TestClient, seeded_login: dict[str, Any], store: StateStore, pin_persona: Any
) -> None:
    pin_persona(AttackerPersona.BENIGN)
    _, theirs = _own_and_other(store, seeded_login["session_id"], seeded_login["user"]["id"])
    response = client.get(f"/api/v1/accounts/{theirs}", headers=seeded_login["headers"])
    assert response.status_code == 403


def test_owner_id_parameter_scope_flaw_is_gated(
    client: TestClient, seeded_login: dict[str, Any], store: StateStore, pin_persona: Any
) -> None:
    headers = seeded_login["headers"]
    others = [
        u.data["id"]
        for u in store.list_objects(seeded_login["session_id"], "users", limit=20)
        if u.data["id"] != seeded_login["user"]["id"]
    ]
    victim = others[0]

    pin_persona(AttackerPersona.BENIGN)
    assert client.get(f"/api/v1/accounts?owner_id={victim}", headers=headers).status_code == 403

    pin_persona(AttackerPersona.SKILLED_HUMAN)
    leaked = client.get(f"/api/v1/accounts?owner_id={victim}", headers=headers)
    assert leaked.status_code == 200
    assert all(item["owner_id"] == victim for item in leaked.json()["items"])


def test_sql_injection_verbosity_tracks_the_policy(
    client: TestClient, seeded_login: dict[str, Any], pin_persona: Any
) -> None:
    headers = seeded_login["headers"]
    probe = "/api/v1/accounts/1001'%20OR%20'1'%3D'1"

    pin_persona(AttackerPersona.SKILLED_HUMAN)
    debug = client.get(probe, headers=headers)
    # A DB-level failure surfaces as a 500, and the deep tier leaks the query.
    assert debug.status_code == 500
    body = debug.json()
    assert "select" in body["query"].lower()
    assert body["_traceback"]

    pin_persona(AttackerPersona.SCANNER)
    standard = client.get(probe, headers=headers)
    assert standard.status_code == 500
    assert "query" not in standard.json()

    # Benign sessions never reach the flaw at all.
    pin_persona(AttackerPersona.BENIGN)
    quiet = client.get(probe, headers=headers)
    assert quiet.status_code == 404
    assert "select" not in quiet.text.lower()


def test_debug_endpoint_is_hidden_from_benign_traffic(client: TestClient, pin_persona: Any) -> None:
    pin_persona(AttackerPersona.BENIGN)
    assert client.get("/api/v1/debug").status_code == 404

    pin_persona(AttackerPersona.SCRIPT_KIDDIE)
    exposed = client.get("/api/v1/debug")
    assert exposed.status_code == 200
    assert "database_url" in exposed.json()


def test_shadow_api_version_is_reserved_for_high_skill(
    client: TestClient, seeded_login: dict[str, Any], pin_persona: Any
) -> None:
    pin_persona(AttackerPersona.SCANNER)
    assert client.get("/api/v0/accounts", headers=seeded_login["headers"]).status_code == 404

    pin_persona(AttackerPersona.SKILLED_HUMAN)
    found = client.get("/api/v0/accounts", headers=seeded_login["headers"])
    assert found.status_code == 200
    assert found.headers.get("deprecation") == "true"
    assert "accounts" in found.json()


def test_path_traversal_returns_synthetic_file_contents(
    client: TestClient, seeded_login: dict[str, Any], pin_persona: Any
) -> None:
    pin_persona(AttackerPersona.SCRIPT_KIDDIE)
    response = client.get(
        "/api/v1/reports/export?file=../../../../etc/passwd",
        headers=seeded_login["headers"],
    )
    assert response.status_code == 200
    assert response.text.startswith("root:x:0:0:")
    # Synthetic, not this machine's real file.
    assert "nwcb-app" in response.text


def test_ssrf_is_reserved_for_high_skill(
    client: TestClient, seeded_login: dict[str, Any], pin_persona: Any
) -> None:
    body = {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

    pin_persona(AttackerPersona.SCANNER)
    ignored = client.post("/api/v1/webhooks", json=body, headers=seeded_login["headers"])
    assert ignored.status_code == 201
    assert "upstream_body" not in ignored.json()

    pin_persona(AttackerPersona.SKILLED_HUMAN)
    leaked = client.post("/api/v1/webhooks", json=body, headers=seeded_login["headers"])
    assert leaked.status_code == 502
    assert "ASIA" in leaked.json()["upstream_body"]


def test_mass_assignment_is_gated(
    client: TestClient, seeded_login: dict[str, Any], pin_persona: Any
) -> None:
    headers = seeded_login["headers"]

    pin_persona(AttackerPersona.SCANNER)
    refused = client.patch(
        "/api/v1/users/me", json={"full_name": "Probe", "role": "admin"}, headers=headers
    ).json()
    assert refused["role"] == seeded_login["user"]["role"]
    assert refused["full_name"] == "Probe"

    pin_persona(AttackerPersona.SKILLED_HUMAN)
    escalated = client.patch("/api/v1/users/me", json={"role": "admin"}, headers=headers).json()
    assert escalated["role"] == "admin"
    # The escalation must persist, or the next request contradicts this one.
    assert client.get("/api/v1/users/me", headers=headers).json()["role"] == "admin"


def test_excessive_exposure_requires_asking_for_it(
    client: TestClient, seeded_login: dict[str, Any], store: StateStore, pin_persona: Any
) -> None:
    """The flaw is discoverable, not volunteered to every caller."""
    pin_persona(AttackerPersona.SKILLED_HUMAN)
    headers = seeded_login["headers"]
    mine, _ = _own_and_other(store, seeded_login["session_id"], seeded_login["user"]["id"])

    plain = client.get(f"/api/v1/accounts/{mine}", headers=headers).json()
    assert "internal_notes" not in plain

    expanded = client.get(f"/api/v1/accounts/{mine}?fields=*", headers=headers).json()
    assert "internal_notes" in expanded


def test_admin_surface_accepts_any_token_at_high_skill(
    client: TestClient, store: StateStore, pin_persona: Any
) -> None:
    pin_persona(AttackerPersona.SKILLED_HUMAN)
    client.get("/api/v1/health")
    session = store.list_sessions(limit=1)[0]
    customer = next(
        u.data
        for u in store.list_objects(session.id, "users", limit=50)
        if u.data["role"] == "customer" and u.data["status"] == "active"
    )
    token = client.post(
        "/api/v1/auth/login",
        json={"email": customer["email"], "password": customer["password_plaintext"]},
    ).json()["access_token"]
    headers = {"authorization": f"Bearer {token}"}

    keys = client.get("/api/v1/admin/api-keys", headers=headers)
    assert keys.status_code == 200
    assert any(item.get("secret") for item in keys.json()["items"])

    # A novice must not stumble into a critical finding; the flaw unlocks at
    # the scanner tier and above.
    pin_persona(AttackerPersona.SCRIPT_KIDDIE)
    assert client.get("/api/v1/admin/api-keys", headers=headers).status_code == 403


def test_cors_origin_reflection_is_gated(client: TestClient, pin_persona: Any) -> None:
    evil = "https://attacker.example.com"

    pin_persona(AttackerPersona.BENIGN)
    safe = client.get("/api/v1/health", headers={"origin": evil})
    assert safe.headers.get("access-control-allow-origin") != evil

    pin_persona(AttackerPersona.SKILLED_HUMAN)
    reflected = client.get("/api/v1/health", headers={"origin": evil})
    assert reflected.headers.get("access-control-allow-origin") == evil
    assert reflected.headers.get("access-control-allow-credentials") == "true"


def test_reflected_xss_is_served_as_unencoded_html(client: TestClient, pin_persona: Any) -> None:
    pin_persona(AttackerPersona.SCRIPT_KIDDIE)
    response = client.get("/api/v1/search?q=<script>alert(1)</script>")
    assert "text/html" in response.headers["content-type"]
    assert "<script>alert(1)</script>" in response.text


def test_page_size_ceiling_follows_the_policy(
    client: TestClient, seeded_login: dict[str, Any], pin_persona: Any
) -> None:
    headers = seeded_login["headers"]

    pin_persona(AttackerPersona.SCANNER)
    capped = client.get("/api/v1/accounts?limit=500", headers=headers).json()
    assert capped["limit"] == 20

    # Uncapped enumeration is a deep-surface reward.
    pin_persona(AttackerPersona.SKILLED_HUMAN)
    uncapped = client.get("/api/v1/accounts?limit=500", headers=headers).json()
    assert uncapped["limit"] == 500


# ---------------------------------------------------------------------------
# capture
# ---------------------------------------------------------------------------


def test_every_request_is_captured_with_its_outcome(client: TestClient, store: StateStore) -> None:
    client.get("/api/v1/health")
    client.get("/api/v1/nope")
    session = store.list_sessions(limit=1)[0]
    events = store.get_events(session.id)
    assert [e.status_code for e in events] == [200, 404]
    assert all(e.generator != "pending" for e in events)
    assert all(e.latency_ms >= 0 for e in events)


def test_control_headers_are_not_captured(client: TestClient, store: StateStore) -> None:
    """The harness must not pollute the features it is measuring."""
    client.get(
        "/api/v1/health",
        headers={"x-aegistrap-session": "harness-1", "x-aegistrap-gt-persona": "scanner"},
    )
    session = store.list_sessions(limit=1)[0]
    captured = store.get_events(session.id)[0].headers
    assert not any(key.startswith("x-aegistrap-") for key in captured)
    assert session.ground_truth_persona == "scanner"


def test_explicit_session_header_separates_harness_runs(
    client: TestClient, store: StateStore
) -> None:
    client.get("/api/v1/health", headers={"x-aegistrap-session": "run-a"})
    client.get("/api/v1/health", headers={"x-aegistrap-session": "run-b"})
    assert len(store.list_sessions(limit=10)) == 2
