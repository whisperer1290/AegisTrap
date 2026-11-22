"""Operator dashboard: data correctness and concealment from attackers."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from aegistrap.config import Settings
from aegistrap.models import AttackerPersona
from aegistrap.store import StateStore


def _attack(client: TestClient) -> None:
    headers = {"user-agent": "sqlmap/1.8.2#stable (https://sqlmap.org)"}
    for path in (
        "/.env",
        "/openapi.json",
        "/api/v1/debug",
        "/api/v1/reports/export?file=../../../../etc/passwd",
    ):
        client.get(path, headers=headers)


# ---------------------------------------------------------------------------
# concealment
# ---------------------------------------------------------------------------


def test_dashboard_is_absent_from_the_public_schema(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert not any(path.startswith("/dashboard") for path in schema["paths"])


def test_dashboard_traffic_does_not_create_honeypot_sessions(
    client: TestClient, store: StateStore
) -> None:
    """An operator refreshing the page must not appear in the profiling data."""
    client.get("/dashboard/api/overview")
    client.get("/dashboard/api/sessions")
    client.get("/dashboard")
    assert store.list_sessions(limit=10) == []


def test_unauthorised_access_is_indistinguishable_from_a_missing_page(
    tmp_path: Any, store: StateStore
) -> None:
    """A 401 at /dashboard would tell a prober the host is instrumented."""
    from aegistrap.main import create_app

    settings = Settings(
        db_path=tmp_path / "guarded.sqlite3",
        report_dir=tmp_path / "reports",
        llm_provider="offline",
        latency_floor_ms=0,
        latency_jitter_ms=0,
        dashboard_token="s3cret",
        auto_report_enabled=False,
        log_level="WARNING",
    )
    settings.ensure_directories()

    with TestClient(create_app(settings)) as guarded:
        blocked = guarded.get("/dashboard/api/overview")
        assert blocked.status_code == 404
        assert blocked.json()["error"] == "not_found"
        assert "www-authenticate" not in blocked.headers

        unknown = guarded.get("/definitely/not/here")
        assert blocked.json()["error"] == unknown.json()["error"]

        allowed = guarded.get("/dashboard/api/overview", headers={"x-dashboard-token": "s3cret"})
        assert allowed.status_code == 200

        via_query = guarded.get("/dashboard/api/overview?token=s3cret")
        assert via_query.status_code == 200


# ---------------------------------------------------------------------------
# data
# ---------------------------------------------------------------------------


def test_overview_reports_live_activity(client: TestClient) -> None:
    _attack(client)
    body = client.get("/dashboard/api/overview").json()

    assert body["stats"]["sessions"] == 1
    assert body["stats"]["requests"] >= 4
    assert body["stats"]["personas"]
    assert body["engine"]["provider"] == "offline"
    assert "reporter" in body or "engine" in body


def test_session_list_exposes_personas_and_signals(client: TestClient) -> None:
    _attack(client)
    items = client.get("/dashboard/api/sessions").json()["items"]
    assert len(items) == 1
    session = items[0]
    assert session["persona"] in {p.value for p in AttackerPersona}
    assert session["requests"] >= 4
    assert session["signals"]
    assert 0.0 <= session["persona_confidence"] <= 1.0


def test_session_detail_includes_the_transcript_and_analysis(
    client: TestClient, store: StateStore
) -> None:
    _attack(client)
    session_id = store.list_sessions(limit=1)[0].id
    detail = client.get(f"/dashboard/api/sessions/{session_id}").json()

    assert detail["session"]["id"] == session_id
    assert len(detail["events"]) >= 4
    first = detail["events"][0]
    for key in ("seq", "ts", "method", "path", "status", "generator", "weaknesses"):
        assert key in first, key
    analysis = detail["analysis"]
    assert analysis["session_id"] == session_id
    assert analysis["exposed_weaknesses"] or analysis["attack_techniques"]
    assert detail["session"]["persona"]
    assert detail["persona_scores"]


def test_unknown_session_detail_is_a_404(client: TestClient) -> None:
    assert client.get("/dashboard/api/sessions/nope").status_code == 404


def test_reports_can_be_generated_and_read_back(client: TestClient, store: StateStore) -> None:
    _attack(client)
    session_id = store.list_sessions(limit=1)[0].id

    created = client.post(f"/dashboard/api/sessions/{session_id}/report")
    assert created.status_code == 200
    report_id = created.json()["report_id"]
    assert report_id

    listing = client.get("/dashboard/api/reports").json()["items"]
    entry = next(item for item in listing if item["id"] == report_id)
    assert entry["session_id"] == session_id
    assert entry["title"]

    detail = client.get(f"/dashboard/api/reports/{report_id}").json()
    assert detail["document"]["session"]["id"] == session_id
    assert detail["markdown"].startswith("#")


def test_unknown_report_is_a_404(client: TestClient) -> None:
    assert client.get("/dashboard/api/reports/nope").status_code == 404


def test_policy_matrix_documents_every_persona(client: TestClient) -> None:
    """The dashboard has to explain *why* a session saw what it saw."""
    body = client.get("/dashboard/api/policies").json()
    published = {row["persona"]: row for row in body["policies"]}

    for persona in AttackerPersona:
        assert persona.value in published, persona
        row = published[persona.value]
        assert row["rationale"]
        assert "unlocked_weaknesses" in row

    benign = published[AttackerPersona.BENIGN.value]
    attacker = published[AttackerPersona.ATTACKER.value]
    assert len(benign["unlocked_weaknesses"]) < len(attacker["unlocked_weaknesses"])
    assert benign["unlocked_weaknesses"] == []


def test_policy_matrix_lists_the_weakness_catalogue(client: TestClient) -> None:
    from aegistrap.intel.catalogue import WEAKNESSES

    body = client.get("/dashboard/api/policies").json()
    catalogue = {w["id"]: w for w in body["catalogue"]}
    assert set(catalogue) == set(WEAKNESSES)
    for weakness_id, row in catalogue.items():
        assert row["min_persona_rank"] == WEAKNESSES[weakness_id].min_persona_rank
        assert row["severity"] == WEAKNESSES[weakness_id].severity


def test_sweep_closes_idle_sessions(client: TestClient, store: StateStore) -> None:
    _attack(client)
    session_id = store.list_sessions(limit=1)[0].id
    store.close_session(session_id)

    result = client.post("/dashboard/api/sweep").json()
    assert set(result) == {"closed", "reports"}
    assert result["reports"] == 0, "auto-reporting is disabled in the test settings"


def test_sweep_writes_reports_when_auto_reporting_is_on(tmp_path: Any, store: StateStore) -> None:
    from aegistrap.main import create_app

    settings = Settings(
        db_path=tmp_path / "auto.sqlite3",
        report_dir=tmp_path / "reports",
        llm_provider="offline",
        latency_floor_ms=0,
        latency_jitter_ms=0,
        dashboard_token="",
        auto_report_enabled=True,
        report_sweep_seconds=3600,
        log_level="WARNING",
    )
    settings.ensure_directories()

    with TestClient(create_app(settings)) as app_client:
        _attack(app_client)
        from aegistrap.store import get_store

        auto_store = get_store(settings.db_path)
        session_id = auto_store.list_sessions(limit=1)[0].id
        auto_store.close_session(session_id)

        result = app_client.post("/dashboard/api/sweep").json()
        assert result["reports"] >= 1
        assert auto_store.get_session(session_id).reported_at is not None


def test_ui_page_is_served(client: TestClient) -> None:
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "AegisTrap" in response.text


@pytest.mark.parametrize("path", ["/dashboard", "/dashboard/"])
def test_both_dashboard_roots_work(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 200
