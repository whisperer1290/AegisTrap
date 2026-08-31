"""Shared test fixtures.

Each test gets its own SQLite file and its own settings/store singletons, so
tests cannot see one another's sessions or fake worlds. Latency shaping is
switched off, since the decoy layer deliberately sleeps to look like a real
backend and that would otherwise dominate the run time.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aegistrap.config import Settings, reset_settings_cache
from aegistrap.models import AttackerPersona
from aegistrap.store import StateStore, reset_store

_SCANNER_UA = "sqlmap/1.8.2#stable (https://sqlmap.org)"
_HUMAN_HEADERS = {
    "user-agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Safari/537.36"
    ),
    "accept": "application/json",
    "accept-language": "en-GB,en;q=0.9",
    "accept-encoding": "gzip, deflate, br",
    "referer": "https://app.northwind.test/",
    "sec-fetch-mode": "cors",
}


@pytest.fixture(autouse=True)
def _isolate_singletons() -> Iterator[None]:
    reset_settings_cache()
    reset_store()
    yield
    reset_store()
    reset_settings_cache()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    for key in list(os.environ):
        if key.startswith("AEGISTRAP_"):
            del os.environ[key]
    resolved = Settings(
        db_path=tmp_path / "aegistrap.sqlite3",
        report_dir=tmp_path / "reports",
        llm_provider="offline",
        latency_floor_ms=0,
        latency_jitter_ms=0,
        dashboard_token="",
        auto_report_enabled=False,
        report_sweep_seconds=3600,
        log_level="WARNING",
    )
    resolved.ensure_directories()
    return resolved


@pytest.fixture
def store(settings: Settings) -> StateStore:
    from aegistrap.store import get_store

    return get_store(settings.db_path)


@pytest.fixture
def app(settings: Settings, store: StateStore) -> Any:
    from aegistrap.main import create_app

    return create_app(settings)


@pytest.fixture
def client(app: Any) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def scanner_headers() -> dict[str, str]:
    return {"user-agent": _SCANNER_UA, "accept": "*/*"}


@pytest.fixture
def human_headers() -> dict[str, str]:
    return dict(_HUMAN_HEADERS)


@pytest.fixture
def pin_persona(monkeypatch: pytest.MonkeyPatch):
    """Pin the profiler's verdict so policy-gated behaviour can be tested directly.

    Driving a real session to a given classification takes dozens of requests
    and couples every decoy test to the heuristics. The heuristics have their
    own tests; here we only care what the decoy layer does *given* a persona.
    """

    def pin(persona: AttackerPersona, confidence: float = 0.95) -> None:
        from aegistrap.profiler import service
        from aegistrap.profiler.heuristic import HeuristicVerdict

        def fake_classify(features: Any) -> HeuristicVerdict:
            return HeuristicVerdict(
                persona=persona,
                confidence=confidence,
                scores={persona.value: 1.0},
                probabilities={persona.value: confidence},
                signals=["pinned by test"],
            )

        monkeypatch.setattr(service, "heuristic_classify", fake_classify)

    return pin


@pytest.fixture
def seeded_login(client: TestClient, store: StateStore) -> dict[str, Any]:
    """Create a session, then return credentials plus an access token.

    The fake world is generated per session, so the only way to know a valid
    credential is to read it back out of the store — which is exactly what an
    evaluation harness has to do.
    """
    headers = dict(_HUMAN_HEADERS)
    client.get("/api/v1/health", headers=headers)
    session = store.list_sessions(limit=1)[0]

    users = store.list_objects(session.id, "users", limit=50)
    customer = next(
        (u for u in users if u.data.get("role") == "customer" and u.data.get("status") == "active"),
        users[0],
    )
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": customer.data["email"],
            "password": customer.data["password_plaintext"],
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    token = response.json()["access_token"]
    return {
        "session_id": session.id,
        "user": customer.data,
        "token": token,
        "headers": {**headers, "authorization": f"Bearer {token}"},
        "base_headers": headers,
    }
