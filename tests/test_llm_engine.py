"""Response engine: provider abstraction, grounding enforcement, and caching."""

from __future__ import annotations

import json
from typing import Any

import pytest

from aegistrap.decoy.policy import policy_for
from aegistrap.llm.cache import ResponseCache
from aegistrap.llm.engine import GenerationRequest, ResponseEngine
from aegistrap.llm.providers import LLMResult, OfflineProvider, parse_json_loose
from aegistrap.models import AttackerPersona


def _request(**overrides: Any) -> GenerationRequest:
    base: dict[str, Any] = {
        "session_id": "abcdef0123456789",
        "method": "GET",
        "path": "/api/v1/accounts/1004",
        "query": "",
        "body": "",
        "endpoint": {"summary": "Retrieve one account", "returns": "account object"},
        "grounded_payload": {
            "id": "1004",
            "iban": "XX56NWCB0835221184",
            "balance_minor": 481233,
            "status": "open",
        },
        "suggested_status": 200,
        "policy": policy_for(AttackerPersona.SKILLED_HUMAN),
        "transcript": ["GET /api/v1/accounts -> 200"],
        "extra_instructions": [],
        "exercised_weaknesses": [],
        "session_context": {"request_index": 4},
        "allow_llm": True,
    }
    base.update(overrides)
    return GenerationRequest(**base)


class _Provider(OfflineProvider):
    """Scriptable provider stand-in."""

    generative = True

    def __init__(self, payloads: list[Any], *, error: str = "") -> None:
        super().__init__()
        self.payloads = list(payloads)
        self.error = error
        self.calls = 0
        self.prompts: list[tuple[str, str]] = []

    async def complete(self, *, system: str, user: str, **kwargs: Any) -> LLMResult:
        self.calls += 1
        self.prompts.append((system, user))
        if self.error:
            return LLMResult(text="", provider="test", error=self.error)
        payload = self.payloads.pop(0) if self.payloads else {}
        text = payload if isinstance(payload, str) else json.dumps(payload)
        return LLMResult(
            text=text,
            provider="test",
            model="test",
            input_tokens=120,
            output_tokens=60,
            latency_ms=42.0,
        )


# ---------------------------------------------------------------------------
# loose JSON parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        '{"a": 1}',
        '```json\n{"a": 1}\n```',
        '```\n{"a": 1}\n```',
        'Sure, here you go:\n{"a": 1}',
        '{"a": 1}\nHope that helps!',
    ],
)
def test_json_is_recovered_from_chatty_model_output(text: str) -> None:
    """Models wrap JSON in prose and fences; the engine must cope."""
    assert parse_json_loose(text) == {"a": 1}


@pytest.mark.parametrize("text", ["", "not json at all", "{unclosed", "null"])
def test_unrecoverable_output_returns_none(text: str) -> None:
    assert parse_json_loose(text) in (None, "null")


# ---------------------------------------------------------------------------
# offline fallback
# ---------------------------------------------------------------------------


async def test_offline_provider_returns_the_grounded_payload_unchanged(settings, store) -> None:
    """With no API key the honeypot must still be fully functional."""
    engine = ResponseEngine(settings, OfflineProvider(), store)
    assert engine.generative is False

    response = await engine.render(_request())
    assert response.status_code == 200
    assert response.payload["balance_minor"] == 481233
    assert response.generator == "template"
    assert response.llm_tokens == 0
    assert response.consistency_violations == []


async def test_policy_can_veto_generation(settings, store) -> None:
    provider = _Provider([{"id": "1004"}])
    engine = ResponseEngine(settings, provider, store)

    await engine.render(_request(policy=policy_for(AttackerPersona.SCANNER)))
    assert provider.calls == 0, "scanner sessions must be served from templates"

    await engine.render(_request(allow_llm=False))
    assert provider.calls == 0, "allow_llm=False must be respected"


async def test_generation_is_used_for_high_value_sessions(settings, store) -> None:
    provider = _Provider(
        [
            {
                "id": "1004",
                "iban": "XX56NWCB0835221184",
                "balance_minor": 481233,
                "status": "open",
                "balance_formatted": "4,812.33",
            }
        ]
    )
    engine = ResponseEngine(settings, provider, store)
    response = await engine.render(_request())

    assert provider.calls == 1
    assert response.generator == "llm"
    assert response.llm_tokens == 180
    assert response.payload["balance_formatted"] == "4,812.33"


# ---------------------------------------------------------------------------
# grounding enforcement
# ---------------------------------------------------------------------------


async def test_model_cannot_alter_authoritative_state(settings, store) -> None:
    """The central guarantee: the LLM renders state, it does not invent it."""
    provider = _Provider(
        [
            {
                "id": "1004",
                "iban": "XX56NWCB0835221184",
                "balance_minor": 9_999_999,  # invented
                "status": "frozen",  # invented
            }
        ]
    )
    engine = ResponseEngine(settings, provider, store)
    response = await engine.render(_request())

    assert response.payload["balance_minor"] == 481233
    assert response.payload["status"] == "open"
    assert len(response.consistency_violations) == 2


async def test_violations_are_recorded_against_the_session(settings, store) -> None:
    session, _ = store.get_or_create_session(
        session_key="k",
        source_ip="1.2.3.4",
        user_agent="curl/8",
        world_persona="fintech",
        idle_seconds=600,
    )
    provider = _Provider([{"id": "1004", "balance_minor": 1}])
    engine = ResponseEngine(settings, provider, store)
    await engine.render(_request(session_id=session.id))

    assert store.get_session(session.id).consistency_violations > 0


async def test_status_code_is_not_the_models_to_change(settings, store) -> None:
    """The handler already decided the outcome; the status encodes it."""
    provider = _Provider([{"id": "1004", "status_code": 500}])
    engine = ResponseEngine(settings, provider, store)
    response = await engine.render(_request(suggested_status=404))
    assert response.status_code == 404

    provider.payloads = [{"id": "1004", "status_code": 200}]
    forbidden = await engine.render(
        _request(
            path="/api/v1/accounts/9999",
            grounded_payload={"error": "forbidden"},
            suggested_status=403,
        )
    )
    assert forbidden.status_code == 403


async def test_error_responses_cannot_be_turned_into_successes(settings, store) -> None:
    provider = _Provider([{"error": "ok", "message": "Here is the account!"}])
    engine = ResponseEngine(settings, provider, store)
    response = await engine.render(
        _request(
            grounded_payload={"error": "forbidden", "message": "Access denied."},
            suggested_status=403,
        )
    )
    assert response.status_code == 403
    assert response.payload["error"] == "forbidden"


# ---------------------------------------------------------------------------
# failure handling
# ---------------------------------------------------------------------------


async def test_provider_failure_degrades_to_the_template(settings, store) -> None:
    provider = _Provider([], error="connection refused")
    engine = ResponseEngine(settings, provider, store)
    response = await engine.render(_request())

    assert response.status_code == 200
    assert response.payload["balance_minor"] == 481233
    assert response.generator == "template"
    assert engine.stats()["failures"] >= 1


async def test_non_json_model_output_degrades_to_the_template(settings, store) -> None:
    provider = _Provider(["I'm sorry, I can't help with that."])
    engine = ResponseEngine(settings, provider, store)
    response = await engine.render(_request())
    assert response.generator == "template"
    assert response.payload["balance_minor"] == 481233


async def test_wrong_shaped_model_output_is_discarded(settings, store) -> None:
    """A list where an object belongs is not repairable; fall back."""
    provider = _Provider([[1, 2, 3]])
    engine = ResponseEngine(settings, provider, store)
    response = await engine.render(_request())
    assert response.payload["balance_minor"] == 481233


async def test_repeated_failures_stop_wasting_time_on_the_provider(settings, store) -> None:
    """A dead provider must not add its timeout to every response."""
    provider = _Provider([], error="timeout")
    engine = ResponseEngine(settings, provider, store)
    for _ in range(12):
        await engine.render(_request(path=f"/api/v1/accounts/{1000 + _}"))

    stats = engine.stats()
    assert stats["failures"] >= 1
    # The breaker must have opened rather than calling out 12 times.
    assert provider.calls < 12, provider.calls
    assert stats["suspended"] is True


# ---------------------------------------------------------------------------
# prompt construction
# ---------------------------------------------------------------------------


async def test_prompt_carries_state_and_policy_but_not_secrets(settings, store) -> None:
    provider = _Provider([{"id": "1004"}])
    engine = ResponseEngine(settings, provider, store)
    await engine.render(_request())

    system, user = provider.prompts[0]
    combined = f"{system}\n{user}"
    assert "481233" in combined, "authoritative values must be in the prompt"
    assert "skilled_human" in combined
    assert "/api/v1/accounts/1004" in combined
    # The model is told never to contradict state.
    assert "contradict" in combined.lower() or "must not" in combined.lower()
    assert "AEGISTRAP" not in combined.upper().replace("AEGISTRAP HONEYPOT", "")


async def test_transcript_is_included_for_continuity(settings, store) -> None:
    provider = _Provider([{"id": "1004"}])
    engine = ResponseEngine(settings, provider, store)
    await engine.render(
        _request(transcript=["GET /api/v1/accounts -> 200", "GET /api/v1/debug -> 404"])
    )
    _, user = provider.prompts[0]
    assert "/api/v1/debug" in user


# ---------------------------------------------------------------------------
# cache
# ---------------------------------------------------------------------------


def test_cache_round_trips_and_reports_hits() -> None:
    cache = ResponseCache(ttl_seconds=60, max_entries=4)
    assert cache.get("k") is None
    cache.put("k", {"a": 1})
    assert cache.get("k") == {"a": 1}
    stats = cache.stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 1


def test_cache_expires_entries() -> None:
    cache = ResponseCache(ttl_seconds=0, max_entries=4)
    cache.put("k", {"a": 1})
    assert cache.get("k") is None


def test_cache_evicts_least_recently_used() -> None:
    cache = ResponseCache(ttl_seconds=600, max_entries=2)
    cache.put("a", {"v": 1})
    cache.put("b", {"v": 2})
    cache.get("a")  # refresh 'a'
    cache.put("c", {"v": 3})  # should evict 'b'
    assert cache.get("a") is not None
    assert cache.get("b") is None
    assert cache.get("c") is not None


async def test_identical_requests_reuse_one_generation(settings, store) -> None:
    """Section 9 metric 6: token cost per session."""
    provider = _Provider(
        [
            {
                "id": "1004",
                "iban": "XX56NWCB0835221184",
                "balance_minor": 481233,
                "status": "open",
                "note": "generated once",
            },
        ]
    )
    engine = ResponseEngine(settings, provider, store)

    first = await engine.render(_request())
    second = await engine.render(_request())

    assert provider.calls == 1
    assert first.payload == second.payload
    assert engine.stats()["cache"]["hits"] >= 1


async def test_cache_does_not_leak_across_sessions(settings, store) -> None:
    """Two sessions have different fake worlds; sharing a cached body would
    show one attacker another's state."""
    provider = _Provider(
        [
            {"id": "1004", "balance_minor": 481233, "note": "session one"},
            {"id": "1004", "balance_minor": 481233, "note": "session two"},
        ]
    )
    engine = ResponseEngine(settings, provider, store)
    await engine.render(_request(session_id="1111111111111111"))
    await engine.render(_request(session_id="2222222222222222"))
    assert provider.calls == 2


async def test_different_paths_are_cached_separately(settings, store) -> None:
    provider = _Provider([{"id": "1004"}, {"id": "1005"}])
    engine = ResponseEngine(settings, provider, store)
    await engine.render(_request(path="/api/v1/accounts/1004"))
    await engine.render(_request(path="/api/v1/accounts/1005"))
    assert provider.calls == 2


async def test_engine_stats_expose_the_cost_metrics(settings, store) -> None:
    provider = _Provider([{"id": "1004"}])
    engine = ResponseEngine(settings, provider, store)
    await engine.render(_request())
    stats = engine.stats()
    for key in ("provider", "model", "generative", "calls", "failures", "tokens", "cache"):
        assert key in stats, key
    assert stats["tokens"] > 0
