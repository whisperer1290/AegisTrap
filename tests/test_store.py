"""Session state store behaviour."""

from __future__ import annotations

import time

from aegistrap.models import AttackerPersona
from aegistrap.store import StateStore


def _new_session(store: StateStore, key: str = "k1", idle: float = 300.0):
    session, created = store.get_or_create_session(
        session_key=key,
        source_ip="203.0.113.9",
        user_agent="curl/8.4.0",
        world_persona="fintech",
        idle_seconds=idle,
    )
    return session, created


def test_session_is_reused_within_the_idle_window(store: StateStore) -> None:
    first, created_first = _new_session(store)
    second, created_second = _new_session(store)
    assert created_first is True
    assert created_second is False
    assert first.id == second.id


def test_idle_session_is_closed_and_replaced(store: StateStore) -> None:
    first, _ = _new_session(store, idle=0.0)
    time.sleep(0.01)
    second, created = _new_session(store, idle=0.0)
    assert created is True
    assert second.id != first.id
    # The stale session must be closed so the auto-reporter picks it up.
    assert store.get_session(first.id).closed_at is not None


def test_distinct_clients_get_distinct_sessions(store: StateStore) -> None:
    first, _ = _new_session(store, key="a")
    second, _ = _new_session(store, key="b")
    assert first.id != second.id


def test_session_key_is_stable_and_separable() -> None:
    a = StateStore.make_session_key("1.2.3.4", "curl/8")
    b = StateStore.make_session_key("1.2.3.4", "curl/8")
    c = StateStore.make_session_key("1.2.3.5", "curl/8")
    assert a == b
    assert a != c
    assert StateStore.make_session_key("1.2.3.4", "curl/8", explicit="x") != a


def test_touch_increments_sequence(store: StateStore) -> None:
    session, _ = _new_session(store)
    assert store.touch_session(session.id) == 1
    assert store.touch_session(session.id) == 2


def test_world_objects_round_trip_and_update(store: StateStore) -> None:
    session, _ = _new_session(store)
    store.put_object(
        session.id, "accounts", "1001", {"id": "1001", "balance_minor": 500}, owner_id="usr_1"
    )
    fetched = store.get_object(session.id, "accounts", "1001")
    assert fetched is not None
    assert fetched.data["balance_minor"] == 500
    created_at = fetched.created_at

    store.put_object(
        session.id, "accounts", "1001", {"id": "1001", "balance_minor": 400}, owner_id="usr_1"
    )
    updated = store.get_object(session.id, "accounts", "1001")
    assert updated.data["balance_minor"] == 400
    # An update must not reset creation time; the fake world has to look aged.
    assert updated.created_at == created_at


def test_objects_are_scoped_per_session(store: StateStore) -> None:
    first, _ = _new_session(store, key="a")
    second, _ = _new_session(store, key="b")
    store.put_object(first.id, "accounts", "1001", {"id": "1001"})
    assert store.get_object(second.id, "accounts", "1001") is None


def test_owner_filter_and_counters(store: StateStore) -> None:
    session, _ = _new_session(store)
    for index in range(4):
        store.put_object(
            session.id,
            "accounts",
            str(1000 + index),
            {"id": str(1000 + index)},
            owner_id="usr_1" if index < 2 else "usr_2",
        )
    assert len(store.list_objects(session.id, "accounts", owner_id="usr_1")) == 2
    assert store.count_objects(session.id, "accounts") == 4
    assert store.next_counter(session.id, "seq", start=10) == 10
    assert store.next_counter(session.id, "seq") == 11


def test_persona_and_usage_are_persisted(store: StateStore) -> None:
    session, _ = _new_session(store)
    store.update_persona(
        session.id,
        AttackerPersona.ATTACKER,
        0.87,
        {"attacker": 0.87},
        ["irregular pacing"],
    )
    store.record_llm_usage(session.id, tokens=140, latency_ms=920.0)
    store.record_consistency_violations(session.id, 3)

    reloaded = store.get_session(session.id)
    assert reloaded.persona is AttackerPersona.ATTACKER
    assert reloaded.persona_confidence == 0.87
    assert reloaded.persona_signals == ["irregular pacing"]
    assert reloaded.llm_calls == 1
    assert reloaded.llm_tokens == 140
    assert reloaded.consistency_violations == 3


def test_reports_are_stored_and_listed(store: StateStore) -> None:
    session, _ = _new_session(store)
    report = store.save_report(
        session_id=session.id,
        document={"title": "t", "severity": "high"},
        markdown="# t",
        generator="rules",
        severity="high",
        confidence=0.7,
    )
    assert store.get_report(report.id).document["title"] == "t"
    assert [r.id for r in store.get_reports_for_session(session.id)] == [report.id]
    assert [r.id for r in store.list_reports()] == [report.id]


def test_unreported_closed_sessions_are_discoverable(store: StateStore) -> None:
    session, _ = _new_session(store)
    store.touch_session(session.id)
    assert store.find_unreported_sessions() == []
    store.close_session(session.id)
    pending = store.find_unreported_sessions()
    assert [s.id for s in pending] == [session.id]
    store.mark_reported(session.id)
    assert store.find_unreported_sessions() == []


def test_events_record_and_read_back_in_order(store: StateStore) -> None:
    session, _ = _new_session(store)
    for seq in range(1, 4):
        store.record_event(
            session_id=session.id,
            seq=seq,
            method="GET",
            path=f"/api/v1/accounts/{1000 + seq}",
            query_string="",
            headers={"user-agent": "curl/8.4.0"},
            body="",
            status_code=200,
            response="{}",
            generator="template",
            latency_ms=5.0,
            llm_tokens=0,
            weaknesses=["IDOR_ACCOUNT"] if seq == 2 else [],
            persona_at_time="attacker",
        )
    events = store.get_events(session.id)
    assert [e.seq for e in events] == [1, 2, 3]
    assert events[1].weaknesses == ["IDOR_ACCOUNT"]
    assert len(store.recent_event_timings(session.id)) == 3


def test_summary_stats_reflect_activity(store: StateStore) -> None:
    session, _ = _new_session(store)
    store.touch_session(session.id)
    stats = store.summary_stats()
    assert stats["sessions"] == 1
    assert stats["requests"] == 1
    assert stats["active_sessions"] == 1
