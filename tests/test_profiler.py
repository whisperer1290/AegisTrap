"""Attacker profiling: features, heuristics, and classification accuracy."""

from __future__ import annotations

import time
from collections import Counter

import pytest

from aegistrap.models import AttackerPersona
from aegistrap.profiler.features import extract_features, shannon_entropy
from aegistrap.profiler.heuristic import classify
from aegistrap.profiler.signatures import ClientClass, classify_client, scan_payload
from aegistrap.profiler.synthetic import generate_dataset, generate_session, supported_personas
from aegistrap.store import Event

# ---------------------------------------------------------------------------
# signatures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "family"),
    [
        ("1001' OR '1'='1", "sqli"),
        ("1 UNION ALL SELECT null,version()--", "sqli"),
        ("' AND (SELECT 1 FROM pg_sleep(5))--", "sqli"),
        ("../../../../etc/passwd", "traversal"),
        ("%2e%2e%2fetc%2fpasswd", "traversal"),
        ("<script>alert(1)</script>", "xss"),
        ("http://169.254.169.254/latest/meta-data/", "ssrf"),
        (";cat /etc/passwd", "cmdi"),
        ('{"password": {"$ne": null}}', "nosqli"),
    ],
)
def test_known_attack_payloads_are_matched(payload: str, family: str) -> None:
    assert family in {m.family for m in scan_payload(payload)}, payload


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "1001",
        "alice@example.com",
        "?limit=25&offset=50",
        "Ordinary product description with or without commas",
        "O'Brien",
    ],
)
def test_benign_input_is_not_flagged(payload: str) -> None:
    assert scan_payload(payload) == [], payload


def test_sophistication_ranks_blind_injection_above_cheat_sheet() -> None:
    basic = max(m.sophistication for m in scan_payload("' OR 1=1--"))
    blind = max(m.sophistication for m in scan_payload("' AND (SELECT 1 FROM pg_sleep(5))--"))
    assert blind > basic


@pytest.mark.parametrize(
    ("user_agent", "expected"),
    [
        ("", ClientClass.EMPTY),
        ("sqlmap/1.8.2#stable (https://sqlmap.org)", ClientClass.SCANNER),
        ("Nuclei - Open-source project (github.com/projectdiscovery/nuclei)", ClientClass.SCANNER),
        ("curl/8.4.0", ClientClass.LIBRARY),
        ("python-requests/2.31.0", ClientClass.LIBRARY),
        ("python-httpx/0.27.0 (LangChain; gpt-4o autonomous agent)", ClientClass.AI_AGENT),
    ],
)
def test_client_class_is_derived_from_user_agent(user_agent: str, expected: ClientClass) -> None:
    assert classify_client(user_agent, {"host", "accept"}) is expected


def test_browser_claim_without_browser_headers_is_not_believed() -> None:
    """A browser User-Agent from a client sending no browser headers is a lie."""
    chrome = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Safari/537.36"
    )
    believed = classify_client(
        chrome, {"accept-language", "accept-encoding", "referer", "sec-fetch-mode"}
    )
    bare = classify_client(chrome, {"host"})
    assert believed is ClientClass.BROWSER
    assert bare is not ClientClass.BROWSER


def test_entropy_separates_random_from_natural_text() -> None:
    assert shannon_entropy("aaaaaaaaaa") < shannon_entropy("the quick brown fox")
    assert shannon_entropy("f8Kz2Qm9Xv7Lp3Rw") > shannon_entropy("the quick brown fox")


# ---------------------------------------------------------------------------
# feature extraction
# ---------------------------------------------------------------------------


def _event(seq: int, ts: float, **kwargs) -> Event:
    base = {
        "id": seq,
        "session_id": "s",
        "seq": seq,
        "ts": ts,
        "method": "GET",
        "path": f"/api/v1/accounts/{1000 + seq}",
        "query_string": "",
        "headers": {"user-agent": "curl/8.4.0"},
        "body": "",
        "status_code": 200,
        "response": "{}",
        "generator": "template",
        "latency_ms": 5.0,
        "llm_tokens": 0,
        "weaknesses": [],
        "persona_at_time": "unknown",
    }
    base.update(kwargs)
    return Event(**base)


def test_empty_history_yields_empty_features() -> None:
    features = extract_features([])
    assert features.request_count == 0
    assert features.requests_per_second == 0.0


def test_request_rate_and_pacing_are_measured() -> None:
    events = [_event(i, 1000.0 + i * 0.1) for i in range(1, 21)]
    features = extract_features(events)
    assert features.request_count == 20
    assert features.requests_per_second > 5
    assert features.mean_interval_s == pytest.approx(0.1, abs=0.02)
    # Machine-regular pacing: near-zero coefficient of variation.
    assert features.interval_cv < 0.1


def test_human_pacing_is_irregular() -> None:
    gaps = [0.4, 3.1, 12.0, 1.2, 8.6, 22.0, 2.3, 5.5]
    ts = 1000.0
    events = []
    for index, gap in enumerate(gaps, start=1):
        ts += gap
        events.append(_event(index, ts))
    assert extract_features(events).interval_cv > 0.5


def test_wordlist_probing_is_detected() -> None:
    paths = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin", "/actuator/env"]
    events = [
        _event(i, 1000.0 + i * 0.05, path=path, status_code=404)
        for i, path in enumerate(paths, start=1)
    ]
    features = extract_features(events)
    assert features.wordlist_path_ratio > 0.9
    assert features.not_found_ratio > 0.9


def test_sequential_id_probing_is_counted() -> None:
    events = [_event(i, 1000.0 + i, path=f"/api/v1/accounts/{1000 + i}") for i in range(1, 11)]
    assert extract_features(events).sequential_id_probes > 5


def test_reactive_reuse_of_returned_ids_is_detected() -> None:
    """Discovery-then-use is the signature of a reasoning attacker.

    A wordlist replays a fixed list; an agent or a skilled human reads a
    response and requests the identifiers it just learned.
    """
    listing = _event(
        1,
        1000.0,
        path="/api/v1/accounts",
        response='{"items": [{"id": "7431"}, {"id": "9902"}]}',
    )
    follow_ups = [
        _event(2, 1004.0, path="/api/v1/accounts/7431"),
        _event(3, 1009.0, path="/api/v1/accounts/9902"),
    ]
    features = extract_features([listing, *follow_ups])
    assert features.reactive_request_count >= 2
    assert features.reactive_request_ratio > 0.5


def test_unrelated_follow_ups_are_not_reactive() -> None:
    listing = _event(1, 1000.0, path="/api/v1/accounts", response='{"items": []}')
    follow_ups = [_event(2, 1004.0, path="/.env"), _event(3, 1008.0, path="/admin")]
    assert extract_features([listing, *follow_ups]).reactive_request_count == 0


def test_payload_sophistication_is_aggregated() -> None:
    events = [
        _event(1, 1000.0, path="/api/v1/accounts/1' OR '1'='1"),
        _event(2, 1002.0, path="/api/v1/search", query_string="q=../../etc/passwd"),
        _event(3, 1004.0, method="POST", body='{"q": "\' AND (SELECT 1 FROM pg_sleep(5))--"}'),
    ]
    features = extract_features(events)
    assert {"sqli", "traversal"} <= features.payload_families
    assert features.max_sophistication >= 4
    assert features.payload_request_ratio > 0.9


def test_browser_headers_raise_the_browser_score() -> None:
    bare = extract_features([_event(1, 1000.0)])
    rich = extract_features(
        [
            _event(
                1,
                1000.0,
                headers={
                    "user-agent": "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/128.0 Safari/537.36",
                    "accept-language": "en-GB",
                    "accept-encoding": "gzip",
                    "referer": "https://app.northwind.test/",
                    "sec-fetch-mode": "cors",
                },
            )
        ]
    )
    assert rich.browser_header_score > bare.browser_header_score


def test_canary_echo_is_detected() -> None:
    """An agent that repeats planted instructions confirms it read them."""
    events = [
        _event(
            1,
            1000.0,
            path="/api/v1/debug",
            response='{"diagnostic_hint": "X-Diagnostic-Token: AEGIS-VERIFY-ABC123"}',
        ),
        _event(
            2,
            1003.0,
            headers={"user-agent": "curl/8.4.0", "x-diagnostic-token": "AEGIS-VERIFY-ABC123"},
        ),
    ]
    assert extract_features(events).canary_echo is True


def test_graphql_activity_is_summarised() -> None:
    events = [
        _event(
            1,
            1000.0,
            method="POST",
            path="/graphql",
            body='{"query": "{ __schema { types { name } } }"}',
        ),
        _event(
            2,
            1002.0,
            method="POST",
            path="/graphql",
            body='{"query": "{ a { b { c { d { e { f { g { h { i } } } } } } } } }"}',
        ),
    ]
    features = extract_features(events)
    assert features.graphql_request_count == 2
    assert features.graphql_introspection is True
    assert features.graphql_max_depth >= 8


def test_feature_vector_is_stable_and_numeric() -> None:
    """The ML profiler indexes this vector positionally, so it must not drift."""
    from aegistrap.profiler.features import SessionFeatures

    features = extract_features([_event(i, 1000.0 + i) for i in range(1, 6)])
    vector = features.to_vector()
    assert len(vector) == len(SessionFeatures.vector_names())
    assert all(isinstance(v, float) for v in vector)
    assert len(set(SessionFeatures.vector_names())) == len(vector)


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------


def test_no_evidence_yields_unknown_not_a_guess() -> None:
    verdict = classify(extract_features([]))
    assert verdict.persona is AttackerPersona.UNKNOWN
    assert verdict.confidence == 0.0


def test_scanner_is_recognised_from_tool_and_rate() -> None:
    events = [
        _event(
            i,
            1000.0 + i * 0.04,
            path=p,
            status_code=404,
            headers={"user-agent": "sqlmap/1.8.2#stable (https://sqlmap.org)"},
        )
        for i, p in enumerate(
            [
                "/.env",
                "/.git/config",
                "/admin",
                "/phpmyadmin",
                "/backup.zip",
                "/swagger",
                "/api-docs",
                "/actuator/env",
                "/console",
                "/metrics",
            ],
            start=1,
        )
    ]
    verdict = classify(extract_features(events))
    assert verdict.persona is AttackerPersona.SCANNER
    assert verdict.confidence > 0.4
    assert verdict.signals


def test_verdicts_carry_human_readable_signals() -> None:
    events = [
        _event(
            i,
            1000.0 + i * 0.04,
            path="/.env",
            status_code=404,
            headers={"user-agent": "nuclei/3.1.0"},
        )
        for i in range(1, 12)
    ]
    verdict = classify(extract_features(events))
    assert any("User-Agent" in s or "wordlist" in s for s in verdict.signals)


def test_probabilities_form_a_distribution() -> None:
    events = [_event(i, 1000.0 + i * 0.05, path="/.env", status_code=404) for i in range(1, 12)]
    verdict = classify(extract_features(events))
    assert sum(verdict.probabilities.values()) == pytest.approx(1.0, abs=1e-3)


# ---------------------------------------------------------------------------
# accuracy against labelled synthetic sessions (Section 9, metric 1)
# ---------------------------------------------------------------------------


def test_synthetic_generator_covers_every_classifiable_persona() -> None:
    assert set(supported_personas()) == {
        AttackerPersona.BENIGN,
        AttackerPersona.SCRIPT_KIDDIE,
        AttackerPersona.SCANNER,
        AttackerPersona.SKILLED_HUMAN,
        AttackerPersona.AI_AGENT,
    }


def test_synthetic_sessions_are_reproducible() -> None:
    import random

    first = generate_session(AttackerPersona.SCANNER, random.Random(7))
    second = generate_session(AttackerPersona.SCANNER, random.Random(7))
    assert [(e.method, e.path, e.body) for e in first] == [
        (e.method, e.path, e.body) for e in second
    ]


def test_heuristic_accuracy_meets_the_target() -> None:
    """Section 9 metric 1: persona classification accuracy.

    Asserts on macro-averaged recall as well as raw accuracy, so a classifier
    that wins by collapsing onto the majority class cannot pass.
    """
    dataset = generate_dataset(per_persona=40, seed=4242)
    correct = 0
    per_persona: Counter[str] = Counter()
    totals: Counter[str] = Counter()

    for label, events in dataset:
        predicted = classify(extract_features(events)).persona
        totals[label.value] += 1
        if predicted is label:
            correct += 1
            per_persona[label.value] += 1

    accuracy = correct / len(dataset)
    recalls = {p: per_persona[p] / totals[p] for p in totals}
    macro_recall = sum(recalls.values()) / len(recalls)

    assert accuracy >= 0.80, (accuracy, recalls)
    assert macro_recall >= 0.75, recalls
    # No persona may be effectively undetectable.
    assert min(recalls.values()) >= 0.55, recalls


def test_benign_traffic_is_rarely_misread_as_an_attacker() -> None:
    """False positives are the expensive error: they bait real users."""
    dataset = generate_dataset(per_persona=40, seed=99)
    benign = [events for label, events in dataset if label is AttackerPersona.BENIGN]
    misread = [
        events
        for events in benign
        if classify(extract_features(events)).persona
        not in (AttackerPersona.BENIGN, AttackerPersona.UNKNOWN)
    ]
    assert len(misread) / len(benign) <= 0.10


def test_classification_stabilises_as_a_session_grows() -> None:
    """Confidence should not swing wildly once the picture is clear."""
    import random

    events = generate_session(AttackerPersona.SCANNER, random.Random(11))
    assert len(events) > 12
    late = [
        classify(extract_features(events[:n])).persona
        for n in range(max(10, len(events) // 2), len(events) + 1, 3)
    ]
    assert late.count(AttackerPersona.SCANNER) >= len(late) - 1


def test_profiler_service_persists_its_verdict(store, settings) -> None:
    from aegistrap.profiler.service import AttackerProfiler

    session, _ = store.get_or_create_session(
        session_key="k",
        source_ip="1.2.3.4",
        user_agent="sqlmap/1.8.2",
        world_persona="fintech",
        idle_seconds=600,
    )
    for index, path in enumerate(
        ["/.env", "/.git/config", "/admin", "/phpmyadmin", "/backup.zip", "/swagger"],
        start=1,
    ):
        store.record_event(
            session_id=session.id,
            seq=index,
            method="GET",
            path=path,
            query_string="",
            headers={"user-agent": "sqlmap/1.8.2"},
            body="",
            status_code=404,
            response="{}",
            generator="template",
            latency_ms=1.0,
            llm_tokens=0,
            weaknesses=[],
            persona_at_time="unknown",
        )

    profiler = AttackerProfiler(store, mode="heuristic", adaptive=True)
    result = profiler.profile(session.id)
    assert result.persona is AttackerPersona.SCANNER
    assert result.policy.persona is AttackerPersona.SCANNER
    assert store.get_session(session.id).persona is AttackerPersona.SCANNER


def test_ablation_mode_ignores_the_verdict(store) -> None:
    from aegistrap.decoy.policy import BASELINE_POLICY
    from aegistrap.profiler.service import AttackerProfiler

    session, _ = store.get_or_create_session(
        session_key="k",
        source_ip="1.2.3.4",
        user_agent="sqlmap/1.8.2",
        world_persona="fintech",
        idle_seconds=600,
    )
    profiler = AttackerProfiler(store, mode="heuristic", adaptive=False)
    assert profiler.profile(session.id).policy is BASELINE_POLICY


def test_profiler_falls_back_when_no_model_is_trained(store, tmp_path) -> None:
    from aegistrap.profiler.service import AttackerProfiler

    profiler = AttackerProfiler(
        store, mode="ml", adaptive=True, model_path=tmp_path / "absent.joblib"
    )
    assert profiler.mode == "heuristic"


def test_feature_window_bounds_work_per_session(store) -> None:
    from aegistrap.profiler.service import FEATURE_WINDOW, AttackerProfiler

    session, _ = store.get_or_create_session(
        session_key="k",
        source_ip="1.2.3.4",
        user_agent="curl/8.4.0",
        world_persona="fintech",
        idle_seconds=600,
    )
    for index in range(1, FEATURE_WINDOW + 25):
        store.record_event(
            session_id=session.id,
            seq=index,
            method="GET",
            path=f"/api/v1/accounts/{index}",
            query_string="",
            headers={"user-agent": "curl/8.4.0"},
            body="",
            status_code=200,
            response="{}",
            generator="template",
            latency_ms=1.0,
            llm_tokens=0,
            weaknesses=[],
            persona_at_time="unknown",
        )
    result = AttackerProfiler(store).profile(session.id)
    assert result.features.request_count <= FEATURE_WINDOW


def test_profiling_a_live_session_is_fast_enough_to_be_inline(store) -> None:
    """Profiling runs on the request path, so it must stay cheap."""
    from aegistrap.profiler.service import AttackerProfiler

    session, _ = store.get_or_create_session(
        session_key="k",
        source_ip="1.2.3.4",
        user_agent="curl/8.4.0",
        world_persona="fintech",
        idle_seconds=600,
    )
    for index in range(1, 61):
        store.record_event(
            session_id=session.id,
            seq=index,
            method="GET",
            path=f"/api/v1/accounts/{index}",
            query_string="",
            headers={"user-agent": "curl/8.4.0"},
            body='{"q": "1 OR 1=1"}',
            status_code=200,
            response="{}",
            generator="template",
            latency_ms=1.0,
            llm_tokens=0,
            weaknesses=[],
            persona_at_time="unknown",
        )
    profiler = AttackerProfiler(store)
    started = time.perf_counter()
    for _ in range(10):
        profiler.profile(session.id)
    per_call_ms = (time.perf_counter() - started) * 100
    assert per_call_ms < 60, per_call_ms
