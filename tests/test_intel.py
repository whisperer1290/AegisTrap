"""Threat-intelligence tagging and auto-reporting."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from aegistrap.intel.catalogue import CWES, OWASP_API, OWASP_WEB, TECHNIQUES, WEAKNESSES
from aegistrap.intel.reporter import ThreatIntelReporter, render_markdown
from aegistrap.intel.tagger import analyse_session
from aegistrap.store import StateStore

# ---------------------------------------------------------------------------
# catalogue integrity
# ---------------------------------------------------------------------------


def test_every_weakness_maps_to_real_catalogue_entries() -> None:
    """A report citing an ATT&CK ID that does not exist is worse than no report."""
    for weakness in WEAKNESSES.values():
        assert weakness.owasp_api in OWASP_API, weakness.id
        assert weakness.owasp_web in OWASP_WEB, weakness.id
        assert weakness.cwe in CWES, weakness.id
        assert weakness.techniques, weakness.id
        for technique in weakness.techniques:
            assert technique in TECHNIQUES, (weakness.id, technique)


def test_technique_ids_follow_attack_format() -> None:
    import re

    for technique_id in TECHNIQUES:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", technique_id), technique_id


def test_sub_techniques_reference_their_parent() -> None:
    for technique_id in TECHNIQUES:
        if "." in technique_id:
            assert technique_id.split(".")[0] in TECHNIQUES, technique_id


def test_severities_are_from_a_fixed_scale() -> None:
    allowed = {"low", "medium", "high", "critical"}
    assert {w.severity for w in WEAKNESSES.values()} <= allowed


# ---------------------------------------------------------------------------
# rule tagger
# ---------------------------------------------------------------------------


def _record(store: StateStore, session_id: str, seq: int, **kwargs: Any) -> None:
    base: dict[str, Any] = {
        "method": "GET",
        "path": "/api/v1/health",
        "query_string": "",
        "headers": {"user-agent": "curl/8.4.0"},
        "body": "",
        "status_code": 200,
        "response": "{}",
        "generator": "template",
        "latency_ms": 4.0,
        "llm_tokens": 0,
        "weaknesses": [],
        "persona_at_time": "unknown",
    }
    base.update(kwargs)
    store.record_event(session_id=session_id, seq=seq, **base)


@pytest.fixture
def analysed(store: StateStore):
    session, _ = store.get_or_create_session(
        session_key="k",
        source_ip="203.0.113.7",
        user_agent="sqlmap/1.8.2#stable (https://sqlmap.org)",
        world_persona="fintech",
        idle_seconds=600,
    )
    events = [
        {"path": "/.env", "status_code": 404},
        {"path": "/openapi.json", "weaknesses": ["OPENAPI_EXPOSED"]},
        {
            "path": "/api/v1/auth/login",
            "method": "POST",
            "status_code": 401,
            "body": '{"email":"a@example.com","password":"x"}',
            "weaknesses": ["USER_ENUMERATION"],
        },
        {"path": "/api/v1/accounts/1002", "weaknesses": ["IDOR_ACCOUNT"]},
        {
            "path": "/api/v1/accounts/1' OR '1'='1",
            "status_code": 500,
            "weaknesses": ["SQL_INJECTION"],
        },
        {
            "path": "/api/v1/reports/export",
            "query_string": "file=../../../../etc/passwd",
            "weaknesses": ["PATH_TRAVERSAL"],
        },
        {"path": "/api/v1/admin/api-keys", "weaknesses": ["BFLA_ADMIN_ROUTE", "HONEY_CREDENTIALS"]},
    ]
    for index, event in enumerate(events, start=1):
        _record(store, session.id, index, **event)
    store.close_session(session.id)
    session = store.get_session(session.id)
    return session, analyse_session(session, store.get_events(session.id))


def test_analysis_collects_weaknesses_and_maps_them_up(analysed) -> None:
    _, analysis = analysed
    assert "SQL_INJECTION" in analysis.weakness_ids
    assert "IDOR_ACCOUNT" in analysis.weakness_ids
    # Mapped through the catalogue to the frameworks a defender reports in.
    assert "API1:2023" in analysis.owasp_api
    assert "CWE-89" in analysis.cwe_ids
    assert "T1190" in analysis.technique_ids


def test_exposed_and_attempted_weaknesses_are_distinguished(store: StateStore) -> None:
    """A blocked attempt is intelligence, but it is not an exposure."""
    session, _ = store.get_or_create_session(
        session_key="k2",
        source_ip="203.0.113.8",
        user_agent="curl/8.4.0",
        world_persona="fintech",
        idle_seconds=600,
    )
    _record(
        store,
        session.id,
        1,
        path="/api/v1/accounts/1' OR '1'='1",
        status_code=500,
        weaknesses=["SQL_INJECTION"],
    )
    # A traversal probe that the policy refused: no weakness recorded, 404 out.
    _record(
        store,
        session.id,
        2,
        path="/api/v1/reports/export",
        query_string="file=../../../../etc/passwd",
        status_code=404,
    )
    analysis = analyse_session(store.get_session(session.id), store.get_events(session.id))

    assert "SQL_INJECTION" in analysis.exposed_weakness_ids
    assert "PATH_TRAVERSAL" in analysis.attempted_weakness_ids
    assert "PATH_TRAVERSAL" not in analysis.exposed_weakness_ids


def test_behaviours_are_derived_with_evidence(analysed) -> None:
    _, analysis = analysed
    assert analysis.behaviours
    for behaviour in analysis.behaviours:
        assert behaviour.title
        assert behaviour.technique_ids
        assert all(t in TECHNIQUES for t in behaviour.technique_ids)
        assert behaviour.first_seq >= 1
    assert analysis.evidence
    for item in analysis.evidence:
        assert item.request_line
        assert item.seq >= 1


def test_severity_escalates_with_the_worst_finding(analysed, store: StateStore) -> None:
    _, analysis = analysed
    assert analysis.severity == "critical"

    quiet, _ = store.get_or_create_session(
        session_key="quiet",
        source_ip="198.51.100.1",
        user_agent="curl/8.4.0",
        world_persona="fintech",
        idle_seconds=600,
    )
    _record(store, quiet.id, 1)
    calm = analyse_session(store.get_session(quiet.id), store.get_events(quiet.id))
    assert calm.severity in ("informational", "low")


def test_timeline_follows_kill_chain_order(analysed) -> None:
    """The narrative is grouped by ATT&CK tactic, earliest phase first."""
    _, analysis = analysed
    assert analysis.timeline
    phases = [
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    ]
    positions = [phases.index(entry["tactic"]) for entry in analysis.timeline]
    assert positions == sorted(positions)
    assert analysis.timeline[0]["tactic"] == "reconnaissance"
    for entry in analysis.timeline:
        assert entry["attack_techniques"]
        assert all(t in TECHNIQUES for t in entry["attack_techniques"])


def test_analysis_of_an_empty_session_is_still_well_formed(store: StateStore) -> None:
    session, _ = store.get_or_create_session(
        session_key="empty",
        source_ip="198.51.100.2",
        user_agent="",
        world_persona="fintech",
        idle_seconds=600,
    )
    analysis = analyse_session(store.get_session(session.id), [])
    assert analysis.weakness_ids == []
    assert analysis.severity == "informational"
    assert analysis.to_dict()["session_id"] == session.id


# ---------------------------------------------------------------------------
# reporter
# ---------------------------------------------------------------------------


async def test_offline_reporter_produces_a_complete_document(
    analysed, store: StateStore, settings
) -> None:
    from aegistrap.llm.providers import OfflineProvider

    session, _ = analysed
    reporter = ThreatIntelReporter(settings, OfflineProvider(), store)
    bundle = await reporter.report_session(session)

    document = bundle.document
    for key in (
        "report_version",
        "generated_at",
        "generator",
        "title",
        "severity",
        "confidence",
        "summary",
        "session",
        "attacker_assessment",
        "attack_timeline",
        "mitre_attack",
        "owasp",
        "cwe",
        "deception",
        "real_world_impact",
        "recommended_actions",
        "evidence",
        "metrics",
        "provenance",
        "ethics",
    ):
        assert key in document, key
    assert document["session"]["id"] == session.id
    assert bundle.severity == "critical"
    assert 0.0 <= bundle.confidence <= 1.0
    assert bundle.generator in ("rules", "llm")
    assert document["recommended_actions"]
    # Section 10: the report must state that the evidence is synthetic.
    assert "synthetic" in str(document["ethics"]).lower()


async def test_report_tags_are_validated_against_the_catalogue(
    analysed, store: StateStore, settings
) -> None:
    from aegistrap.llm.providers import OfflineProvider

    session, _ = analysed
    bundle = await ThreatIntelReporter(settings, OfflineProvider(), store).report_session(session)
    for technique in bundle.document["mitre_attack"]["techniques"]:
        assert technique["id"] in TECHNIQUES
        assert technique["name"] == TECHNIQUES[technique["id"]].name
    for category in bundle.document["owasp"]["api_top_10_2023"]:
        assert category["id"] in OWASP_API
        assert category["name"] == OWASP_API[category["id"]].name
    from aegistrap.intel.catalogue import OWASP_WEB_2025, WEB_TO_2025

    for category in bundle.document["owasp"]["top_10_2025"]:
        assert category["id"] in OWASP_WEB_2025
    assert set(WEB_TO_2025) == set(OWASP_WEB)
    for cwe in bundle.document["cwe"]:
        assert cwe["id"] in CWES


async def test_hallucinated_tags_from_the_model_are_dropped(
    analysed, store: StateStore, settings, monkeypatch
) -> None:
    """The model writes prose; it does not get to invent framework IDs."""
    from aegistrap.llm.providers import LLMResult, OfflineProvider

    class Inventive(OfflineProvider):
        generative = True

        async def complete(self, **kwargs: Any) -> LLMResult:
            import json

            return LLMResult(
                text=json.dumps(
                    {
                        "title": "Invented incident",
                        "summary": "A summary of the incident.",
                        "attack_techniques": ["T9999", "T1190", "NOT-AN-ID"],
                        "recommended_actions": ["Patch it."],
                    }
                ),
                provider="test",
                model="test",
                output_tokens=40,
            )

    session, _ = analysed
    reporter = ThreatIntelReporter(settings, Inventive(), store)
    bundle = await reporter.report_session(session)
    ids = {t["id"] for t in bundle.document["mitre_attack"]["techniques"]}
    assert "T9999" not in ids
    assert "NOT-AN-ID" not in ids
    assert ids <= set(TECHNIQUES)


async def test_report_is_persisted_and_retrievable(analysed, store: StateStore, settings) -> None:
    from aegistrap.llm.providers import OfflineProvider

    session, _ = analysed
    reporter = ThreatIntelReporter(settings, OfflineProvider(), store)
    bundle = await reporter.report_session(session, persist=True)

    stored = store.get_reports_for_session(session.id)
    assert len(stored) == 1
    assert stored[0].document["title"] == bundle.document["title"]
    assert store.get_session(session.id).reported_at is not None


async def test_markdown_rendering_is_readable_and_complete(
    analysed, store: StateStore, settings
) -> None:
    from aegistrap.llm.providers import OfflineProvider

    session, _ = analysed
    bundle = await ThreatIntelReporter(settings, OfflineProvider(), store).report_session(session)
    markdown = render_markdown(bundle.document)

    assert markdown.startswith("#")
    for heading in (
        "## Summary",
        "## Attacker assessment",
        "## Attack timeline",
        "## MITRE ATT&CK techniques",
        "## Recommended actions",
        "## Evidence",
    ):
        assert heading in markdown, heading
    assert "T1190" in markdown
    assert markdown == bundle.markdown


async def test_report_files_are_written_to_disk(analysed, store: StateStore, settings) -> None:
    from aegistrap.llm.providers import OfflineProvider

    session, _ = analysed
    bundle = await ThreatIntelReporter(settings, OfflineProvider(), store).report_session(session)
    assert bundle.markdown_path is not None
    assert bundle.markdown_path.exists()
    assert bundle.yaml_path is not None
    assert bundle.yaml_path.exists()
    assert session.id[:8] in bundle.markdown_path.name


async def test_reporter_survives_a_provider_failure(analysed, store: StateStore, settings) -> None:
    """A model outage must degrade to the rule-based report, not lose the session."""
    from aegistrap.llm.providers import LLMResult, OfflineProvider

    class Broken(OfflineProvider):
        generative = True

        async def complete(self, **kwargs: Any) -> LLMResult:
            return LLMResult(text="", provider="test", error="connection refused")

    session, _ = analysed
    bundle = await ThreatIntelReporter(settings, Broken(), store).report_session(session)
    assert bundle.generator == "rules"
    assert bundle.document["summary"]


async def test_reporter_rejects_non_json_model_output(
    analysed, store: StateStore, settings
) -> None:
    from aegistrap.llm.providers import LLMResult, OfflineProvider

    class Chatty(OfflineProvider):
        generative = True

        async def complete(self, **kwargs: Any) -> LLMResult:
            return LLMResult(
                text="Sure! Here's the report you asked for, in prose.",
                provider="test",
                output_tokens=12,
            )

    session, _ = analysed
    bundle = await ThreatIntelReporter(settings, Chatty(), store).report_session(session)
    assert bundle.generator == "rules"


# ---------------------------------------------------------------------------
# end-to-end through the live app
# ---------------------------------------------------------------------------


async def test_a_live_attack_session_produces_a_report(
    client: TestClient, store: StateStore, settings
) -> None:
    from aegistrap.llm.providers import OfflineProvider

    headers = {"user-agent": "sqlmap/1.8.2#stable (https://sqlmap.org)"}
    for path in (
        "/.env",
        "/openapi.json",
        "/api/v1/debug",
        "/api/v1/reports/export?file=../../../../etc/passwd",
    ):
        client.get(path, headers=headers)

    session = store.list_sessions(limit=1)[0]
    store.close_session(session.id)
    bundle = await ThreatIntelReporter(settings, OfflineProvider(), store).report_session(
        store.get_session(session.id)
    )

    assert bundle.document["evidence"]
    assert bundle.document["attacker_assessment"]["persona"]
    assert bundle.document["deception"]["weaknesses_exposed"]
    assert bundle.severity != "informational"
