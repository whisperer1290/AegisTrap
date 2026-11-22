"""Deterministic session analysis and framework tagging.

This module answers "what did this attacker actually do?" using rules only, and
it plays three distinct roles:

1. **Evidence gathering for the LLM reporter.** The model is given structured,
   pre-extracted evidence rather than a raw log, which keeps its job to
   narrative synthesis and severity judgement instead of transcript archaeology.
2. **Fallback report generator.** With no provider configured, the rules alone
   still produce a complete, framework-mapped report. The auto-reporting
   contribution therefore does not depend on an API key.
3. **Comparison arm for the report-quality metric.** Section 9 scores the
   LLM's ATT&CK tags against manual ground truth; scoring the rule tagger the
   same way shows how much the LLM actually adds.

Tags come from two independent sources that are deliberately kept separate:
weaknesses the *honeypot* exercised (recorded at response time, so they are
ground truth about what was exposed), and payload signatures found in *request*
data (evidence of intent, even where the attempt did not land).
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from aegistrap.decoy.canary import canary_present
from aegistrap.intel.catalogue import (
    TECHNIQUES,
    WEAKNESSES,
    describe_technique,
    max_severity,
    owasp_for_weaknesses,
    sort_techniques,
    techniques_for_weaknesses,
)
from aegistrap.profiler.signatures import looks_like_wordlist_path, scan_payload
from aegistrap.store import Event, Session

_LOGIN_PATH_RE = re.compile(r"/(?:auth/)?(?:login|signin|token|oauth|sessions)\b", re.I)
_ADMIN_PATH_RE = re.compile(r"/admin\b", re.I)
_EXPORT_PATH_RE = re.compile(r"/(?:export|download|reports?|statements?)\b", re.I)
_TRANSFER_PATH_RE = re.compile(r"/(?:transfers?|payments?|payouts?|withdrawals?)\b", re.I)
_WEBHOOK_PATH_RE = re.compile(r"/(?:webhooks?|callbacks?|integrations?)\b", re.I)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


@dataclass
class Evidence:
    """One observation that justifies a tag."""

    seq: int
    request_line: str
    description: str
    technique_ids: list[str] = field(default_factory=list)
    weakness_id: str = ""
    status_code: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "request": self.request_line,
            "status": self.status_code,
            "observation": self.description,
            "attack_techniques": self.technique_ids,
            "weakness": self.weakness_id,
        }


@dataclass
class Behaviour:
    """A campaign-level pattern, as opposed to a single request."""

    id: str
    title: str
    description: str
    technique_ids: list[str]
    severity: str
    first_seq: int
    occurrences: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "first_seq": self.first_seq,
            "occurrences": self.occurrences,
            "attack_techniques": [describe_technique(t) for t in self.technique_ids],
        }


@dataclass
class SessionAnalysis:
    session_id: str
    weakness_ids: list[str] = field(default_factory=list)
    #: Weaknesses the honeypot actually exposed in a response.
    exposed_weakness_ids: list[str] = field(default_factory=list)
    #: Weaknesses the attacker probed for but did not reach.
    attempted_weakness_ids: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)
    owasp_api: list[str] = field(default_factory=list)
    owasp_web: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    behaviours: list[Behaviour] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    severity: str = "informational"
    stats: dict[str, Any] = field(default_factory=dict)
    timeline: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "severity": self.severity,
            "attack_techniques": [describe_technique(t) for t in self.technique_ids],
            "owasp_api": self.owasp_api,
            "owasp_web": self.owasp_web,
            "cwe": self.cwe_ids,
            "exposed_weaknesses": [
                WEAKNESSES[w].to_dict() for w in self.exposed_weakness_ids if w in WEAKNESSES
            ],
            "attempted_weaknesses": [
                WEAKNESSES[w].to_dict() for w in self.attempted_weakness_ids if w in WEAKNESSES
            ],
            "behaviours": [b.to_dict() for b in self.behaviours],
            "evidence": [e.to_dict() for e in self.evidence],
            "timeline": self.timeline,
            "stats": self.stats,
        }


def _request_line(event: Event) -> str:
    query = f"?{event.query_string}" if event.query_string else ""
    line = f"{event.method} {event.path}{query}"
    if event.body:
        line += f" body={event.body[:160]}"
    return line[:400]


def analyse_session(session: Session, events: Iterable[Event]) -> SessionAnalysis:
    """Turn a session transcript into structured, framework-tagged findings."""
    history = list(events)
    analysis = SessionAnalysis(session_id=session.id)
    if not history:
        return analysis

    # Weaknesses the honeypot actually exposed, versus weaknesses the attacker
    # tried for. Both belong in a report, but conflating them would overstate
    # what the attacker achieved.
    exposed: Counter[str] = Counter()
    attempted: set[str] = set()
    technique_ids: set[str] = set()
    evidence: list[Evidence] = []

    login_attempts: list[tuple[int, str]] = []
    missing_paths: set[str] = set()
    wordlist_hits = 0
    admin_successes = 0
    numeric_ids_probed: dict[str, list[int]] = {}
    forged_token_uses = 0
    canary_echoes = 0
    external_urls = 0
    transfer_attempts = 0
    large_page_requests = 0

    for event in history:
        blob = f"{event.path}?{event.query_string} {event.body}"

        # (1) Weaknesses the honeypot actually exposed on this request.
        for weakness_id in event.weaknesses:
            if weakness_id not in WEAKNESSES:
                continue
            exposed[weakness_id] += 1
            weakness = WEAKNESSES[weakness_id]
            technique_ids.update(weakness.techniques)
            if exposed[weakness_id] == 1:
                evidence.append(
                    Evidence(
                        seq=event.seq,
                        request_line=_request_line(event),
                        description=f"Service exposed: {weakness.title}",
                        technique_ids=list(weakness.techniques),
                        weakness_id=weakness_id,
                        status_code=event.status_code,
                    )
                )
            if weakness_id == "JWT_ALG_NONE":
                forged_token_uses += 1

        # (2) Attack intent visible in the request itself.
        for match in scan_payload(blob):
            if match.weakness_id and match.weakness_id in WEAKNESSES:
                attempted.add(match.weakness_id)
                technique_ids.update(WEAKNESSES[match.weakness_id].techniques)
            evidence.append(
                Evidence(
                    seq=event.seq,
                    request_line=_request_line(event),
                    description=(
                        f"Payload matched {match.name} "
                        f"({match.family}, sophistication {match.sophistication}/4): "
                        f"{match.excerpt}"
                    ),
                    technique_ids=list(WEAKNESSES[match.weakness_id].techniques)
                    if match.weakness_id in WEAKNESSES
                    else [],
                    weakness_id=match.weakness_id,
                    status_code=event.status_code,
                )
            )

        # (3) Campaign-level counters.
        if _LOGIN_PATH_RE.search(event.path) and event.method.upper() == "POST":
            login_attempts.append((event.seq, _extract_email(event.body)))
        if event.status_code == 404:
            missing_paths.add(event.path)
        if looks_like_wordlist_path(event.path):
            wordlist_hits += 1
        if _ADMIN_PATH_RE.search(event.path) and 200 <= event.status_code < 300:
            admin_successes += 1
        if _TRANSFER_PATH_RE.search(event.path) and event.method.upper() == "POST":
            transfer_attempts += 1
        if (
            _WEBHOOK_PATH_RE.search(event.path) or _EXPORT_PATH_RE.search(event.path)
        ) and "http" in blob.lower():
            external_urls += 1
        if canary_present(f"{event.query_string} {event.body} {json.dumps(event.headers)}"):
            canary_echoes += 1
        if _requested_page_size(event) > 200:
            large_page_requests += 1

        probe = _numeric_tail(event.path)
        if probe:
            numeric_ids_probed.setdefault(probe[0], []).append(probe[1])

    behaviours: list[Behaviour] = []

    if len(login_attempts) >= 5:
        emails = {email for _, email in login_attempts if email}
        if len(emails) >= 3:
            technique = ["T1110", "T1110.003"]
            title = "Password spraying across multiple accounts"
        elif len(emails) == 1:
            technique = ["T1110", "T1110.001"]
            title = "Password guessing against a single account"
        else:
            technique = ["T1110", "T1110.004"]
            title = "Credential stuffing run"
        behaviours.append(
            Behaviour(
                id="credential_attack",
                title=title,
                description=(
                    f"{len(login_attempts)} authentication attempts across "
                    f"{max(1, len(emails))} distinct identities with no lockout applied."
                ),
                technique_ids=technique,
                severity="high",
                first_seq=login_attempts[0][0],
                occurrences=len(login_attempts),
            )
        )
        technique_ids.update(technique)

    if len(missing_paths) >= 8 or wordlist_hits >= 5:
        technique = ["T1595", "T1595.003"]
        behaviours.append(
            Behaviour(
                id="content_discovery",
                title="Wordlist-driven content discovery",
                description=(
                    f"{len(missing_paths)} distinct non-existent paths requested, "
                    f"{wordlist_hits} of which appear in common discovery wordlists."
                ),
                technique_ids=technique,
                severity="medium",
                first_seq=history[0].seq,
                occurrences=max(len(missing_paths), wordlist_hits),
            )
        )
        technique_ids.update(technique)

    walk_steps = sum(
        1
        for ids in numeric_ids_probed.values()
        for a, b in zip(sorted(ids), sorted(ids)[1:], strict=False)
        if 0 < abs(b - a) <= 3
    )
    if walk_steps >= 2:
        technique = ["T1190", "T1087", "T1213"]
        behaviours.append(
            Behaviour(
                id="object_id_enumeration",
                title="Object-identifier enumeration (BOLA probing)",
                description=(
                    f"{walk_steps} adjacent object identifiers requested in sequence, "
                    "consistent with testing for broken object level authorization."
                ),
                technique_ids=technique,
                severity="high",
                first_seq=history[0].seq,
                occurrences=walk_steps,
            )
        )
        technique_ids.update(technique)

    if admin_successes:
        technique = ["T1068", "T1069", "T1190"]
        behaviours.append(
            Behaviour(
                id="admin_function_access",
                title="Administrative function reached successfully",
                description=(
                    f"{admin_successes} successful responses from administrative routes, "
                    "indicating broken function level authorization was exercised."
                ),
                technique_ids=technique,
                severity="critical",
                first_seq=history[0].seq,
                occurrences=admin_successes,
            )
        )
        technique_ids.update(technique)

    if forged_token_uses:
        technique = ["T1134", "T1528", "T1078"]
        behaviours.append(
            Behaviour(
                id="token_forgery",
                title="Unsigned access token accepted",
                description=(
                    f"{forged_token_uses} request(s) authenticated with an unsigned "
                    "(alg=none) token, impersonating another principal."
                ),
                technique_ids=technique,
                severity="critical",
                first_seq=history[0].seq,
                occurrences=forged_token_uses,
            )
        )
        technique_ids.update(technique)

    if transfer_attempts:
        technique = ["T1657", "T1565"]
        behaviours.append(
            Behaviour(
                id="money_movement",
                title="Attempted money movement",
                description=(
                    f"{transfer_attempts} transfer or payment request(s) issued against "
                    "the decoy ledger."
                ),
                technique_ids=technique,
                severity="critical",
                first_seq=history[0].seq,
                occurrences=transfer_attempts,
            )
        )
        technique_ids.update(technique)

    if external_urls:
        technique = ["T1567", "T1041"]
        behaviours.append(
            Behaviour(
                id="external_callback",
                title="Attacker-controlled callback supplied",
                description=(
                    f"{external_urls} request(s) supplied an external URL to a webhook "
                    "or export parameter, a common exfiltration and SSRF vector."
                ),
                technique_ids=technique,
                severity="high",
                first_seq=history[0].seq,
                occurrences=external_urls,
            )
        )
        technique_ids.update(technique)

    if large_page_requests >= 2:
        technique = ["T1119", "T1213"]
        behaviours.append(
            Behaviour(
                id="bulk_collection",
                title="Bulk data collection",
                description=(
                    f"{large_page_requests} request(s) asked for oversized pages, "
                    "consistent with wholesale harvesting of a collection."
                ),
                technique_ids=technique,
                severity="medium",
                first_seq=history[0].seq,
                occurrences=large_page_requests,
            )
        )
        technique_ids.update(technique)

    if canary_echoes:
        technique = ["T1071.001"]
        behaviours.append(
            Behaviour(
                id="response_canary_echo",
                title="Client echoed a response-embedded diagnostic canary",
                description=(
                    f"{canary_echoes} request(s) echoed an instruction planted in an "
                    "earlier response body, indicating the client read and reused "
                    "response content rather than fanning out from a wordlist."
                ),
                technique_ids=technique,
                severity="medium",
                first_seq=history[0].seq,
                occurrences=canary_echoes,
            )
        )
        technique_ids.update(technique)

    # Any traffic at all is web-protocol C2-adjacent; only claim it when there
    # is something else to report, so low-noise sessions stay informational.
    if technique_ids:
        technique_ids.add("T1071.001")

    exposed_ids = sorted(exposed)
    weakness_ids = sorted(set(exposed_ids) | attempted)
    owasp = owasp_for_weaknesses(weakness_ids)
    # Severity is driven by what was actually exposed plus campaign behaviour.
    # An attempt that never landed does not make an incident critical.
    severities = [WEAKNESSES[w].severity for w in exposed_ids if w in WEAKNESSES]
    severities.extend(b.severity for b in behaviours)

    analysis.weakness_ids = weakness_ids
    analysis.exposed_weakness_ids = exposed_ids
    analysis.attempted_weakness_ids = sorted(attempted - set(exposed_ids))
    analysis.technique_ids = sort_techniques(
        technique_ids | set(techniques_for_weaknesses(weakness_ids))
    )
    analysis.owasp_api = owasp["owasp_api"]
    analysis.owasp_web = owasp["owasp_web"]
    analysis.cwe_ids = owasp["cwe"]
    analysis.behaviours = sorted(behaviours, key=lambda b: b.first_seq)
    analysis.evidence = _prune_evidence(evidence)
    analysis.severity = max_severity(severities) if severities else "informational"
    analysis.stats = _session_stats(session, history)
    analysis.timeline = _build_timeline(history, analysis.technique_ids, behaviours)
    return analysis


def _prune_evidence(evidence: list[Evidence], limit: int = 40) -> list[Evidence]:
    """Keep the first occurrence of each distinct observation."""
    seen: set[str] = set()
    pruned: list[Evidence] = []
    for item in evidence:
        key = item.description[:80]
        if key in seen:
            continue
        seen.add(key)
        pruned.append(item)
        if len(pruned) >= limit:
            break
    return pruned


def _session_stats(session: Session, history: list[Event]) -> dict[str, Any]:
    statuses = Counter(e.status_code for e in history)
    generators = Counter(e.generator for e in history)
    latencies = [e.latency_ms for e in history if e.latency_ms]
    return {
        "requests": len(history),
        "duration_seconds": round(session.duration_seconds, 2),
        "distinct_paths": len({e.path for e in history}),
        "methods": sorted({e.method.upper() for e in history}),
        "status_codes": {str(k): v for k, v in sorted(statuses.items())},
        "generators": dict(generators),
        "mean_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
        "llm_calls": session.llm_calls,
        "llm_tokens": session.llm_tokens,
        "consistency_violations": session.consistency_violations,
        "persona": session.persona.value,
        "persona_confidence": round(session.persona_confidence, 3),
    }


def _build_timeline(
    history: list[Event], technique_ids: list[str], behaviours: list[Behaviour]
) -> list[dict[str, Any]]:
    """Phase-ordered narrative of the session, grouped by ATT&CK tactic."""
    by_tactic: dict[str, list[str]] = {}
    for technique_id in technique_ids:
        technique = TECHNIQUES.get(technique_id)
        if technique:
            by_tactic.setdefault(technique.tactic, []).append(technique_id)

    behaviour_by_tactic: dict[str, list[str]] = {}
    for behaviour in behaviours:
        for technique_id in behaviour.technique_ids:
            technique = TECHNIQUES.get(technique_id)
            if technique:
                behaviour_by_tactic.setdefault(technique.tactic, []).append(behaviour.title)

    timeline: list[dict[str, Any]] = []
    for tactic, ids in by_tactic.items():
        titles = sorted(set(behaviour_by_tactic.get(tactic, [])))
        timeline.append(
            {
                "tactic": tactic,
                "attack_techniques": ids,
                "observed_behaviours": titles,
            }
        )
    order = {
        t: i
        for i, t in enumerate(
            [
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
        )
    }
    timeline.sort(key=lambda entry: order.get(entry["tactic"], 99))
    return timeline


def _extract_email(body: str) -> str:
    match = _EMAIL_RE.search(body or "")
    return match.group(0).lower() if match else ""


def _numeric_tail(path: str) -> tuple[str, int] | None:
    parts = path.rstrip("/").rsplit("/", 1)
    if len(parts) != 2 or not parts[1].isdigit():
        return None
    try:
        return parts[0], int(parts[1])
    except ValueError:
        return None


def _requested_page_size(event: Event) -> int:
    for source in (event.query_string, event.body):
        match = re.search(
            r"(?:limit|per_page|page_size|first|take)[\"'\s:=]+(\d{1,6})", source or "", re.I
        )
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                continue
    return 0
