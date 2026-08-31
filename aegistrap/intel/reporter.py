"""Threat Intelligence Auto-Reporter (Core Module 5).

Runs when a session closes (or on the sweep timer) and turns the full
transcript into an analyst-ready incident report: attack timeline, techniques
used, MITRE ATT&CK IDs, OWASP/CWE mapping, and severity. This is the step most
honeypot work leaves to a human, so it is treated as a first-class output
rather than a log dump.

Design decisions worth stating:

* **Rules first, model second.** ``intel.tagger`` extracts structured evidence
  deterministically; the model's job is narrative synthesis and severity
  judgement over that evidence. A model that fails, times out, or is absent
  costs us prose, never tags.
* **Closed tag vocabulary.** The prompt supplies the permitted ATT&CK and
  OWASP identifiers, and any identifier outside the catalogue is dropped from
  the output and counted. Without this, LLM-generated reports contain
  plausible-looking technique IDs that do not exist, which is far worse than a
  missing tag because it silently corrupts downstream analysis. The drop count
  is recorded in the report's provenance block so it can be reported honestly
  as part of the tagging-precision metric.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from aegistrap.config import Settings
from aegistrap.intel.catalogue import (
    CWES,
    OWASP_API,
    OWASP_WEB,
    OWASP_WEB_2025,
    TECHNIQUES,
    WEAKNESSES,
    describe_technique,
    map_web_to_2025,
    max_severity,
    severity_rank,
    sort_techniques,
)
from aegistrap.intel.tagger import SessionAnalysis, analyse_session
from aegistrap.llm.providers import LLMProvider
from aegistrap.logging_setup import get_logger
from aegistrap.store import Report, Session, StateStore

log = get_logger("intel.reporter")

REPORTER_SYSTEM_PROMPT = """\
You are a senior threat-intelligence analyst writing an incident report from
honeypot telemetry. You write for a SOC analyst who must act on the report
without re-reading the raw log.

You are given structured, pre-extracted evidence from a deception system: the
attacker's inferred skill profile, the decoy weaknesses that were exposed or
probed, campaign-level behaviours, and a request-level evidence list.

RULES

1. Use ONLY identifiers from the `allowed_attack_techniques` and
   `allowed_owasp_*` lists provided. Never invent, guess, or extrapolate an ID.
   If no listed ID fits an observation, describe it in prose instead.
2. Ground every claim in the supplied evidence. Reference evidence by its
   `seq` number. Do not assert impact that the evidence does not support.
3. Distinguish what the attacker ACHIEVED (weaknesses exposed) from what they
   ATTEMPTED (payloads sent that did not land). Severity follows achievement.
4. Remember this is a honeypot: no real customer data, systems, or funds were
   at risk. Assess what the same activity WOULD have achieved against a real
   deployment of this API, and say so explicitly.
5. Be specific and terse. No filler, no hedging, no restating the schema.

Return ONE JSON object, no markdown fences:

{
  "title": "<=90 char incident title",
  "summary": "2-4 sentence executive summary",
  "severity": "informational|low|medium|high|critical",
  "confidence": <0.0-1.0 in your own assessment>,
  "attacker_assessment": {
    "persona": "<one of the personas named in the input>",
    "capability": "1-2 sentences on demonstrated skill, citing seq numbers",
    "objective": "1 sentence on apparent goal"
  },
  "attack_timeline": [
    {"tactic": "<ATT&CK tactic name>", "narrative": "what happened in this phase",
     "attack_techniques": ["Txxxx"], "evidence_seq": [<int>]}
  ],
  "attack_techniques": ["Txxxx", ...],
  "owasp_api": ["APIn:2023", ...],
  "owasp_web": ["Ann", ...],
  "real_world_impact": "what this would have achieved against a real service",
  "recommended_actions": ["specific, actionable defensive step", ...],
  "analyst_notes": "anything unusual worth a human's attention"
}
"""


@dataclass
class ReportBundle:
    document: dict[str, Any]
    markdown: str
    severity: str
    confidence: float
    generator: str
    yaml_path: Path | None = None
    markdown_path: Path | None = None
    #: Set when the report was persisted, so a caller can link straight to it.
    report_id: str = ""


class ThreatIntelReporter:
    def __init__(
        self,
        settings: Settings,
        provider: LLMProvider,
        store: StateStore,
    ) -> None:
        self.settings = settings
        self.provider = provider
        self.store = store
        self.generated = 0
        self.llm_failures = 0
        self.dropped_tags = 0

    @property
    def generative(self) -> bool:
        return bool(getattr(self.provider, "generative", False))

    async def report_session(self, session: Session, *, persist: bool = True) -> ReportBundle:
        events = self.store.get_events(session.id, limit=500)
        analysis = analyse_session(session, events)

        narrative: dict[str, Any] | None = None
        generator = "rules"
        dropped: dict[str, list[str]] = {}

        if self.generative and events:
            narrative, dropped = await self._generate_narrative(session, analysis)
            if narrative is not None:
                generator = f"llm:{getattr(self.provider, 'name', 'unknown')}"
            else:
                self.llm_failures += 1

        document = self._build_document(session, analysis, narrative, generator, dropped)
        markdown = render_markdown(document)
        bundle = ReportBundle(
            document=document,
            markdown=markdown,
            severity=document["severity"],
            confidence=float(document.get("confidence", 0.0)),
            generator=generator,
        )

        if persist:
            report = self.store.save_report(
                session_id=session.id,
                document=document,
                markdown=markdown,
                generator=generator,
                severity=bundle.severity,
                confidence=bundle.confidence,
            )
            bundle.report_id = report.id
            bundle.yaml_path, bundle.markdown_path = self._write_files(report, markdown)
            self.store.mark_reported(session.id)

        self.generated += 1
        return bundle

    # -- LLM narrative -------------------------------------------------------

    async def _generate_narrative(
        self, session: Session, analysis: SessionAnalysis
    ) -> tuple[dict[str, Any] | None, dict[str, list[str]]]:
        payload = {
            "session": {
                "requests": session.request_count,
                "duration_seconds": round(session.duration_seconds, 1),
                "inferred_persona": session.persona.value,
                "persona_confidence": round(session.persona_confidence, 3),
                "persona_signals": session.persona_signals[:10],
                "user_agent": session.user_agent[:200],
                "emulated_api": session.world_persona,
            },
            "exposed_weaknesses": [
                {
                    "id": w,
                    "title": WEAKNESSES[w].title,
                    "severity": WEAKNESSES[w].severity,
                    "owasp_api": WEAKNESSES[w].owasp_api,
                    "cwe": WEAKNESSES[w].cwe,
                }
                for w in analysis.exposed_weakness_ids
                if w in WEAKNESSES
            ],
            "attempted_weaknesses": [
                {"id": w, "title": WEAKNESSES[w].title}
                for w in analysis.attempted_weakness_ids
                if w in WEAKNESSES
            ],
            "behaviours": [b.to_dict() for b in analysis.behaviours],
            "evidence": [e.to_dict() for e in analysis.evidence[:30]],
            "rule_derived_techniques": analysis.technique_ids,
            "stats": analysis.stats,
            "allowed_attack_techniques": [
                {"id": t.id, "name": t.name, "tactic": t.tactic} for t in TECHNIQUES.values()
            ],
            "allowed_owasp_api": [{"id": c.id, "name": c.name} for c in OWASP_API.values()],
            "allowed_owasp_web": [{"id": c.id, "name": c.name} for c in OWASP_WEB.values()],
        }

        result = await self.provider.complete(
            system=REPORTER_SYSTEM_PROMPT,
            user=(
                "Write the incident report for this honeypot session.\n\n"
                + json.dumps(payload, separators=(",", ":"), default=str)
            ),
            max_tokens=2400,
            temperature=0.2,
            json_only=True,
        )
        if not result.ok:
            log.warning("reporter generation failed: %s", result.error or "empty output")
            return None, {}

        narrative = result.json_payload()
        if not isinstance(narrative, dict):
            log.warning("reporter returned unparseable output")
            return None, {}

        narrative, dropped = self._validate_tags(narrative)
        narrative["_llm"] = {
            "provider": result.provider,
            "model": result.model,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "latency_ms": round(result.latency_ms, 1),
        }
        return narrative, dropped

    def _validate_tags(
        self, narrative: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, list[str]]]:
        """Strip identifiers that are not in the catalogue, and count them."""
        dropped: dict[str, list[str]] = {}

        def filter_list(key: str, allowed: set[str]) -> None:
            raw = narrative.get(key)
            if not isinstance(raw, list):
                narrative[key] = []
                return
            kept, bad = [], []
            for item in raw:
                text = str(item).strip()
                (kept if text in allowed else bad).append(text)
            narrative[key] = kept
            if bad:
                dropped[key] = bad
                self.dropped_tags += len(bad)

        filter_list("attack_techniques", set(TECHNIQUES))
        filter_list("owasp_api", set(OWASP_API))
        filter_list("owasp_web", set(OWASP_WEB))

        timeline = narrative.get("attack_timeline")
        if isinstance(timeline, list):
            cleaned_timeline = []
            for entry in timeline:
                if not isinstance(entry, dict):
                    continue
                ids = [
                    str(t).strip()
                    for t in (entry.get("attack_techniques") or [])
                    if str(t).strip() in TECHNIQUES
                ]
                bad = [
                    str(t).strip()
                    for t in (entry.get("attack_techniques") or [])
                    if str(t).strip() not in TECHNIQUES
                ]
                if bad:
                    dropped.setdefault("attack_timeline", []).extend(bad)
                    self.dropped_tags += len(bad)
                entry["attack_techniques"] = ids
                cleaned_timeline.append(entry)
            narrative["attack_timeline"] = cleaned_timeline
        else:
            narrative["attack_timeline"] = []

        return narrative, dropped

    # -- document assembly ---------------------------------------------------

    def _build_document(
        self,
        session: Session,
        analysis: SessionAnalysis,
        narrative: dict[str, Any] | None,
        generator: str,
        dropped: dict[str, list[str]],
    ) -> dict[str, Any]:
        narrative = narrative or {}
        llm_meta = narrative.pop("_llm", {}) if narrative else {}

        # Union of rule-derived and model-proposed tags. The rules are never
        # overridden: a tag the deterministic layer justified stays in even if
        # the model omitted it.
        techniques = sort_techniques(
            [*analysis.technique_ids, *narrative.get("attack_techniques", [])]
        )
        owasp_api = _merge_ids(analysis.owasp_api, narrative.get("owasp_api", []), OWASP_API)
        owasp_web = _merge_ids(analysis.owasp_web, narrative.get("owasp_web", []), OWASP_WEB)
        owasp_web_2025 = map_web_to_2025(owasp_web)

        model_severity = str(narrative.get("severity", "")).lower()
        severity = analysis.severity
        if model_severity in {"informational", "low", "medium", "high", "critical"}:
            # Take the more serious of the two: the model can see campaign
            # context the rules cannot, but it cannot downgrade a critical
            # weakness that was demonstrably exposed.
            severity = max_severity([severity, model_severity])

        timeline = narrative.get("attack_timeline") or analysis.timeline

        document: dict[str, Any] = {
            "report_version": "1.0",
            "generated_at": _iso(time.time()),
            "generator": generator,
            "title": narrative.get("title") or _fallback_title(session, analysis),
            "severity": severity,
            "confidence": _clamp(narrative.get("confidence", _rule_confidence(analysis)), 0.0, 1.0),
            "summary": narrative.get("summary") or _fallback_summary(session, analysis),
            "session": {
                "id": session.id,
                "source_ip": session.source_ip,
                "user_agent": session.user_agent,
                "first_seen": _iso(session.first_seen),
                "last_seen": _iso(session.last_seen),
                "duration_seconds": round(session.duration_seconds, 2),
                "requests": session.request_count,
                "emulated_api": session.world_persona,
                "experiment_tag": session.experiment_tag,
            },
            "attacker_assessment": {
                "persona": session.persona.value,
                "persona_label": session.persona.label,
                "confidence": round(session.persona_confidence, 3),
                "signals": session.persona_signals,
                **{
                    k: v
                    for k, v in (narrative.get("attacker_assessment") or {}).items()
                    if k in ("capability", "objective")
                },
            },
            "attack_timeline": timeline,
            "mitre_attack": {
                "techniques": [describe_technique(t) for t in techniques],
                "tactics": sorted({TECHNIQUES[t].tactic for t in techniques if t in TECHNIQUES}),
            },
            "owasp": {
                "api_top_10_2023": [
                    {"id": i, "name": OWASP_API[i].name} for i in owasp_api if i in OWASP_API
                ],
                "top_10": [
                    {"id": i, "name": OWASP_WEB[i].name} for i in owasp_web if i in OWASP_WEB
                ],
                "top_10_2025": [
                    {"id": i, "name": OWASP_WEB_2025[i].name}
                    for i in owasp_web_2025
                    if i in OWASP_WEB_2025
                ],
            },
            "cwe": [{"id": i, "name": CWES.get(i, i)} for i in analysis.cwe_ids],
            "deception": {
                "weaknesses_exposed": [
                    WEAKNESSES[w].to_dict()
                    for w in analysis.exposed_weakness_ids
                    if w in WEAKNESSES
                ],
                "weaknesses_attempted_only": [
                    {"id": w, "title": WEAKNESSES[w].title}
                    for w in analysis.attempted_weakness_ids
                    if w in WEAKNESSES
                ],
                "behaviours": [b.to_dict() for b in analysis.behaviours],
            },
            "real_world_impact": narrative.get("real_world_impact") or _fallback_impact(analysis),
            "recommended_actions": _recommended_actions(analysis, narrative),
            "evidence": [e.to_dict() for e in analysis.evidence],
            "metrics": analysis.stats,
            "provenance": {
                "rule_tagger_techniques": analysis.technique_ids,
                "llm_proposed_techniques": narrative.get("attack_techniques", []),
                "dropped_invalid_tags": dropped,
                "dropped_invalid_tag_count": sum(len(v) for v in dropped.values()),
                "llm": llm_meta,
            },
            "ethics": {
                "data_classification": "synthetic",
                "note": (
                    "All accounts, balances, identities, and PII in this incident are "
                    "synthetic honeypot state. No production system or real customer "
                    "data was exposed."
                ),
            },
        }
        if narrative.get("analyst_notes"):
            document["analyst_notes"] = narrative["analyst_notes"]
        return document

    def _write_files(self, report: Report, markdown: str) -> tuple[Path, Path]:
        directory = self.settings.report_dir
        directory.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime(report.created_at))
        stem = f"{stamp}_{report.session_id[:8]}_{report.severity}"
        yaml_path = directory / f"{stem}.yaml"
        markdown_path = directory / f"{stem}.md"
        yaml_path.write_text(
            yaml.safe_dump(report.document, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        markdown_path.write_text(markdown, encoding="utf-8")
        return yaml_path, markdown_path

    def stats(self) -> dict[str, Any]:
        return {
            "generated": self.generated,
            "llm_failures": self.llm_failures,
            "dropped_invalid_tags": self.dropped_tags,
            "generative": self.generative,
            "provider": getattr(self.provider, "name", "unknown"),
        }


# ---------------------------------------------------------------------------
# Fallbacks used when there is no model, or the model omitted a field
# ---------------------------------------------------------------------------


def _fallback_title(session: Session, analysis: SessionAnalysis) -> str:
    if analysis.behaviours:
        return f"{analysis.behaviours[0].title} against decoy {session.world_persona} API"
    if analysis.exposed_weakness_ids:
        first = WEAKNESSES.get(analysis.exposed_weakness_ids[0])
        if first:
            return f"{first.title} exercised on decoy API"
    return f"Reconnaissance activity from {session.persona.label.lower()}"


def _fallback_summary(session: Session, analysis: SessionAnalysis) -> str:
    parts = [
        f"A session classified as {session.persona.label.lower()} "
        f"(confidence {session.persona_confidence:.2f}) issued "
        f"{session.request_count} requests over "
        f"{session.duration_seconds:.0f}s against the decoy "
        f"{session.world_persona} API."
    ]
    if analysis.exposed_weakness_ids:
        titles = [
            WEAKNESSES[w].title.lower()
            for w in analysis.exposed_weakness_ids[:3]
            if w in WEAKNESSES
        ]
        parts.append("The honeypot exposed " + "; ".join(titles) + ".")
    if analysis.behaviours:
        parts.append(
            "Campaign-level behaviour observed: "
            + ", ".join(b.title.lower() for b in analysis.behaviours[:3])
            + "."
        )
    if not analysis.exposed_weakness_ids and not analysis.behaviours:
        parts.append("No exploitation of the seeded weakness surface was observed.")
    return " ".join(parts)


def _fallback_impact(analysis: SessionAnalysis) -> str:
    if not analysis.exposed_weakness_ids:
        return (
            "Against a real deployment this activity would amount to "
            "reconnaissance without confirmed access."
        )
    critical = [
        WEAKNESSES[w]
        for w in analysis.exposed_weakness_ids
        if w in WEAKNESSES and severity_rank(WEAKNESSES[w].severity) >= 3
    ]
    if critical:
        return (
            "Against a real deployment, the same sequence would have achieved: "
            + "; ".join(w.title.lower() for w in critical[:4])
            + "."
        )
    return (
        "Against a real deployment this activity would have yielded limited "
        "information disclosure without privileged access."
    )


def _recommended_actions(analysis: SessionAnalysis, narrative: dict[str, Any]) -> list[str]:
    actions: list[str] = []
    for item in narrative.get("recommended_actions") or []:
        text = str(item).strip()
        if text and text not in actions:
            actions.append(text)
    # Defender notes from the catalogue are specific and always applicable, so
    # they are appended regardless of what the model produced.
    for weakness_id in analysis.exposed_weakness_ids:
        weakness = WEAKNESSES.get(weakness_id)
        if weakness and weakness.defender_note and weakness.defender_note not in actions:
            actions.append(weakness.defender_note)
    if not actions:
        actions.append(
            "No action required beyond monitoring; no weakness was successfully exercised."
        )
    return actions[:10]


def _rule_confidence(analysis: SessionAnalysis) -> float:
    if not analysis.technique_ids:
        return 0.35
    signal = len(analysis.exposed_weakness_ids) + len(analysis.behaviours)
    return round(min(0.95, 0.5 + 0.08 * signal), 3)


def _merge_ids(rule_ids: list[str], model_ids: list[Any], catalogue: dict[str, Any]) -> list[str]:
    merged = list(rule_ids)
    for item in model_ids:
        text = str(item).strip()
        if text in catalogue and text not in merged:
            merged.append(text)
    return merged


def _clamp(value: Any, low: float, high: float) -> float:
    try:
        return round(max(low, min(high, float(value))), 3)
    except (TypeError, ValueError):
        return low


def _iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def render_markdown(document: dict[str, Any]) -> str:
    session = document.get("session", {})
    assessment = document.get("attacker_assessment", {})
    lines: list[str] = [
        f"# {document.get('title', 'Honeypot incident report')}",
        "",
        f"**Severity:** {document.get('severity', 'unknown').upper()}  ",
        f"**Confidence:** {document.get('confidence', 0):.2f}  ",
        f"**Generated:** {document.get('generated_at', '')} by `{document.get('generator', '')}`  ",
        f"**Session:** `{session.get('id', '')}`",
        "",
        "## Summary",
        "",
        document.get("summary", ""),
        "",
        "## Attacker assessment",
        "",
        f"- **Profile:** {assessment.get('persona_label', assessment.get('persona', 'unknown'))} "
        f"(confidence {assessment.get('confidence', 0):.2f})",
    ]
    if assessment.get("capability"):
        lines.append(f"- **Capability:** {assessment['capability']}")
    if assessment.get("objective"):
        lines.append(f"- **Apparent objective:** {assessment['objective']}")
    if assessment.get("signals"):
        lines.append("- **Classification signals:**")
        lines.extend(f"  - {signal}" for signal in assessment["signals"][:8])

    lines += [
        "",
        "## Session facts",
        "",
        f"- Source: `{session.get('source_ip', 'unknown')}`",
        f"- User-Agent: `{(session.get('user_agent') or 'none')[:120]}`",
        f"- Window: {session.get('first_seen', '')} to {session.get('last_seen', '')} "
        f"({session.get('duration_seconds', 0):.0f}s)",
        f"- Requests: {session.get('requests', 0)}",
        f"- Emulated API: {session.get('emulated_api', 'unknown')}",
        "",
        "## Attack timeline",
        "",
    ]

    timeline = document.get("attack_timeline") or []
    if timeline:
        for index, entry in enumerate(timeline, start=1):
            tactic = entry.get("tactic", "unknown")
            techniques = ", ".join(entry.get("attack_techniques", [])) or "-"
            lines.append(f"**{index}. {tactic}** ({techniques})")
            if entry.get("narrative"):
                lines.append("")
                lines.append(f"   {entry['narrative']}")
            elif entry.get("observed_behaviours"):
                lines.append("")
                lines.extend(f"   - {b}" for b in entry["observed_behaviours"])
            lines.append("")
    else:
        lines += ["No multi-phase activity observed.", ""]

    techniques = document.get("mitre_attack", {}).get("techniques", [])
    lines += ["## MITRE ATT&CK techniques", ""]
    if techniques:
        lines += ["| ID | Technique | Tactic |", "| --- | --- | --- |"]
        lines += [
            f"| [{t['id']}]({t.get('url', '')}) | {t['name']} | {t['tactic']} |" for t in techniques
        ]
    else:
        lines.append("None mapped.")
    lines.append("")

    owasp = document.get("owasp", {})
    lines += ["## OWASP and CWE mapping", ""]
    api_rows = owasp.get("api_top_10_2023", [])
    if api_rows:
        lines.append("**API Security Top 10 (2023)**")
        lines.append("")
        lines += [f"- `{row['id']}` {row['name']}" for row in api_rows]
        lines.append("")
    web_2025_rows = owasp.get("top_10_2025", [])
    if web_2025_rows:
        lines.append("**Top 10 (web, 2025)**")
        lines.append("")
        lines += [f"- `{row['id']}` {row['name']}" for row in web_2025_rows]
        lines.append("")
    web_rows = owasp.get("top_10", [])
    if web_rows:
        lines.append("**Top 10 (web, 2021)**")
        lines.append("")
        lines += [f"- `{row['id']}` {row['name']}" for row in web_rows]
        lines.append("")
    if document.get("cwe"):
        lines.append("**CWE**")
        lines.append("")
        lines += [f"- `{row['id']}` {row['name']}" for row in document["cwe"]]
        lines.append("")

    deception = document.get("deception", {})
    exposed = deception.get("weaknesses_exposed", [])
    lines += ["## Weakness surface exercised", ""]
    if exposed:
        for weakness in exposed:
            lines.append(
                f"- **{weakness['title']}** ({weakness['severity']}) - "
                f"`{weakness['owasp_api']['id']}`, `{weakness['cwe']['id']}`"
            )
    else:
        lines.append("No seeded weakness was successfully exercised.")
    attempted = deception.get("weaknesses_attempted_only", [])
    if attempted:
        lines += ["", "Probed without success:", ""]
        lines += [f"- {item['title']}" for item in attempted]
    lines.append("")

    lines += ["## Real-world impact", "", document.get("real_world_impact", ""), ""]

    lines += ["## Recommended actions", ""]
    lines += [
        f"{i}. {action}" for i, action in enumerate(document.get("recommended_actions", []), 1)
    ]
    lines.append("")

    evidence = document.get("evidence", [])
    if evidence:
        lines += [
            "## Evidence",
            "",
            "| Seq | Request | Status | Observation |",
            "| --- | --- | --- | --- |",
        ]
        for item in evidence[:25]:
            request = str(item.get("request", "")).replace("|", "\\|")[:120]
            observation = str(item.get("observation", "")).replace("|", "\\|")[:160]
            lines.append(
                f"| {item.get('seq', '')} | `{request}` | {item.get('status', '')} | {observation} |"
            )
        lines.append("")

    metrics = document.get("metrics", {})
    if metrics:
        lines += ["## Telemetry", ""]
        lines += [
            f"- Requests: {metrics.get('requests', 0)} across "
            f"{metrics.get('distinct_paths', 0)} distinct paths",
            f"- Methods: {', '.join(metrics.get('methods', []))}",
            f"- Status codes: {metrics.get('status_codes', {})}",
            f"- Mean response latency: {metrics.get('mean_latency_ms', 0)} ms",
            f"- LLM calls: {metrics.get('llm_calls', 0)} ({metrics.get('llm_tokens', 0)} tokens)",
            f"- State contradictions repaired: {metrics.get('consistency_violations', 0)}",
            "",
        ]

    provenance = document.get("provenance", {})
    dropped = provenance.get("dropped_invalid_tag_count", 0)
    if dropped:
        lines += [
            "## Provenance",
            "",
            f"{dropped} model-proposed identifier(s) were not present in the "
            "ATT&CK/OWASP catalogue and were dropped:",
            "",
            f"```\n{json.dumps(provenance.get('dropped_invalid_tags', {}), indent=2)}\n```",
            "",
        ]

    ethics = document.get("ethics", {})
    if ethics.get("note"):
        lines += ["---", "", f"*{ethics['note']}*", ""]

    return "\n".join(lines)
