"""Operator dashboard: live sessions, personas, transcripts, and reports.

Two things are deliberate here.

**It does not use the decoy request pipeline.** Dashboard routes talk to the
store directly, so an operator refreshing the page never creates honeypot
sessions, never seeds a fake world, and never appears in the profiling data.

**Failed authentication looks like a missing page.** The dashboard lives on the
same origin as the honeypot, so a 401 or a login form at ``/dashboard`` would
tell a probing attacker that this host is instrumented. When a token is
configured and not supplied, these routes return the same 404 body the decoy
catch-all serves for any unknown path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from aegistrap.app_state import AppRuntime
from aegistrap.decoy.policy import all_policies, unlocked_weaknesses
from aegistrap.intel.catalogue import WEAKNESSES
from aegistrap.intel.tagger import analyse_session
from aegistrap.models import AttackerPersona
from aegistrap.store import Session

_UI_PATH = Path(__file__).parent / "static" / "dashboard.html"

_DECOY_404 = {
    "error": "not_found",
    "message": "The requested path does not exist on this service.",
}


def _runtime(request: Request) -> AppRuntime:
    return request.app.state.runtime


def _authorised(request: Request) -> bool:
    runtime = _runtime(request)
    expected = runtime.settings.dashboard_token
    if not expected:
        return True
    supplied = request.headers.get("x-dashboard-token") or request.query_params.get("token") or ""
    return supplied == expected


def _deny() -> Response:
    return JSONResponse(_DECOY_404, status_code=404)


def _session_summary(session: Session) -> dict[str, Any]:
    return {
        "id": session.id,
        "source_ip": session.source_ip,
        "user_agent": session.user_agent[:160],
        "persona": session.persona.value,
        "persona_label": session.persona.label,
        "persona_confidence": round(session.persona_confidence, 3),
        "signals": session.persona_signals[:6],
        "requests": session.request_count,
        "first_seen": session.first_seen,
        "last_seen": session.last_seen,
        "duration_seconds": round(session.duration_seconds, 1),
        "closed": session.is_closed,
        "reported": session.reported_at is not None,
        "llm_calls": session.llm_calls,
        "llm_tokens": session.llm_tokens,
        "consistency_violations": session.consistency_violations,
        "experiment_tag": session.experiment_tag,
        "ground_truth_persona": session.ground_truth_persona,
    }


def build_dashboard_router() -> APIRouter:
    router = APIRouter(prefix="/dashboard", tags=["dashboard"], include_in_schema=False)

    @router.get("")
    @router.get("/")
    async def dashboard_page(request: Request) -> Response:
        if not _authorised(request):
            return HTMLResponse(
                "<!doctype html><html><head><title>404 Not Found</title></head>"
                "<body><h1>Not Found</h1></body></html>",
                status_code=404,
            )
        if not _UI_PATH.exists():  # pragma: no cover - packaging safety net
            return HTMLResponse("<h1>Dashboard UI asset missing</h1>", status_code=500)
        return HTMLResponse(_UI_PATH.read_text(encoding="utf-8"))

    @router.get("/api/overview")
    async def overview(request: Request) -> Response:
        if not _authorised(request):
            return _deny()
        runtime = _runtime(request)
        stats = runtime.store.summary_stats()
        sessions = runtime.store.list_sessions(limit=500)
        active = [s for s in sessions if not s.is_closed]
        return JSONResponse(
            {
                "stats": stats,
                "engine": runtime.engine.stats(),
                "reporter": runtime.reporter.stats(),
                "evasion": runtime.evasion.describe(),
                "config": {
                    "persona": runtime.settings.persona,
                    "adaptive_deception": runtime.settings.adaptive_deception,
                    "profiler_mode": runtime.profiler.mode,
                    "llm_provider": runtime.settings.llm_provider,
                    "session_idle_seconds": runtime.settings.session_idle_seconds,
                    "auto_report_enabled": runtime.settings.auto_report_enabled,
                },
                "sweeper": {
                    "sweeps": getattr(request.app.state, "sweeper", None)
                    and request.app.state.sweeper.sweeps,
                    "closed_sessions": getattr(request.app.state, "sweeper", None)
                    and request.app.state.sweeper.closed_sessions,
                    "reports_written": getattr(request.app.state, "sweeper", None)
                    and request.app.state.sweeper.reports_written,
                },
                "persona_breakdown": _persona_breakdown(sessions),
                "active_sessions": len(active),
            }
        )

    @router.get("/api/sessions")
    async def sessions(request: Request, limit: int = 100) -> Response:
        if not _authorised(request):
            return _deny()
        runtime = _runtime(request)
        items = runtime.store.list_sessions(limit=max(1, min(limit, 500)))
        return JSONResponse({"items": [_session_summary(s) for s in items]})

    @router.get("/api/sessions/{session_id}")
    async def session_detail(request: Request, session_id: str) -> Response:
        if not _authorised(request):
            return _deny()
        runtime = _runtime(request)
        session = runtime.store.get_session(session_id)
        if session is None:
            return JSONResponse({"error": "unknown_session"}, status_code=404)
        events = runtime.store.get_events(session_id, limit=500)
        analysis = analyse_session(session, events)
        reports = runtime.store.get_reports_for_session(session_id)
        return JSONResponse(
            {
                "session": _session_summary(session),
                "persona_scores": session.persona_scores,
                "events": [
                    {
                        "seq": e.seq,
                        "ts": e.ts,
                        "method": e.method,
                        "path": e.path,
                        "query": e.query_string,
                        "body": e.body[:600],
                        "status": e.status_code,
                        "generator": e.generator,
                        "latency_ms": round(e.latency_ms, 1),
                        "llm_tokens": e.llm_tokens,
                        "weaknesses": e.weaknesses,
                        "persona_at_time": e.persona_at_time,
                        "response": e.response[:800],
                    }
                    for e in events
                ],
                "analysis": analysis.to_dict(),
                "reports": [
                    {
                        "id": r.id,
                        "created_at": r.created_at,
                        "severity": r.severity,
                        "generator": r.generator,
                        "confidence": r.confidence,
                    }
                    for r in reports
                ],
            }
        )

    @router.post("/api/sessions/{session_id}/report")
    async def force_report(request: Request, session_id: str) -> Response:
        if not _authorised(request):
            return _deny()
        runtime = _runtime(request)
        session = runtime.store.get_session(session_id)
        if session is None:
            return JSONResponse({"error": "unknown_session"}, status_code=404)
        bundle = await runtime.reporter.report_session(session)
        return JSONResponse(
            {
                "report_id": bundle.report_id,
                "severity": bundle.severity,
                "generator": bundle.generator,
                "yaml_path": str(bundle.yaml_path) if bundle.yaml_path else None,
                "markdown_path": str(bundle.markdown_path) if bundle.markdown_path else None,
                "document": bundle.document,
            }
        )

    @router.get("/api/reports")
    async def reports(request: Request, limit: int = 50) -> Response:
        if not _authorised(request):
            return _deny()
        runtime = _runtime(request)
        items = runtime.store.list_reports(limit=max(1, min(limit, 200)))
        return JSONResponse(
            {
                "items": [
                    {
                        "id": r.id,
                        "session_id": r.session_id,
                        "created_at": r.created_at,
                        "severity": r.severity,
                        "confidence": r.confidence,
                        "generator": r.generator,
                        "title": r.document.get("title", ""),
                        "summary": r.document.get("summary", ""),
                        "techniques": [
                            t["id"]
                            for t in r.document.get("mitre_attack", {}).get("techniques", [])
                        ],
                        "owasp_api": [
                            c["id"] for c in r.document.get("owasp", {}).get("api_top_10_2023", [])
                        ],
                        "owasp_web_2025": [
                            c["id"] for c in r.document.get("owasp", {}).get("top_10_2025", [])
                        ],
                    }
                    for r in items
                ]
            }
        )

    @router.get("/api/reports/{report_id}")
    async def report_detail(request: Request, report_id: str) -> Response:
        if not _authorised(request):
            return _deny()
        runtime = _runtime(request)
        report = runtime.store.get_report(report_id)
        if report is None:
            return JSONResponse({"error": "unknown_report"}, status_code=404)
        return JSONResponse(
            {
                "id": report.id,
                "session_id": report.session_id,
                "created_at": report.created_at,
                "severity": report.severity,
                "confidence": report.confidence,
                "generator": report.generator,
                "document": report.document,
                "markdown": report.markdown,
            }
        )

    @router.get("/api/policies")
    async def policies(request: Request) -> Response:
        if not _authorised(request):
            return _deny()
        return JSONResponse(
            {
                "policies": [
                    {
                        "persona": persona,
                        "error_verbosity": policy.error_verbosity.value,
                        "idor_leak_probability": policy.idor_leak_probability,
                        "use_llm": policy.use_llm,
                        "narrative_richness": policy.narrative_richness,
                        "max_page_size": policy.max_page_size,
                        "rationale": policy.rationale,
                        "unlocked_weaknesses": unlocked_weaknesses(policy),
                    }
                    for persona, policy in all_policies().items()
                ],
                "catalogue": [
                    {
                        "id": w.id,
                        "title": w.title,
                        "severity": w.severity,
                        "owasp_api": w.owasp_api,
                        "cwe": w.cwe,
                        "min_persona_rank": w.min_persona_rank,
                    }
                    for w in WEAKNESSES.values()
                ],
            }
        )

    @router.post("/api/sweep")
    async def sweep(request: Request) -> Response:
        if not _authorised(request):
            return _deny()
        sweeper = getattr(request.app.state, "sweeper", None)
        if sweeper is None:
            return JSONResponse({"error": "sweeper_unavailable"}, status_code=503)
        result = await sweeper.sweep_once()
        return JSONResponse(result)

    return router


def _persona_breakdown(sessions: list[Session]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {p.value: 0 for p in AttackerPersona}
    for session in sessions:
        counts[session.persona.value] = counts.get(session.persona.value, 0) + 1
    return [
        {"persona": persona, "label": AttackerPersona(persona).label, "count": count}
        for persona, count in counts.items()
        if count or persona != "benign"
    ]
