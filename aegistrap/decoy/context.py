"""Per-request decoy context.

Every response the honeypot emits funnels through :meth:`DecoyContext.respond`.
Centralising it means one place decides response headers, one place records the
event for the profiler and the reporter, and one place shapes timing — so there
is no code path that can accidentally answer an attacker with a
framework-default body or forget to log.

Ordering matters here. The profiler runs *before* the handler, so the in-flight
request shapes the deception surface it is answered with. Since that request
has no status code yet, it is passed to the profiler as a provisional event and
persisted afterwards with the real outcome.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from aegistrap.app_state import AppRuntime
from aegistrap.decoy.auth import TokenVerification, extract_bearer, verify_token
from aegistrap.decoy.errors import DecoyError
from aegistrap.decoy.world import seed_world
from aegistrap.llm.engine import GenerationRequest
from aegistrap.llm.prompts import summarise_transcript
from aegistrap.models import AttackerPersona, DeceptionPolicy, DecoyResponse
from aegistrap.profiler.service import ProfileResult
from aegistrap.store import Event, Session

#: Harness-only headers. Stripped before capture and profiling so the
#: evaluation rig cannot influence the features it is measuring.
CONTROL_HEADERS: frozenset[str] = frozenset(
    {
        "x-aegistrap-session",
        "x-aegistrap-gt-persona",
        "x-aegistrap-gt-techniques",
        "x-aegistrap-experiment",
    }
)

MAX_TRANSCRIPT_ENTRIES = 8


@dataclass
class DecoyContext:
    request: Request
    runtime: AppRuntime
    session: Session
    profile: ProfileResult
    seq: int
    body_text: str
    headers: dict[str, str]
    started: float
    auth: TokenVerification
    weaknesses: list[str] = field(default_factory=list)
    _responded: bool = False

    # -- convenience ---------------------------------------------------------

    @property
    def policy(self) -> DeceptionPolicy:
        return self.profile.policy

    @property
    def persona(self) -> AttackerPersona:
        return self.profile.persona

    @property
    def store(self):
        return self.runtime.store

    @property
    def session_id(self) -> str:
        return self.session.id

    def note_weakness(self, *weakness_ids: str) -> None:
        for weakness_id in weakness_ids:
            if weakness_id and weakness_id not in self.weaknesses:
                self.weaknesses.append(weakness_id)

    def json_body(self) -> Any:
        """Parse the request body leniently.

        A real service would 400 on malformed JSON, but rejecting it through
        the framework's validator would expose FastAPI's distinctive error
        envelope, so parsing failures are handled by the caller instead.
        """
        if not self.body_text.strip():
            return None
        try:
            return json.loads(self.body_text)
        except (json.JSONDecodeError, ValueError):
            return None

    def query_value(self, name: str, default: str = "") -> str:
        return self.request.query_params.get(name, default)

    def int_query(self, name: str, default: int, *, minimum: int = 0, maximum: int = 10_000) -> int:
        raw = self.request.query_params.get(name)
        if raw is None:
            return default
        try:
            return max(minimum, min(maximum, int(raw)))
        except (TypeError, ValueError):
            return default

    def rng(self, salt: str = "") -> random.Random:
        """Deterministic RNG for probabilistic deception decisions.

        Seeded on the session so that a repeated request gets the same
        outcome. An attacker who retries ``GET /accounts/1002`` and gets data
        once and a 403 the next time has found a honeypot.
        """
        return random.Random(f"{self.session_id}:{salt}")

    # -- response funnel -----------------------------------------------------

    async def respond(
        self,
        payload: Any,
        status: int = 200,
        *,
        endpoint: dict[str, Any] | None = None,
        weaknesses: list[str] | None = None,
        extra_instructions: list[str] | None = None,
        allow_llm: bool = True,
        headers: dict[str, str] | None = None,
    ) -> Response:
        self.note_weakness(*(weaknesses or []))

        generation = GenerationRequest(
            session_id=self.session_id,
            method=self.request.method,
            path=self.request.url.path,
            query=str(self.request.url.query or ""),
            body=self.body_text,
            endpoint=endpoint or {"summary": "undocumented route"},
            grounded_payload=payload,
            suggested_status=status,
            policy=self.policy,
            transcript=self._transcript(),
            extra_instructions=extra_instructions or [],
            exercised_weaknesses=list(self.weaknesses),
            session_context=self._session_context(),
            allow_llm=allow_llm,
        )
        decoy = await self.runtime.engine.render(generation)
        return await self._emit(decoy, extra_headers=headers)

    async def respond_error(
        self,
        error: DecoyError,
        *,
        endpoint: dict[str, Any] | None = None,
        allow_llm: bool = True,
        headers: dict[str, str] | None = None,
    ) -> Response:
        return await self.respond(
            error.payload,
            error.status,
            endpoint=endpoint,
            weaknesses=error.weaknesses,
            allow_llm=allow_llm,
            headers=headers,
            extra_instructions=[
                "This is an error response. Keep the error code and message "
                "semantics intact and do not turn it into a success."
            ],
        )

    async def respond_raw(
        self,
        content: str,
        *,
        status: int = 200,
        media_type: str = "text/plain",
        weaknesses: list[str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Response:
        """Emit a non-JSON body (HTML error pages, text exports, docs)."""
        self.note_weakness(*(weaknesses or []))
        decoy = DecoyResponse(
            status_code=status,
            payload=content,
            generator="template",
            exercised_weaknesses=list(self.weaknesses),
        )
        return await self._emit(decoy, extra_headers=headers, media_type=media_type)

    async def _emit(
        self,
        decoy: DecoyResponse,
        *,
        extra_headers: dict[str, str] | None = None,
        media_type: str = "application/json",
    ) -> Response:
        self._responded = True
        headers: dict[str, str] = {}
        headers.update(self.runtime.evasion.response_headers(self.session_id, seq=self.seq))
        headers.update(decoy.headers)
        headers.update(extra_headers or {})

        if self.policy.expose_admin_hints and "link" not in headers:
            # A real service often advertises related endpoints; here it is
            # also the breadcrumb to the decoy admin surface.
            headers["link"] = '</api/v1/admin>; rel="admin"'

        headers.update(self._cors_headers())

        body_text = (
            decoy.payload
            if isinstance(decoy.payload, str)
            else json.dumps(decoy.payload, default=str)
        )

        await self._shape_latency()
        latency_ms = (time.perf_counter() - self.started) * 1000

        self.store.record_event(
            session_id=self.session_id,
            seq=self.seq,
            method=self.request.method,
            path=self.request.url.path,
            query_string=str(self.request.url.query or ""),
            headers=self.headers,
            body=self.body_text,
            status_code=decoy.status_code,
            response=body_text,
            generator=decoy.generator,
            latency_ms=latency_ms,
            llm_tokens=decoy.llm_tokens,
            weaknesses=list(self.weaknesses),
            persona_at_time=self.persona.value,
            max_body_bytes=self.runtime.settings.max_body_capture_bytes,
        )

        if media_type == "application/json":
            return JSONResponse(
                content=decoy.payload, status_code=decoy.status_code, headers=headers
            )
        if media_type == "text/html":
            return HTMLResponse(content=body_text, status_code=decoy.status_code, headers=headers)
        return PlainTextResponse(
            content=body_text,
            status_code=decoy.status_code,
            headers=headers,
            media_type=media_type,
        )

    def _cors_headers(self) -> dict[str, str]:
        """CORS policy, with the seeded origin-reflection flaw.

        The flaw is reflecting an arbitrary ``Origin`` *and* allowing
        credentials, which is what makes a permissive policy actually
        exploitable rather than merely untidy.
        """
        origin = self.headers.get("origin", "")
        if not origin:
            return {}
        from aegistrap.decoy.policy import weakness_unlocked

        if weakness_unlocked("CORS_MISCONFIG", self.policy):
            self.note_weakness("CORS_MISCONFIG")
            return {
                "access-control-allow-origin": origin[:200],
                "access-control-allow-credentials": "true",
                "vary": "Origin",
            }
        return {
            "access-control-allow-origin": "https://app.northwind.test",
            "vary": "Origin",
        }

    async def _shape_latency(self) -> None:
        """Hold fast responses back to a plausible backend latency.

        This only ever slows responses down. A honeypot that answers a
        database-backed endpoint in 0.4 ms is as suspicious as one that takes
        four seconds, and template-rendered replies are far too fast. LLM-path
        slowness is handled separately, by caching and by reserving generation
        for sessions worth spending it on.
        """
        floor_ms, jitter_ms = self.runtime.evasion.latency_profile(self.session_id)
        target_ms = floor_ms + self.rng(f"latency:{self.seq}").uniform(0, jitter_ms)
        elapsed_ms = (time.perf_counter() - self.started) * 1000
        remaining = (target_ms - elapsed_ms) / 1000
        if remaining > 0:
            await asyncio.sleep(remaining)

    def _transcript(self) -> list[str]:
        events = self.store.get_events(self.session_id, limit=MAX_TRANSCRIPT_ENTRIES * 3)
        entries = [
            {
                "method": event.method,
                "path": event.path,
                "query": event.query_string,
                "status": event.status_code,
            }
            for event in events
        ]
        return summarise_transcript(entries, limit=MAX_TRANSCRIPT_ENTRIES)

    def _session_context(self) -> dict[str, Any]:
        return {
            "request_index": self.seq,
            "session_age_seconds": round(time.time() - self.session.first_seen, 1),
            "authenticated_as": self.auth.user_id or None,
            "authenticated_role": self.auth.role if self.auth.ok else None,
            "attacker_persona": self.persona.value,
            "persona_confidence": round(self.profile.confidence, 3),
        }


async def build_context(request: Request) -> DecoyContext:
    """FastAPI dependency: resolve session, seed world, profile the request."""
    started = time.perf_counter()
    runtime: AppRuntime = request.app.state.runtime
    settings = runtime.settings
    store = runtime.store

    raw_headers = {k.lower(): v for k, v in request.headers.items()}
    control = {k: v for k, v in raw_headers.items() if k in CONTROL_HEADERS}
    headers = {k: v for k, v in raw_headers.items() if k not in CONTROL_HEADERS}

    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="replace")[: settings.max_body_capture_bytes]

    source_ip = request.client.host if request.client else "unknown"
    if settings.anonymise_ips:
        source_ip = _anonymise(source_ip)

    session_key = store.make_session_key(
        source_ip,
        headers.get("user-agent", ""),
        explicit=control.get("x-aegistrap-session", ""),
    )
    ground_truth = control.get("x-aegistrap-gt-persona") or None
    techniques_header = control.get("x-aegistrap-gt-techniques", "")
    ground_truth_techniques = [t.strip() for t in techniques_header.split(",") if t.strip()]

    session, _created = store.get_or_create_session(
        session_key=session_key,
        source_ip=source_ip,
        user_agent=headers.get("user-agent", ""),
        world_persona=settings.persona,
        idle_seconds=settings.session_idle_seconds,
        ground_truth_persona=ground_truth,
        ground_truth_techniques=ground_truth_techniques,
        experiment_tag=control.get("x-aegistrap-experiment") or None,
    )
    seed_world(store, session.id, settings.persona)

    seq = store.touch_session(session.id)
    pending = Event(
        id=0,
        session_id=session.id,
        seq=seq,
        ts=time.time(),
        method=request.method,
        path=request.url.path,
        query_string=str(request.url.query or ""),
        headers=headers,
        body=body_text,
        status_code=0,
        response="",
        generator="pending",
        latency_ms=0.0,
        llm_tokens=0,
        weaknesses=[],
        persona_at_time=session.persona.value,
    )
    profile = runtime.profiler.profile(session.id, pending)

    refreshed = store.get_session(session.id) or session
    auth = verify_token(extract_bearer(headers), session.id, profile.policy)

    return DecoyContext(
        request=request,
        runtime=runtime,
        session=refreshed,
        profile=profile,
        seq=seq,
        body_text=body_text,
        headers=headers,
        started=started,
        auth=auth,
        weaknesses=list(auth.weaknesses),
    )


def _anonymise(ip: str) -> str:
    """Truncate an address to its network prefix (Section 10)."""
    if ":" in ip:
        parts = ip.split(":")
        return ":".join(parts[:3]) + "::/48"
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".0/24"
    return ip
