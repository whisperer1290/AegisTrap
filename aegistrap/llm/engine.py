"""LLM response engine (Core Module 4).

Given the endpoint, the current fake state, the attacker's profile tag, and the
schema, this produces the response body the attacker sees.

The engine is deliberately *not* the source of truth. Decoy handlers compute an
authoritative payload from the session store first; the engine's job is to make
that payload look like it came from a mature production service. Everything the
model returns is reconciled against the authoritative payload before it leaves
the process, and any divergence is repaired and counted.

That split is what makes the engine safe to degrade: if the provider is
unreachable, times out, returns malformed JSON, or is simply switched off for
this persona, the authoritative payload is served as-is and the attacker sees a
terse but entirely consistent API.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from aegistrap.config import Settings
from aegistrap.llm.cache import ResponseCache
from aegistrap.llm.grounding import reconcile
from aegistrap.llm.prompts import RESPONSE_SYSTEM_PROMPT, build_response_prompt
from aegistrap.llm.providers import LLMProvider, parse_json_loose
from aegistrap.logging_setup import get_logger
from aegistrap.models import DeceptionPolicy, DecoyResponse
from aegistrap.store import StateStore

log = get_logger("llm.engine")

#: Response headers the model is never allowed to set, because they change
#: transport semantics rather than appearance.
_FORBIDDEN_HEADERS = frozenset(
    {"content-length", "transfer-encoding", "connection", "content-encoding"}
)
_MAX_MODEL_HEADERS = 6

#: Consecutive provider failures before generation is suspended, and how long
#: the suspension lasts. Every failed call costs its full timeout, and that
#: latency is added to a response the attacker is waiting on — the exact tell
#: Section 13 warns about. Since the grounded payload is always a complete,
#: consistent answer, giving up quickly is strictly better than retrying.
_BREAKER_THRESHOLD = 3
_BREAKER_COOLDOWN_S = 60.0


@dataclass
class GenerationRequest:
    session_id: str
    method: str
    path: str
    query: str
    body: str
    endpoint: dict[str, Any]
    grounded_payload: Any
    suggested_status: int
    policy: DeceptionPolicy
    transcript: list[str] = field(default_factory=list)
    extra_instructions: list[str] = field(default_factory=list)
    exercised_weaknesses: list[str] = field(default_factory=list)
    session_context: dict[str, Any] = field(default_factory=dict)
    #: Skip generation for cheap, high-volume endpoints (health, 404 fanout).
    allow_llm: bool = True


class ResponseEngine:
    def __init__(
        self,
        settings: Settings,
        provider: LLMProvider,
        store: StateStore,
        *,
        cache: ResponseCache | None = None,
    ) -> None:
        self.settings = settings
        self.provider = provider
        self.store = store
        self.cache = cache or ResponseCache(ttl_seconds=settings.llm_cache_ttl_seconds)
        self.calls = 0
        self.failures = 0
        self.tokens = 0
        self._consecutive_failures = 0
        self._suspended_until = 0.0

    @property
    def generative(self) -> bool:
        return bool(getattr(self.provider, "generative", False))

    @property
    def suspended(self) -> bool:
        """Whether the circuit breaker is currently open."""
        return time.monotonic() < self._suspended_until

    def _note_failure(self) -> None:
        self.failures += 1
        self._consecutive_failures += 1
        if self._consecutive_failures >= _BREAKER_THRESHOLD:
            self._suspended_until = time.monotonic() + _BREAKER_COOLDOWN_S
            log.warning(
                "suspending generation for %.0fs after %d consecutive failures; "
                "serving grounded payloads",
                _BREAKER_COOLDOWN_S,
                self._consecutive_failures,
            )

    async def render(self, request: GenerationRequest) -> DecoyResponse:
        """Produce the response for one decoy request."""
        template = DecoyResponse(
            status_code=request.suggested_status,
            payload=request.grounded_payload,
            generator="template",
            exercised_weaknesses=list(request.exercised_weaknesses),
        )

        if not self.generative or not request.allow_llm or not request.policy.use_llm:
            return template
        if self.suspended:
            return template

        cache_key = ""
        if self.settings.llm_cache_enabled:
            cache_key = ResponseCache.make_key(
                session_id=request.session_id,
                method=request.method,
                path=request.path,
                query=request.query,
                body=request.body,
                persona=request.policy.persona.value,
                verbosity=request.policy.error_verbosity.value,
                grounded_payload=request.grounded_payload,
            )
            cached = self.cache.get(cache_key)
            if cached is not None:
                return DecoyResponse(
                    # The status is the handler's decision, so it comes from
                    # this request rather than from whenever the body was cached.
                    status_code=request.suggested_status,
                    payload=cached.get("body", request.grounded_payload),
                    headers=dict(cached.get("headers", {})),
                    generator="llm-cache",
                    exercised_weaknesses=list(request.exercised_weaknesses),
                )

        prompt = build_response_prompt(
            service={
                "name": self.settings.service_name,
                "version": self.settings.service_version,
                "kind": self.settings.persona,
            },
            request={
                "method": request.method,
                "path": request.path,
                "query": request.query,
                "body": request.body[:2000],
            },
            endpoint=request.endpoint,
            authoritative_payload=request.grounded_payload,
            suggested_status=request.suggested_status,
            disclosure_policy=request.policy.as_prompt_dict(),
            session_context=request.session_context,
            transcript=request.transcript,
            extra_instructions=request.extra_instructions,
        )

        started = time.perf_counter()
        result = await self.provider.complete(
            system=RESPONSE_SYSTEM_PROMPT,
            user=prompt,
            max_tokens=self.settings.llm_max_output_tokens,
            temperature=self.settings.llm_temperature,
            json_only=True,
        )
        self.calls += 1
        elapsed_ms = result.latency_ms or (time.perf_counter() - started) * 1000

        if not result.ok:
            self._note_failure()
            log.warning(
                "generation failed (%s); serving grounded payload: %s",
                result.provider,
                result.error or "empty response",
            )
            return template

        envelope = parse_json_loose(result.text)
        if not isinstance(envelope, dict):
            self._note_failure()
            log.warning("model returned unparseable output; serving grounded payload")
            return template

        body = envelope.get("body", envelope.get("response"))
        if body is None:
            # Some models skip the envelope and emit the body directly.
            body = {
                k: v
                for k, v in envelope.items()
                if k not in ("_reasoning", "status_code", "headers")
            } or None
        if body is None or type(body) is not type(request.grounded_payload):
            # A list where an object belongs is not repairable by reconciliation.
            self._note_failure()
            return template

        self._consecutive_failures = 0
        reconciliation = reconcile(request.grounded_payload, body)
        if reconciliation.violations:
            log.info(
                "repaired %d state contradiction(s) in generated response: %s",
                len(reconciliation.violations),
                "; ".join(reconciliation.violations[:3]),
            )
            self.store.record_consistency_violations(
                request.session_id, len(reconciliation.violations)
            )

        headers = _sanitise_headers(envelope.get("headers"))

        self.tokens += result.total_tokens
        self.store.record_llm_usage(
            request.session_id,
            tokens=result.total_tokens,
            latency_ms=elapsed_ms,
        )

        if cache_key:
            self.cache.put(cache_key, {"headers": headers, "body": reconciliation.payload})

        return DecoyResponse(
            # The handler decided the status from the authorization outcome, so
            # the model does not get a vote: letting it choose would let it
            # turn a 403 into a 200, which is an authorization decision.
            status_code=request.suggested_status,
            payload=reconciliation.payload,
            headers=headers,
            generator="llm",
            exercised_weaknesses=list(request.exercised_weaknesses),
            llm_tokens=result.total_tokens,
            llm_latency_ms=elapsed_ms,
            consistency_violations=reconciliation.violations,
        )

    def stats(self) -> dict[str, Any]:
        return {
            "provider": getattr(self.provider, "name", "unknown"),
            "model": getattr(self.provider, "model", ""),
            "generative": self.generative,
            "calls": self.calls,
            "failures": self.failures,
            "tokens": self.tokens,
            "suspended": self.suspended,
            "cache": self.cache.stats(),
        }


def _sanitise_headers(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    headers: dict[str, str] = {}
    for key, raw in value.items():
        name = str(key).strip().lower()
        if not name or name in _FORBIDDEN_HEADERS or "\n" in name or "\r" in name:
            continue
        text = str(raw).replace("\n", " ").replace("\r", " ")[:200]
        headers[name] = text
        if len(headers) >= _MAX_MODEL_HEADERS:
            break
    return headers
