"""LLM provider abstraction.

The synopsis suggests a hosted API (Claude or GPT) for prototype quality and a
local open-weight model for deployment, since sending attacker payloads to a
third party is undesirable for a honeypot. Both paths are supported here behind
one interface, along with an ``offline`` provider.

Providers are called over raw HTTP rather than through vendor SDKs. Three
reasons: it keeps the dependency surface to ``httpx``, it makes the local
Ollama path structurally identical to the hosted ones, and it means a
provider outage surfaces as a normal HTTP error we can fall back from instead
of an SDK-specific exception.

The ``offline`` provider is not a stub for convenience: it is the *static
baseline* the evaluation plan compares against, so it needs to be a
first-class, always-available mode.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

import httpx

from aegistrap.config import Settings
from aegistrap.logging_setup import get_logger

log = get_logger("llm.provider")


@dataclass
class LLMResult:
    text: str
    provider: str
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.text.strip())

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def json_payload(self) -> Any | None:
        """Parse the response as JSON, tolerating prose or fences around it."""
        return parse_json_loose(self.text)


@runtime_checkable
class LLMProvider(Protocol):
    name: str
    model: str
    #: False for the offline provider, so callers can skip prompt construction.
    generative: bool

    async def complete(
        self,
        *,
        system: str,
        user: str,
        max_tokens: int,
        temperature: float,
        json_only: bool = False,
    ) -> LLMResult: ...

    async def aclose(self) -> None: ...


def parse_json_loose(text: str) -> Any | None:
    """Best-effort JSON extraction from a model response."""
    if not text:
        return None
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = candidate.split("```")[1] if "```" in candidate[3:] else candidate[3:]
        if candidate.lstrip().lower().startswith("json"):
            candidate = candidate.lstrip()[4:]
        candidate = candidate.strip("`\n ")
    try:
        return json.loads(candidate)
    except (json.JSONDecodeError, ValueError):
        pass
    # Fall back to the outermost balanced object or array.
    for opener, closer in (("{", "}"), ("[", "]")):
        start = candidate.find(opener)
        end = candidate.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(candidate[start : end + 1])
            except (json.JSONDecodeError, ValueError):
                continue
    return None


class OfflineProvider:
    """No-network provider; forces the deterministic template path.

    Also the static, no-LLM baseline arm in the evaluation plan.
    """

    name = "offline"
    generative = False

    def __init__(self) -> None:
        self.model = "deterministic-template"

    async def complete(
        self,
        *,
        system: str,
        user: str,
        max_tokens: int,
        temperature: float,
        json_only: bool = False,
    ) -> LLMResult:
        return LLMResult(
            text="",
            provider=self.name,
            model=self.model,
            error="offline provider does not generate",
        )

    async def aclose(self) -> None:
        return None


class _HttpProvider:
    """Shared HTTP plumbing for the hosted and local providers."""

    name = "http"
    generative = True

    def __init__(self, *, base_url: str, model: str, timeout: float) -> None:
        self.model = model
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(timeout, connect=min(5.0, timeout)),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _post(
        self, path: str, payload: dict[str, Any], headers: dict[str, str]
    ) -> tuple[dict[str, Any] | None, str, float]:
        started = time.perf_counter()
        try:
            response = await self._client.post(path, json=payload, headers=headers)
        except httpx.TimeoutException:
            return None, "timeout", (time.perf_counter() - started) * 1000
        except httpx.HTTPError as exc:
            return (
                None,
                f"transport error: {exc.__class__.__name__}",
                (time.perf_counter() - started) * 1000,
            )
        elapsed = (time.perf_counter() - started) * 1000
        if response.status_code >= 400:
            return None, f"http {response.status_code}: {response.text[:200]}", elapsed
        try:
            return response.json(), "", elapsed
        except ValueError:
            return None, "non-JSON response from provider", elapsed


class AnthropicProvider(_HttpProvider):
    name = "anthropic"

    def __init__(self, settings: Settings) -> None:
        super().__init__(
            base_url=settings.anthropic_base_url,
            model=settings.anthropic_model,
            timeout=settings.llm_timeout_seconds,
        )
        self._api_key = settings.anthropic_api_key

    async def complete(
        self,
        *,
        system: str,
        user: str,
        max_tokens: int,
        temperature: float,
        json_only: bool = False,
    ) -> LLMResult:
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if json_only:
            # Anthropic has no JSON mode; pre-filling the assistant turn with an
            # opening brace is the documented way to constrain the shape.
            payload["messages"].append({"role": "assistant", "content": "{"})
        data, error, elapsed = await self._post(
            "/v1/messages",
            payload,
            {
                "x-api-key": self._api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
        )
        if data is None:
            return LLMResult(
                text="", provider=self.name, model=self.model, latency_ms=elapsed, error=error
            )
        blocks = data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        if json_only and text and not text.lstrip().startswith("{"):
            text = "{" + text
        usage = data.get("usage") or {}
        return LLMResult(
            text=text,
            provider=self.name,
            model=data.get("model", self.model),
            input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            latency_ms=elapsed,
        )


class OpenAIProvider(_HttpProvider):
    name = "openai"

    def __init__(self, settings: Settings) -> None:
        super().__init__(
            base_url=settings.openai_base_url,
            model=settings.openai_model,
            timeout=settings.llm_timeout_seconds,
        )
        self._api_key = settings.openai_api_key

    async def complete(
        self,
        *,
        system: str,
        user: str,
        max_tokens: int,
        temperature: float,
        json_only: bool = False,
    ) -> LLMResult:
        payload: dict[str, Any] = {
            "model": self.model,
            "max_completion_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if json_only:
            payload["response_format"] = {"type": "json_object"}
        data, error, elapsed = await self._post(
            "/v1/chat/completions",
            payload,
            {
                "authorization": f"Bearer {self._api_key}",
                "content-type": "application/json",
            },
        )
        if data is None:
            return LLMResult(
                text="", provider=self.name, model=self.model, latency_ms=elapsed, error=error
            )
        choices = data.get("choices") or []
        text = choices[0].get("message", {}).get("content", "") if choices else ""
        usage = data.get("usage") or {}
        return LLMResult(
            text=text or "",
            provider=self.name,
            model=data.get("model", self.model),
            input_tokens=int(usage.get("prompt_tokens", 0)),
            output_tokens=int(usage.get("completion_tokens", 0)),
            latency_ms=elapsed,
        )


class OllamaProvider(_HttpProvider):
    """Local open-weight models (Llama, Mistral) via Ollama.

    This is the deployment-mode provider: attacker payloads never leave the
    host, which matters both for cost and for the data-handling posture in
    Section 10.
    """

    name = "ollama"

    def __init__(self, settings: Settings) -> None:
        super().__init__(
            base_url=settings.ollama_base_url,
            model=settings.ollama_model,
            timeout=settings.llm_timeout_seconds,
        )

    async def complete(
        self,
        *,
        system: str,
        user: str,
        max_tokens: int,
        temperature: float,
        json_only: bool = False,
    ) -> LLMResult:
        payload: dict[str, Any] = {
            "model": self.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if json_only:
            payload["format"] = "json"
        data, error, elapsed = await self._post(
            "/api/chat", payload, {"content-type": "application/json"}
        )
        if data is None:
            return LLMResult(
                text="", provider=self.name, model=self.model, latency_ms=elapsed, error=error
            )
        return LLMResult(
            text=(data.get("message") or {}).get("content", ""),
            provider=self.name,
            model=data.get("model", self.model),
            input_tokens=int(data.get("prompt_eval_count", 0)),
            output_tokens=int(data.get("eval_count", 0)),
            latency_ms=elapsed,
        )


_PROVIDERS = {
    "offline": OfflineProvider,
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "ollama": OllamaProvider,
}


def build_provider(name: str, settings: Settings) -> LLMProvider:
    """Instantiate a provider, degrading to offline if it is misconfigured."""
    key = (name or "offline").strip().lower()
    factory = _PROVIDERS.get(key)
    if factory is None:
        log.warning("unknown LLM provider %r; using offline", name)
        return OfflineProvider()
    if not settings.provider_is_configured(key):
        log.warning(
            "LLM provider %r selected but not configured (missing API key); "
            "using the deterministic offline engine instead",
            key,
        )
        return OfflineProvider()
    if key == "offline":
        return OfflineProvider()
    return factory(settings)  # type: ignore[call-arg]


_cache: dict[str, LLMProvider] = {}


def get_provider(name: str, settings: Settings) -> LLMProvider:
    """Cached provider instance, so the HTTP connection pool is reused."""
    key = (name or "offline").strip().lower()
    if key not in _cache:
        _cache[key] = build_provider(key, settings)
    return _cache[key]


async def close_providers() -> None:
    for provider in list(_cache.values()):
        await provider.aclose()
    _cache.clear()
