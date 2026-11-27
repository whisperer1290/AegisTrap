"""Composition root.

Wires the five core modules together and owns the background sweeper that
closes idle sessions and triggers auto-reporting.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from typing import Any

from aegistrap.config import Settings, get_settings
from aegistrap.evasion import FingerprintMutator
from aegistrap.intel.reporter import ThreatIntelReporter
from aegistrap.llm.engine import ResponseEngine
from aegistrap.llm.providers import LLMProvider, close_providers, get_provider
from aegistrap.logging_setup import get_logger
from aegistrap.profiler.service import AttackerProfiler, ProfilerMode
from aegistrap.store import StateStore, get_store

log = get_logger("runtime")


@dataclass
class AppRuntime:
    settings: Settings
    store: StateStore
    profiler: AttackerProfiler
    engine: ResponseEngine
    reporter: ThreatIntelReporter
    evasion: FingerprintMutator
    response_provider: LLMProvider
    reporter_provider: LLMProvider

    def describe(self) -> dict[str, Any]:
        return {
            "persona": self.settings.persona,
            "adaptive_deception": self.settings.adaptive_deception,
            "profiler_mode": self.profiler.mode,
            "response_engine": self.engine.stats(),
            "reporter": self.reporter.stats(),
            "fingerprint_evasion": self.evasion.describe(),
            "store": self.store.summary_stats(),
        }


def build_runtime(
    settings: Settings | None = None,
    *,
    profiler_mode: ProfilerMode | None = None,
    store: StateStore | None = None,
) -> AppRuntime:
    settings = settings or get_settings()
    mode: ProfilerMode = profiler_mode or settings.profiler_mode
    settings.ensure_directories()
    store = store or get_store(settings.db_path)

    response_provider = get_provider(settings.llm_provider, settings)
    reporter_provider = get_provider(settings.effective_reporter_provider, settings)

    log.info(
        "response engine: %s (%s) | reporter: %s | persona: %s | adaptive: %s",
        getattr(response_provider, "name", "?"),
        getattr(response_provider, "model", "?"),
        getattr(reporter_provider, "name", "?"),
        settings.persona,
        settings.adaptive_deception,
    )

    return AppRuntime(
        settings=settings,
        store=store,
        profiler=AttackerProfiler(store, mode=mode, adaptive=settings.adaptive_deception),
        engine=ResponseEngine(settings, response_provider, store),
        reporter=ThreatIntelReporter(settings, reporter_provider, store),
        evasion=FingerprintMutator(
            enabled=settings.fingerprint_evasion,
            service_name=settings.service_name,
            service_version=settings.service_version,
            base_latency_floor_ms=settings.latency_floor_ms,
            base_latency_jitter_ms=settings.latency_jitter_ms,
            banner=settings.server_banner,
        ),
        response_provider=response_provider,
        reporter_provider=reporter_provider,
    )


async def shutdown_runtime(runtime: AppRuntime) -> None:
    await close_providers()
    runtime.store.close()


class SessionSweeper:
    """Closes idle sessions and auto-reports them.

    Section 6 specifies the reporter runs "on a timer or when a session
    closes". Since attackers do not announce that they are finished, a session
    is considered closed once it has been idle past the configured gap.
    """

    def __init__(self, runtime: AppRuntime) -> None:
        self.runtime = runtime
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()
        self.sweeps = 0
        self.closed_sessions = 0
        self.reports_written = 0

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stopping.clear()
            self._task = asyncio.create_task(self._loop(), name="aegistrap-sweeper")

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None

    async def _loop(self) -> None:
        interval = max(5, self.runtime.settings.report_sweep_seconds)
        while not self._stopping.is_set():
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=interval)
                return
            except TimeoutError:
                pass
            try:
                await self.sweep_once()
            except Exception as exc:
                log.warning("session sweep failed: %s", exc)

    async def sweep_once(self) -> dict[str, int]:
        settings = self.runtime.settings
        store = self.runtime.store
        self.sweeps += 1

        closed = 0
        for session in store.find_idle_sessions(settings.session_idle_seconds):
            store.close_session(session.id, ts=session.last_seen)
            closed += 1
        self.closed_sessions += closed

        written = 0
        if settings.auto_report_enabled:
            for session in store.find_unreported_sessions(limit=10):
                refreshed = store.get_session(session.id) or session
                await self.runtime.reporter.report_session(refreshed)
                written += 1
        self.reports_written += written

        if closed or written:
            log.info("sweep: closed %d session(s), wrote %d report(s)", closed, written)
        return {"closed": closed, "reports": written}
