"""End-to-end evaluation against the metrics in synopsis Section 9.

Runs two complementary arms:

* **Offline profiling.** Classifies synthetic labelled sessions through the
  heuristic (and optional ML) profiler. This is the profiling-accuracy metric.
* **Live decoy.** Replays a smaller labelled sample over HTTP so report
  tagging, state consistency, latency, and the adaptive surface can be scored
  against a running FastAPI app.
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from aegistrap.config import Settings, reset_settings_cache
from aegistrap.eval.labels import expected_techniques
from aegistrap.eval.metrics import classification_report, percentile, set_f1
from aegistrap.logging_setup import get_logger
from aegistrap.models import AttackerPersona
from aegistrap.profiler.features import extract_features
from aegistrap.profiler.heuristic import classify as heuristic_classify
from aegistrap.profiler.ml import MLProfiler
from aegistrap.profiler.synthetic import generate_dataset, generate_session, supported_personas
from aegistrap.store import Event, StateStore, reset_store

log = get_logger("eval")

_MAX_LIVE_EVENTS = 28


@dataclass
class EvaluationResult:
    profiling: dict[str, Any]
    reporting: dict[str, Any]
    live: dict[str, Any]
    consistency: dict[str, Any]
    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.generated_at)),
            "profiling": self.profiling,
            "reporting": self.reporting,
            "live": self.live,
            "consistency": self.consistency,
        }


def run_evaluation(
    *,
    output_dir: Path,
    per_persona: int = 40,
    live_per_persona: int = 2,
    seed: int = 20260831,
    train_ml: bool = False,
) -> EvaluationResult:
    """Run the full Section 9 prototype evaluation and write ``results.json``."""
    output_dir.mkdir(parents=True, exist_ok=True)
    profiling = _evaluate_profiling(per_persona=per_persona, seed=seed, train_ml=train_ml)
    live = _evaluate_live(output_dir / "live", per_persona=live_per_persona, seed=seed)
    result = EvaluationResult(
        profiling=profiling,
        reporting=live["reporting"],
        live=live["sessions"],
        consistency=live["consistency"],
    )
    (output_dir / "results.json").write_text(
        json.dumps(result.to_dict(), indent=2), encoding="utf-8"
    )
    (output_dir / "results.md").write_text(_render_markdown(result), encoding="utf-8")
    return result


def _evaluate_profiling(*, per_persona: int, seed: int, train_ml: bool) -> dict[str, Any]:
    dataset = generate_dataset(per_persona=per_persona, seed=seed)
    heuristic_pairs: list[tuple[str, str]] = []
    for persona, events in dataset:
        verdict = heuristic_classify(extract_features(events))
        heuristic_pairs.append((persona.value, verdict.persona.value))

    labels = [p.value for p in supported_personas()]
    result: dict[str, Any] = {
        "baseline": "heuristic",
        "heuristic": classification_report(heuristic_pairs, labels=labels),
    }

    if train_ml:
        profiler, metrics = MLProfiler.train(per_persona=max(40, per_persona), seed=seed)
        ml_pairs: list[tuple[str, str]] = []
        for persona, events in dataset:
            verdict = profiler.classify(extract_features(events))
            predicted = verdict.persona.value if verdict else AttackerPersona.UNKNOWN.value
            ml_pairs.append((persona.value, predicted))
        result["ml"] = classification_report(ml_pairs, labels=labels)
        result["ml_holdout"] = {
            "samples": metrics.get("samples"),
            "test_size": metrics.get("test_size"),
        }
    return result


def _evaluate_live(output_dir: Path, *, per_persona: int, seed: int) -> dict[str, Any]:
    reset_settings_cache()
    reset_store()
    output_dir.mkdir(parents=True, exist_ok=True)
    settings = Settings(
        db_path=output_dir / "eval.sqlite3",
        report_dir=output_dir / "reports",
        llm_provider="offline",
        latency_floor_ms=0,
        latency_jitter_ms=0,
        auto_report_enabled=False,
        report_sweep_seconds=3600,
        dashboard_enabled=True,
        dashboard_token="",
        log_level="WARNING",
    )
    settings.ensure_directories()

    from aegistrap.main import create_app

    app = create_app(settings)
    rng = random.Random(seed)
    latencies: list[float] = []
    persona_pairs: list[tuple[str, str]] = []
    report_scores: list[dict[str, Any]] = []
    surfaces: dict[str, set[str]] = {p.value: set() for p in supported_personas()}
    request_counts: list[int] = []

    with TestClient(app) as client:
        store: StateStore = app.state.runtime.store
        consistency = _probe_consistency(client, store)

        for persona in supported_personas():
            for index in range(per_persona):
                events = generate_session(persona, rng)
                gold = expected_techniques(events)
                token = f"eval-{persona.value}-{index}"
                replayed = _replay_session(
                    client,
                    events[:_MAX_LIVE_EVENTS],
                    session_token=token,
                    persona=persona,
                    gold_techniques=gold,
                )
                latencies.extend(replayed["latencies"])
                request_counts.append(replayed["requests"])

                matched = _session_by_token(store, token)
                if matched is None:
                    continue
                persona_pairs.append((persona.value, matched.persona.value))
                for event in store.get_events(matched.id, limit=200):
                    surfaces[persona.value].update(event.weaknesses)

                store.close_session(matched.id)
                report = client.post(f"/dashboard/api/sessions/{matched.id}/report")
                if report.status_code != 200:
                    continue
                predicted = [
                    t["id"]
                    for t in report.json()
                    .get("document", {})
                    .get("mitre_attack", {})
                    .get("techniques", [])
                ]
                score = set_f1(predicted, gold)
                score["session_id"] = matched.id
                score["persona"] = persona.value
                report_scores.append(score)

    mean_f1 = sum(s["f1"] for s in report_scores) / len(report_scores) if report_scores else 0.0
    labels = [p.value for p in supported_personas()]
    return {
        "reporting": {
            "scorer": "request-only ground truth (eval.labels)",
            "mean_f1": round(mean_f1, 4),
            "sessions": report_scores,
        },
        "sessions": {
            "profiling_on_live_traffic": classification_report(persona_pairs, labels=labels),
            "mean_requests": round(sum(request_counts) / len(request_counts), 2)
            if request_counts
            else 0.0,
            "latency_ms": {
                "p50": round(percentile(latencies, 50), 2),
                "p95": round(percentile(latencies, 95), 2),
                "n": len(latencies),
            },
            "weaknesses_by_persona": {k: sorted(v) for k, v in surfaces.items()},
        },
        "consistency": consistency,
    }


def _session_by_token(store: StateStore, token: str):
    expected = f"explicit:{token}"
    for session in store.list_sessions(limit=500):
        if session.session_key == expected:
            return session
    return None


def _replay_session(
    client: TestClient,
    events: list[Event],
    *,
    session_token: str,
    persona: AttackerPersona,
    gold_techniques: list[str],
) -> dict[str, Any]:
    latencies: list[float] = []
    sent = 0
    control = {
        "x-aegistrap-session": session_token,
        "x-aegistrap-gt-persona": persona.value,
        "x-aegistrap-gt-techniques": ",".join(gold_techniques),
        "x-aegistrap-experiment": "section9",
    }
    for event in events:
        headers = {**event.headers, **control}
        url = event.path
        if event.query_string:
            url = f"{event.path}?{event.query_string}"
        started = time.perf_counter()
        try:
            client.request(
                event.method,
                url,
                headers=headers,
                content=event.body.encode() if event.body else None,
            )
        except Exception as exc:
            log.warning("eval replay failed on %s %s: %s", event.method, url, exc)
            continue
        latencies.append((time.perf_counter() - started) * 1000)
        sent += 1
    return {"latencies": latencies, "requests": sent}


def _probe_consistency(client: TestClient, store: StateStore) -> dict[str, Any]:
    """GET → transfer → GET must not contradict the ledger (Section 13)."""
    headers = {
        "user-agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/128.0.0.0 Safari/537.36"
        ),
        "accept": "application/json",
        "x-aegistrap-session": "eval-consistency",
        "x-aegistrap-experiment": "consistency",
    }
    health = client.get("/api/v1/health", headers=headers)
    if health.status_code != 200:
        return {"ok": False, "reason": health.text}

    session = _session_by_token(store, "eval-consistency")
    if session is None:
        return {"ok": False, "reason": "consistency session missing"}

    users = store.list_objects(session.id, "users", limit=50)
    customer = next(
        (u for u in users if u.data.get("role") == "customer" and u.data.get("status") == "active"),
        None,
    )
    if customer is None:
        return {"ok": False, "reason": "no active customer"}

    login = client.post(
        "/api/v1/auth/login",
        json={
            "email": customer.data["email"],
            "password": customer.data["password_plaintext"],
        },
        headers=headers,
    )
    if login.status_code != 200:
        return {"ok": False, "reason": login.text, "contradictions": 1}

    auth = {**headers, "authorization": f"Bearer {login.json()['access_token']}"}
    owned = [
        obj
        for obj in store.list_objects(session.id, "accounts", limit=50)
        if obj.owner_id == customer.data["id"]
    ]
    others = [
        obj
        for obj in store.list_objects(session.id, "accounts", limit=50)
        if obj.owner_id != customer.data["id"]
    ]
    if not owned or not others:
        return {"ok": False, "reason": "not enough accounts"}

    source, dest = owned[0], others[0]
    before = int(source.data["balance_minor"])
    amount = min(2500, max(100, before // 20))

    transfer = client.post(
        "/api/v1/transfers",
        json={
            "from_account": source.object_id,
            "to_account": dest.object_id,
            "amount_minor": amount,
        },
        headers=auth,
    )
    after_source = store.get_object(session.id, "accounts", source.object_id)
    after_http = client.get(f"/api/v1/accounts/{source.object_id}", headers=auth)
    http_balance = after_http.json().get("balance_minor") if after_http.status_code == 200 else None
    stored_balance = int(after_source.data["balance_minor"]) if after_source else None
    moved = transfer.status_code in (200, 201) and stored_balance == before - amount
    refused = transfer.status_code == 422 and stored_balance == before
    ok = stored_balance is not None and http_balance == stored_balance and (moved or refused)
    refreshed = store.get_session(session.id)
    return {
        "ok": bool(ok),
        "transfer_status": transfer.status_code,
        "balance_before": before,
        "amount_minor": amount,
        "balance_after_store": stored_balance,
        "balance_after_http": http_balance,
        "store_contradictions": refreshed.consistency_violations if refreshed else 0,
        "http_agrees_with_store": http_balance == stored_balance,
    }


def _render_markdown(result: EvaluationResult) -> str:
    data = result.to_dict()
    lines = [
        "# AegisTrap evaluation (Section 9)",
        "",
        f"Generated `{data['generated_at']}`.",
        "",
        "## Profiling accuracy",
        "",
        f"Heuristic accuracy: **{data['profiling']['heuristic']['accuracy']}** "
        f"(n={data['profiling']['heuristic']['n']}).",
        "",
        "| Persona | Precision | Recall | F1 | Support |",
        "| --- | --- | --- | --- | --- |",
    ]
    for label, row in data["profiling"]["heuristic"]["per_class"].items():
        lines.append(
            f"| `{label}` | {row['precision']} | {row['recall']} | {row['f1']} | {int(row['support'])} |"
        )
    if "ml" in data["profiling"]:
        lines += [
            "",
            f"ML comparison arm accuracy: **{data['profiling']['ml']['accuracy']}**.",
        ]
    lines += [
        "",
        "## Auto-report quality",
        "",
        "F1 of ATT&CK tags against request-only ground truth "
        f"(mean across live sessions): **{data['reporting']['mean_f1']}**.",
        "",
        "## Live decoy",
        "",
        f"- Mean requests per replayed session: {data['live']['mean_requests']}",
        f"- Latency p50 / p95 (ms): {data['live']['latency_ms']['p50']} / "
        f"{data['live']['latency_ms']['p95']}",
        f"- Live-traffic profiling accuracy: {data['live']['profiling_on_live_traffic']['accuracy']}",
        "",
        "## Consistency",
        "",
        f"- Ledger probe passed: **{data['consistency']['ok']}**",
        f"- HTTP GET agrees with store after transfer: "
        f"{data['consistency'].get('http_agrees_with_store')}",
        f"- Engine-recorded contradictions: {data['consistency'].get('store_contradictions')}",
        "",
        "Deception fidelity (a blind mix of real vs honeypot responses) is a human "
        "study and is not automated here. Run a red-team session against "
        "`http://127.0.0.1:8000` and score identification rate separately.",
        "",
    ]
    return "\n".join(lines)
