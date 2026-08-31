"""Section 9 evaluation harness: metrics, labels, and a tiny live run."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegistrap.eval.harness import run_evaluation
from aegistrap.eval.labels import expected_techniques
from aegistrap.eval.metrics import classification_report, percentile, set_f1
from aegistrap.models import AttackerPersona
from aegistrap.profiler.synthetic import generate_session
from aegistrap.store import Event


def test_set_f1_is_symmetric_on_identical_sets() -> None:
    score = set_f1(["T1190", "T1087"], ["T1087", "T1190"])
    assert score["f1"] == 1.0
    assert score["precision"] == 1.0
    assert score["recall"] == 1.0


def test_set_f1_penalises_invented_tags() -> None:
    score = set_f1(["T1190", "T9999"], ["T1190"])
    assert score["false_positives"] == 1
    assert score["recall"] == 1.0
    assert score["precision"] == 0.5


def test_classification_report_accuracy() -> None:
    report = classification_report(
        [("scanner", "scanner"), ("scanner", "script_kiddie"), ("ai_agent", "ai_agent")],
        labels=["scanner", "script_kiddie", "ai_agent"],
    )
    assert report["n"] == 3
    assert report["accuracy"] == pytest.approx(2 / 3, abs=1e-4)
    assert report["confusion"]["scanner"]["scanner"] == 1


def test_percentile_bounds() -> None:
    assert percentile([], 50) == 0.0
    assert percentile([4.0], 95) == 4.0
    assert percentile([1.0, 2.0, 3.0, 4.0], 50) == 2.5


def test_expected_techniques_from_sqli_and_wordlist() -> None:
    events = [
        Event(
            id=1,
            session_id="s",
            seq=1,
            ts=0.0,
            method="GET",
            path="/api/v1/accounts/1' OR '1'='1",
            query_string="",
            headers={},
            body="",
            status_code=500,
            response="",
            generator="template",
            latency_ms=1.0,
            llm_tokens=0,
            weaknesses=[],
            persona_at_time="scanner",
        ),
        Event(
            id=2,
            session_id="s",
            seq=2,
            ts=0.0,
            method="GET",
            path="/.env",
            query_string="",
            headers={},
            body="",
            status_code=404,
            response="",
            generator="template",
            latency_ms=1.0,
            llm_tokens=0,
            weaknesses=[],
            persona_at_time="scanner",
        ),
    ]
    tags = expected_techniques(events)
    assert "T1190" in tags
    assert "T1595" in tags
    assert "T1071.001" in tags


def test_synthetic_scanner_session_has_expected_tags() -> None:
    import random

    events = generate_session(AttackerPersona.SCANNER, random.Random(0))
    tags = expected_techniques(events)
    assert tags  # a scanner session is never an empty campaign


def test_evaluation_harness_writes_results(tmp_path: Path) -> None:
    result = run_evaluation(
        output_dir=tmp_path,
        per_persona=6,
        live_per_persona=1,
        seed=20260831,
        train_ml=False,
    )
    assert (tmp_path / "results.json").exists()
    assert (tmp_path / "results.md").exists()
    assert result.profiling["heuristic"]["n"] == 6 * 5
    assert result.profiling["heuristic"]["accuracy"] >= 0.5
    assert result.consistency["ok"] is True
    assert result.consistency["http_agrees_with_store"] is True
