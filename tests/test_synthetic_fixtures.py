"""Committed synthetic fixtures are present and well-formed."""

from __future__ import annotations

import csv
import json

from aegistrap.config import REPO_ROOT
from aegistrap.models import AttackerPersona

SYN = REPO_ROOT / "data" / "synthetic"


def test_manifest_lists_expected_personas() -> None:
    manifest = json.loads((SYN / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["seed"] == 20260831
    assert manifest["per_persona"] == 12
    assert set(manifest["personas"]) == {p.value for p in AttackerPersona if p.value != "unknown"}
    assert manifest["heuristic_agreement_on_this_export"]["n"] == 60


def test_worlds_contain_synthetic_credentials() -> None:
    fintech = json.loads((SYN / "world_fintech.json").read_text(encoding="utf-8"))
    shop = json.loads((SYN / "world_ecommerce.json").read_text(encoding="utf-8"))
    assert fintech["test_credentials"]
    assert shop["test_credentials"]
    email = fintech["test_credentials"][0]["email"]
    assert email.endswith(("example.com", "example.net", "mail.invalid"))
    assert fintech["collections"]["accounts"]
    assert shop["collections"]["products"]


def test_sessions_jsonl_is_labelled() -> None:
    lines = (SYN / "sessions.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 60
    row = json.loads(lines[0])
    assert "ground_truth_persona" in row
    assert "feature_vector" in row
    assert len(row["feature_vector"]) == 32


def test_feature_matrix_csv_matches_session_count() -> None:
    with (SYN / "feature_matrix.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 60
    assert "ground_truth_persona" in rows[0]


def test_http_replay_scripts_exist_for_every_persona() -> None:
    for persona in ("benign", "scanner", "script_kiddie", "skilled_human", "ai_agent"):
        bundle = json.loads((SYN / "http" / f"{persona}.json").read_text(encoding="utf-8"))
        assert bundle["steps"]
        assert bundle["ground_truth_persona"] == persona
