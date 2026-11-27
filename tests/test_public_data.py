"""CSIC 2010 dumps map onto binary benign / attacker sessions."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegistrap.models import AttackerPersona
from aegistrap.profiler.features import extract_features
from aegistrap.profiler.ml import MLProfiler, sklearn_available
from aegistrap.profiler.public_data import (
    infer_label_from_name,
    load_csic_directory,
    parse_csic_http_dump,
    sessions_from_records,
    summarize_sessions,
)

_BENIGN_DUMP = """\
GET http://localhost:8080/tienda1/index.jsp HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux)
Accept: text/html
Host: localhost:8080
Cookie: JSESSIONID=AAAA1111
Connection: close

GET http://localhost:8080/tienda1/publico/vaciar.jsp HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux)
Accept: text/html
Host: localhost:8080
Cookie: JSESSIONID=AAAA1111
Connection: close

GET http://localhost:8080/tienda1/index.jsp HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux)
Accept: text/html
Host: localhost:8080
Cookie: JSESSIONID=BBBB2222
Connection: close
"""

_ATTACK_DUMP = """\
GET http://localhost:8080/tienda1/publico/anadir.jsp?id=3%27+OR+1%3D1-- HTTP/1.1
User-Agent: sqlmap/1.7
Accept: */*
Host: localhost:8080
Cookie: JSESSIONID=CCCC3333
Connection: close

POST http://localhost:8080/tienda1/publico/registro.jsp HTTP/1.1
User-Agent: sqlmap/1.7
Content-Type: application/x-www-form-urlencoded
Host: localhost:8080
Cookie: JSESSIONID=CCCC3333
Content-Length: 44
Connection: close

modo=registro&login=admin'+OR+'1'='1&password=x
"""


def test_filename_maps_onto_binary_labels() -> None:
    assert infer_label_from_name(Path("normalTrafficTraining.txt")) is AttackerPersona.BENIGN
    assert infer_label_from_name(Path("anomalousTrafficTest.txt")) is AttackerPersona.ATTACKER
    assert infer_label_from_name(Path("readme.md")) is None


def test_parser_splits_get_and_post() -> None:
    records = parse_csic_http_dump(_ATTACK_DUMP)
    assert len(records) == 2
    assert records[0]["method"] == "GET"
    assert "OR+1" in str(records[0]["target"])
    assert records[1]["method"] == "POST"
    assert "login=admin" in str(records[1]["body"])


def test_sessions_group_by_jsessionid() -> None:
    records = parse_csic_http_dump(_BENIGN_DUMP)
    sessions = sessions_from_records(records, label=AttackerPersona.BENIGN)
    assert len(sessions) == 2
    lengths = sorted(len(events) for _, events in sessions)
    assert lengths == [1, 2]
    assert all(persona is AttackerPersona.BENIGN for persona, _ in sessions)


def test_attack_session_features_are_extractable() -> None:
    records = parse_csic_http_dump(_ATTACK_DUMP)
    _, events = sessions_from_records(records, label=AttackerPersona.ATTACKER)[0]
    features = extract_features(events)
    assert len(features.to_vector()) == 31
    assert features.payload_families or features.client_class.value == "scanner"


def test_load_csic_directory_requires_both_classes(tmp_path: Path) -> None:
    (tmp_path / "normalTrafficTraining.txt").write_text(_BENIGN_DUMP, encoding="latin-1")
    (tmp_path / "anomalousTrafficTest.txt").write_text(_ATTACK_DUMP, encoding="latin-1")
    sessions = load_csic_directory(tmp_path)
    summary = summarize_sessions(sessions)
    assert summary["benign"] >= 1
    assert summary["attacker"] >= 1
    assert summary["requests"] == 5


def test_load_csic_directory_rejects_one_sided_corpus(tmp_path: Path) -> None:
    (tmp_path / "normalTrafficTraining.txt").write_text(_BENIGN_DUMP, encoding="latin-1")
    with pytest.raises(ValueError, match="both normal and anomalous"):
        load_csic_directory(tmp_path)


def _csic_sessions(kind: str, count: int) -> str:
    blocks = []
    for i in range(count):
        sid = f"{kind}{i:04d}SESS"
        if kind == "attack":
            blocks.append(
                f"GET http://localhost:8080/tienda1/publico/anadir.jsp?id=3%27+OR+1%3D1-- HTTP/1.1\n"
                f"User-Agent: sqlmap/1.7\nHost: localhost:8080\n"
                f"Cookie: JSESSIONID={sid}\nConnection: close\n"
            )
        else:
            blocks.append(
                f"GET http://localhost:8080/tienda1/index.jsp HTTP/1.1\n"
                f"User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux)\n"
                f"Host: localhost:8080\nCookie: JSESSIONID={sid}\nConnection: close\n"
            )
    return "\n".join(blocks)


def test_unique_jsessionids_fall_back_to_fixed_windows() -> None:
    """CSIC mints a fresh cookie per request; don't emit 1-request sessions."""
    records = parse_csic_http_dump(_csic_sessions("normal", 25))
    sessions = sessions_from_records(records, label=AttackerPersona.BENIGN)
    assert len(sessions) == 3
    assert sorted(len(events) for _, events in sessions) == [5, 10, 10]


def test_encoded_sqli_payload_is_detected_after_decoding() -> None:
    records = parse_csic_http_dump(_ATTACK_DUMP)
    _, events = sessions_from_records(records, label=AttackerPersona.ATTACKER)[0]
    features = extract_features(events)
    assert "sqli" in features.payload_families


def test_double_encoded_xss_payload_is_detected_after_decoding() -> None:
    dump = (
        "GET http://localhost:8080/tienda1/publico/registro.jsp?"
        "login=%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E HTTP/1.1\n"
        "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux)\n"
        "Host: localhost:8080\nCookie: JSESSIONID=DDDD4444\nConnection: close\n"
    )
    records = parse_csic_http_dump(dump)
    _, events = sessions_from_records(records, label=AttackerPersona.ATTACKER)[0]
    features = extract_features(events)
    assert "xss" in features.payload_families
    assert "xss_script_tag" in features.matched_signatures


@pytest.mark.skipif(not sklearn_available(), reason="scikit-learn is not installed")
def test_random_forest_trains_on_csic_sessions(tmp_path: Path) -> None:
    (tmp_path / "normalTrafficTraining.txt").write_text(_csic_sessions("normal", 100), encoding="latin-1")
    (tmp_path / "anomalousTrafficTest.txt").write_text(_csic_sessions("attack", 100), encoding="latin-1")
    sessions = load_csic_directory(tmp_path)
    model, metrics = MLProfiler.train(
        labelled_sessions=sessions, source="csic2010", n_estimators=20, seed=20260831
    )
    assert model.is_ready
    assert metrics["source"] == "csic2010"
    assert "benign" in metrics["holdout_report"]
    assert "attacker" in metrics["holdout_report"]
