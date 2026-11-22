"""Export committed synthetic fixtures under ``data/synthetic/``.

These files are the labelled test set for the profiler, the signature
catalogue, and the HTTP replay used to exercise a running decoy. Everything
here is generated in-process from the same generators the unit tests use, so
a replay of this folder is reproducible given the seed.
"""

from __future__ import annotations

import csv
import json
import tempfile
from pathlib import Path

from aegistrap.config import REPO_ROOT
from aegistrap.decoy.world import collections_for_persona, seed_world
from aegistrap.models import AttackerPersona
from aegistrap.profiler.features import extract_features
from aegistrap.profiler.heuristic import classify as heuristic_classify
from aegistrap.profiler.synthetic import generate_dataset, generate_session, supported_personas
from aegistrap.store import StateStore

SEED = 20260831
OUT = REPO_ROOT / "data" / "synthetic"


def _dump_world(persona: str, session_id: str) -> dict:
    tmp = Path(tempfile.mkdtemp()) / f"{persona}.sqlite3"
    store = StateStore(tmp)
    try:
        session, _ = store.get_or_create_session(
            session_key=f"fixture:{persona}",
            source_ip="203.0.113.10",
            user_agent="aegistrap-fixture/1.0",
            world_persona=persona,
            idle_seconds=86_400,
        )
        with store._lock:
            store._conn.execute("UPDATE sessions SET id = ? WHERE id = ?", (session_id, session.id))
            store._conn.commit()
        seed_world(store, session_id, persona)
        world: dict = {"persona": persona, "session_id": session_id, "collections": {}}
        for collection in collections_for_persona(persona):
            rows = []
            for obj in store.list_objects(session_id, collection, limit=500):
                rows.append(
                    {
                        "id": obj.object_id,
                        "owner_id": obj.owner_id,
                        "sensitive": obj.sensitive,
                        "data": obj.data,
                    }
                )
            world["collections"][collection] = rows
        users = world["collections"].get("users", [])
        world["test_credentials"] = [
            {
                "email": row["data"]["email"],
                "password": row["data"].get("password_plaintext"),
                "role": row["data"].get("role"),
                "user_id": row["data"]["id"],
                "status": row["data"].get("status"),
            }
            for row in users
            if row["data"].get("password_plaintext")
        ]
        return world
    finally:
        store.close()
        tmp.unlink(missing_ok=True)


def _event_record(event) -> dict:
    return {
        "seq": event.seq,
        "method": event.method,
        "path": event.path,
        "query": event.query_string,
        "headers": event.headers,
        "body": event.body,
        "status": event.status_code,
    }


def export_sessions(per_persona: int = 12) -> list[dict]:
    dataset = generate_dataset(per_persona=per_persona, seed=SEED)
    rows = []
    for index, (persona, events) in enumerate(dataset):
        features = extract_features(events)
        verdict = heuristic_classify(features)
        rows.append(
            {
                "id": f"{persona.value}-{index:03d}",
                "ground_truth_persona": persona.value,
                "heuristic_persona": verdict.persona.value,
                "heuristic_confidence": verdict.confidence,
                "heuristic_signals": verdict.signals,
                "features": features.to_dict(),
                "feature_vector": features.to_vector(),
                "event_count": len(events),
                "events": [_event_record(e) for e in events[:40]],
            }
        )
    return rows


def export_http_replays() -> dict[str, list[dict]]:
    """Compact HTTP scripts a tester can replay against a live decoy."""
    browser = {
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
        ),
        "accept": "application/json",
        "accept-language": "en-GB,en;q=0.9",
        "accept-encoding": "gzip, deflate, br",
        "referer": "https://app.northwind.test/",
        "sec-fetch-mode": "cors",
    }
    return {
        "benign": [
            {"method": "GET", "path": "/api/v1/health", "headers": browser},
            {"method": "GET", "path": "/api/v1/accounts", "headers": browser},
            {
                "method": "POST",
                "path": "/api/v1/auth/login",
                "headers": browser,
                "json": {"email": "REPLACE_EMAIL", "password": "REPLACE_PASSWORD"},
            },
        ],
        "attacker": [
            {
                "method": "GET",
                "path": "/.env",
                "headers": {"user-agent": "sqlmap/1.8.2#stable (https://sqlmap.org)"},
            },
            {"method": "GET", "path": "/admin", "headers": {"user-agent": "Nikto/2.5.0"}},
            {
                "method": "GET",
                "path": "/api/v1/accounts/1' OR '1'='1",
                "headers": {"user-agent": "python-requests/2.31.0"},
            },
            {"method": "GET", "path": "/api/v1/accounts/1001", "headers": browser},
            {"method": "GET", "path": "/api/v1/accounts/1002", "headers": browser},
            {
                "method": "GET",
                "path": "/api/v1/accounts/1001' AND (SELECT 1 FROM pg_sleep(0))--",
                "headers": browser,
            },
            {
                "method": "PATCH",
                "path": "/api/v1/users/me",
                "headers": browser,
                "json": {"role": "admin"},
            },
        ],
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "http").mkdir(exist_ok=True)

    fintech = _dump_world("fintech", "synthetic-fintech-fixture")
    ecommerce = _dump_world("ecommerce", "synthetic-ecommerce-fixture")
    (OUT / "world_fintech.json").write_text(json.dumps(fintech, indent=2), encoding="utf-8")
    (OUT / "world_ecommerce.json").write_text(json.dumps(ecommerce, indent=2), encoding="utf-8")

    customer = next(
        c
        for c in fintech["test_credentials"]
        if c["role"] == "customer" and c["status"] == "active"
    )
    replays = export_http_replays()
    for step in replays["benign"]:
        if step.get("json") and "REPLACE_EMAIL" in str(step["json"]):
            step["json"] = {"email": customer["email"], "password": customer["password"]}
    for persona, steps in replays.items():
        (OUT / "http" / f"{persona}.json").write_text(
            json.dumps(
                {
                    "ground_truth_persona": persona,
                    "notes": "Replay with: python scripts/replay_synthetic.py --persona " + persona,
                    "steps": steps,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    sessions = export_sessions(per_persona=12)
    with (OUT / "sessions.jsonl").open("w", encoding="utf-8") as handle:
        for row in sessions:
            handle.write(json.dumps(row) + "\n")

    names = extract_features(generate_session(AttackerPersona.BENIGN)).vector_names()
    with (OUT / "feature_matrix.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["id", "ground_truth_persona", "heuristic_persona", *names])
        for row in sessions:
            writer.writerow(
                [
                    row["id"],
                    row["ground_truth_persona"],
                    row["heuristic_persona"],
                    *row["feature_vector"],
                ]
            )

    # Detection-fixture payload catalogue (classifier inputs, not an exploit guide).
    from aegistrap.profiler.signatures import scan_payload

    samples = [
        ("benign_id", "1001"),
        ("benign_email", "adaeze.okafor.0@example.com"),
        ("sqli_tautology", "1' OR '1'='1"),
        ("sqli_union", "1 UNION ALL SELECT null,version()--"),
        ("sqli_blind", "' AND (SELECT 1 FROM pg_sleep(5))--"),
        ("traversal", "../../../../etc/passwd"),
        ("xss_reflected", "<script>alert(1)</script>"),
        ("ssrf_metadata", "http://169.254.169.254/latest/meta-data/"),
        ("cmdi", ";cat /etc/passwd"),
        ("nosqli", '{"password": {"$ne": null}}'),
    ]
    payload_rows = []
    for name, sample in samples:
        matches = [
            {"family": m.family, "sophistication": m.sophistication, "rule": m.name}
            for m in scan_payload(sample)
        ]
        payload_rows.append({"id": name, "sample": sample, "matches": matches})
    (OUT / "payload_catalogue.json").write_text(
        json.dumps(
            {"description": "Signature-scanner test vectors", "items": payload_rows}, indent=2
        ),
        encoding="utf-8",
    )

    agreement = sum(1 for s in sessions if s["ground_truth_persona"] == s["heuristic_persona"])
    manifest = {
        "seed": SEED,
        "per_persona": 12,
        "personas": [p.value for p in supported_personas()],
        "files": {
            "world_fintech.json": "Deterministic Northwind Capital fake world + login credentials",
            "world_ecommerce.json": "Deterministic Northwind Shop fake world + login credentials",
            "sessions.jsonl": "Labelled synthetic sessions with features and truncated transcripts",
            "feature_matrix.csv": "Numeric feature matrix for the ML comparison arm",
            "payload_catalogue.json": "Payload-family detection fixtures",
            "http/*.json": "HTTP replay scripts for benign and attacker, for a live decoy",
        },
        "heuristic_agreement_on_this_export": {
            "n": len(sessions),
            "matches": agreement,
            "accuracy": round(agreement / len(sessions), 4) if sessions else 0.0,
        },
        "fintech_login_example": {
            "email": customer["email"],
            "password": customer["password"],
            "role": customer["role"],
            "note": "Valid only against a world seeded from session id synthetic-fintech-fixture, or after GET /health in a fresh session whose users you read from the store. Against a live decoy, log in with credentials from THAT session's world (see dashboard or data/aegistrap.sqlite3).",
        },
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"wrote {len(sessions)} sessions to {OUT}")


if __name__ == "__main__":
    main()
