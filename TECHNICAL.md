# AegisTrap — Technical Documentation

An LLM-powered adaptive API honeypot: a stateful fake fintech (or e-commerce) REST/GraphQL backend that classifies each session as benign or attacker, adapts the vulnerability surface it exposes, and auto-generates MITRE ATT&CK / OWASP / CWE incident reports.

This document is the operator and implementer reference. It covers how to run every part of the system, the technology stack, the algorithms behind profiling and reporting, the LLM design, and the synthetic test data under `data/synthetic/`.

---

## Table of contents

1. [What this system is](#1-what-this-system-is)
2. [How to run everything](#2-how-to-run-everything)
3. [Repository layout](#3-repository-layout)
4. [Technology stack](#4-technology-stack)
5. [End-to-end architecture](#5-end-to-end-architecture)
6. [Decoy API and fake world](#6-decoy-api-and-fake-world)
7. [Session state store](#7-session-state-store)
8. [Attacker profiling](#8-attacker-profiling)
9. [Deception policy](#9-deception-policy)
10. [LLM response engine](#10-llm-response-engine)
11. [Threat-intelligence auto-reporter](#11-threat-intelligence-auto-reporter)
12. [Dashboard](#12-dashboard)
13. [Fingerprint evasion](#13-fingerprint-evasion)
14. [Evaluation harness](#14-evaluation-harness)
15. [Synthetic test data](#15-synthetic-test-data)
16. [HTTP and GraphQL surface](#16-http-and-graphql-surface)
17. [Configuration reference](#17-configuration-reference)
18. [Tests, Docker, ethics](#18-tests-docker-ethics)
19. [Troubleshooting](#19-troubleshooting)

---

## 1. What this system is

AegisTrap is **deception technology**, not a WAF and not an exploit toolkit. It sits where a real bank or shop API would sit, answers in JSON, keeps a consistent fake ledger per attacker session, and records everything.

Five modules match the project synopsis:

| Module | Role |
| --- | --- |
| Decoy API layer | FastAPI REST + hand-rolled GraphQL, OpenAPI-documented, seeded fake flaws |
| Session state store | SQLite fake world so balances, users, and orders never contradict themselves |
| Attacker profiler | Classifies each session; drives how much of the fake surface is reachable |
| LLM response engine | Optional generation that **renders** store state, never invents it |
| Auto-reporter | Turns a closed session into ATT&CK / OWASP / CWE Markdown + YAML |

Default mode is fully **offline**: no API key, no outbound model calls. That mode is also the static baseline used in evaluation.

Classes the profiler can emit:

| Value | Meaning |
| --- | --- |
| `benign` | Looks like a real client |
| `attacker` | Attack payloads, scanners, wordlists, or sequential exploitation |
| `unknown` | Not enough evidence yet; keep the surface conservative |

---

## 2. How to run everything

### 2.1 Prerequisites

- Windows, macOS, or Linux
- **Python 3.11+** (developed on 3.12)
- Optional: Docker Desktop, [Ollama](https://ollama.com), an Anthropic or OpenAI API key

### 2.2 Install (first time)

From the project root (`AegisTrap`):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
copy .env.example .env
```

On macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
```

You do **not** need an LLM key to run the honeypot, the dashboard, the tests, or the evaluation harness.

### 2.3 Start the honeypot

Always use the package entrypoint (not a raw `uvicorn` command). Uvicorn would inject `Server: uvicorn`, which fingerprints the runtime as Python/ASGI. The entrypoint disables that header so the decoy owns the banner (`nginx` by default).

```powershell
python -m aegistrap --host 127.0.0.1 --port 8000
```

Equivalent:

```powershell
python -m aegistrap serve --host 127.0.0.1 --port 8000
```

| URL | Purpose |
| --- | --- |
| http://127.0.0.1:8000/api/v1/health | Decoy health |
| http://127.0.0.1:8000/docs | Swagger UI (instrumented as reconnaissance) |
| http://127.0.0.1:8000/openapi.json | OpenAPI document |
| http://127.0.0.1:8000/graphql | GraphQL |
| http://127.0.0.1:8000/dashboard | Operator console |

Bind **127.0.0.1** on a workstation. Bind `0.0.0.0` only on an isolated lab VM you control.

### 2.4 Log in to the fake bank

Every session gets its **own** generated world. Credentials in `data/synthetic/world_fintech.json` are for that fixture file, not for a live session.

Against a running decoy:

1. Hit `/api/v1/health` once (creates a session + world).
2. Read users from `data/aegistrap.sqlite3` (table `world_objects`, collection `users`) or from the dashboard after you enable a debug dump.
3. `POST /api/v1/auth/login` with that session's `email` and `password_plaintext`.
4. Send `Authorization: Bearer <access_token>` on subsequent calls.

Easier path for demos: replay the benign fixture (it substitutes a fixture email; live login still needs that session's world). To force one session from one client, send:

```http
X-AegisTrap-Session: my-demo
```

Sessions are otherwise keyed on `SHA-256(source_ip | user-agent)`.

Worked live example:

```powershell
# Health + OpenAPI (creates a session)
curl http://127.0.0.1:8000/api/v1/health
curl http://127.0.0.1:8000/openapi.json

# Login — replace with credentials from THIS session's world
curl -X POST http://127.0.0.1:8000/api/v1/auth/login `
  -H "Content-Type: application/json" `
  -d '{"email":"a.alrashid.1@example.com","password":"admin123"}'
```

If login returns `unknown_user`, the world you are talking to is not the fixture world. That is expected: live worlds are generated from the live session id.

### 2.5 Watch the dashboard

Open http://127.0.0.1:8000/dashboard

- Overview: session counts, persona mix, LLM/provider stats
- Sessions: click through to the transcript, signals, weaknesses
- Reports: generated Markdown/YAML
- Policies: which seeded flaws each persona can reach

If you set `AEGISTRAP_DASHBOARD_TOKEN`, pass it as `?token=` or header `X-Dashboard-Token`. A missing token looks like a 404 so the dashboard does not advertise itself to scanners.

Force a report from the UI, or:

```powershell
curl -X POST http://127.0.0.1:8000/dashboard/api/sessions/<SESSION_ID>/report
curl -X POST http://127.0.0.1:8000/dashboard/api/sweep
```

Reports are also written to `reports/` as `{timestamp}_{session8}_{severity}.md` and `.yaml` when a session goes idle (`AEGISTRAP_SESSION_IDLE_SECONDS`, default 300s).

### 2.6 Replay synthetic attacker traffic

With the server running:

```powershell
$env:PYTHONPATH = "."
python scripts/replay_synthetic.py --base http://127.0.0.1:8000
python scripts/replay_synthetic.py --persona attacker
```

This sends the HTTP scripts in `data/synthetic/http/` with `X-AegisTrap-Session: replay-<persona>` so the two classes do not collapse into one session. Then refresh `/dashboard`.

### 2.7 Run the test suite

```powershell
pytest
```

Async decoy tests use `pytest-asyncio` (`asyncio_mode = auto`). Each test gets its own SQLite file.

### 2.8 Run the Section 9 evaluation

```powershell
python -m aegistrap eval
python -m aegistrap eval --per-persona 40 --live-per-persona 2 --output artifacts/eval
python -m aegistrap eval --train-ml
```

Writes `artifacts/eval/results.json` and `results.md`: profiling accuracy, auto-report F1, ledger consistency (GET → transfer → GET), latency p50/p95.

### 2.9 Train the optional ML profiler

Synthetic (binary labels, 300 sessions per class):

```powershell
python -m aegistrap train-profiler --per-persona 300 --output data/profiler_model.joblib
```

Public corpus — HTTP Dataset CSIC 2010, labelled only as normal vs anomalous, which maps onto `benign` / `attacker`:

```powershell
python -m aegistrap train-profiler --csic-dir path\to\csic2010 --output data/profiler_model.joblib
```

Put `normalTrafficTraining.txt`, `normalTrafficTest.txt`, and `anomalousTrafficTest.txt` in that folder. The command prints holdout accuracy, per-class precision/recall/F1, and the top features — those numbers go in the paper. Mix generators on top of CSIC with `--include-synthetic` only if you want that ablation; the paper result should be CSIC-only.

Then set `AEGISTRAP_PROFILER_MODE=ml` (or `hybrid`) in `.env`, or pass `profiler_mode=` when constructing the app (see [§8.4](#84-optional-ml-arm-random-forest)). Heuristics remain the default.

### 2.10 Generate a report for a stored session

```powershell
python -m aegistrap report <session-id>
```

### 2.11 Enable a hosted or local LLM

Edit `.env`:

```env
AEGISTRAP_LLM_PROVIDER=anthropic
AEGISTRAP_ANTHROPIC_API_KEY=sk-ant-...
AEGISTRAP_ANTHROPIC_MODEL=claude-sonnet-4-20250514
```

or

```env
AEGISTRAP_LLM_PROVIDER=openai
AEGISTRAP_OPENAI_API_KEY=sk-...
AEGISTRAP_OPENAI_MODEL=gpt-4o-mini
```

or local open-weight (recommended for any deployment that sees real attacker traffic):

```env
AEGISTRAP_LLM_PROVIDER=ollama
AEGISTRAP_OLLAMA_BASE_URL=http://localhost:11434
AEGISTRAP_OLLAMA_MODEL=llama3.1:8b
```

Use a stronger model for reports only:

```env
AEGISTRAP_REPORTER_PROVIDER=anthropic
```

Restart the process after changing `.env`.

### 2.12 Docker

```powershell
docker compose up --build
```

Publishes **127.0.0.1:8000** only. Data lives in volumes `aegistrap-data` and `aegistrap-reports`.

### 2.13 Regenerate synthetic fixtures

```powershell
$env:PYTHONPATH = "."
python scripts/export_synthetic_fixtures.py
```

Seed is fixed (`20260831`), so the worlds and labelled sessions are reproducible.

---

## 3. Repository layout

```text
AegisTrap/
  aegistrap/                 Application package
    decoy/                   REST, GraphQL, fake world, policy, auth, canaries
    profiler/                Features, heuristic rules, ML, synthetic generators
    llm/                     Providers, prompts, cache, state grounding
    intel/                   ATT&CK/OWASP/CWE catalogue, tagger, reporter
    eval/                    Section 9 harness
    static/dashboard.html    Operator UI
    store.py                 SQLite session + world store
    main.py                  FastAPI app factory
    dashboard.py             Operator API (not on the decoy pipeline)
    evasion.py               Banner / latency mutation
    config.py                AEGISTRAP_* settings
  data/synthetic/            Committed labelled fixtures (this doc, §15)
  data/aegistrap.sqlite3     Runtime capture DB (gitignored)
  reports/                   Generated incident reports (gitignored)
  tests/                     Pytest suite
  scripts/                   Fixture export + HTTP replay
  TECHNICAL.md               This file
  README.md                  Short start guide
```

---

## 4. Technology stack

| Layer | Choice | Why |
| --- | --- | --- |
| Language | Python 3.11+ | Matches the synopsis; FastAPI/Pydantic ecosystem |
| API framework | FastAPI 0.141 + Starlette + Uvicorn | Auto OpenAPI, async, dependency injection for per-request decoy context |
| Validation | Pydantic v2 + pydantic-settings | `.env` with `AEGISTRAP_` prefix |
| Templates | Jinja2 | Only used if needed; dashboard is a static HTML file |
| HTTP client | httpx | LLM providers called over raw HTTP — no vendor SDKs |
| State store | SQLite3 (stdlib) | Synopsis scope; single-file VM deploy; serialized with a re-entrant lock |
| Config serialisation | PyYAML | Incident reports as YAML |
| Heuristic profiler | Pure Python rules + temperature softmax | Explainable; every fired rule is a dashboard signal |
| ML profiler (optional) | scikit-learn `RandomForestClassifier` + NumPy | Section 9 comparison arm, not the default |
| Model persistence | joblib | `data/profiler_model.joblib` |
| Tests | pytest + pytest-asyncio | Isolated tmp SQLite per test |
| Lint | Ruff | E/F/I/UP/B/SIM |
| Dashboard | Single-page HTML + `fetch` | No React build step; FastAPI serves it |
| Containers | Python 3.12-slim + Compose | Isolated lab deploy |
| LLMs (optional) | Anthropic Messages, OpenAI Chat Completions, Ollama `/api/chat` | Hosted for prototype quality; local for deployment |

Intentionally **not** used:

- Graphene / Strawberry / graphql-core — library error text would fingerprint the stack. GraphQL is a tolerant hand-rolled parser.
- Vendor LLM SDKs — one httpx path for Claude, GPT, and Llama.
- Redis — SQLite is enough for the minor-project scope.
- Fine-tuning — in-context learning and chain-of-thought only (synopsis §6).

---

## 5. End-to-end architecture

```text
                     +------------------+
  attacker HTTP  --> | FastAPI decoy    |
                     +--------+---------+
                              |
              1. strip control headers (X-AegisTrap-*)
              2. session key = IP+UA or explicit header
              3. seed fake world if new session
              4. profile(history + this request) -> persona + policy
              5. verify JWT against this session's HMAC key
              6. handler reads/writes SQLite (authoritative payload)
              7. ResponseEngine: template or LLM, then grounding
              8. latency floor + banner headers
              9. persist event (path, body, weaknesses, tokens)
                              |
                              v
                     SQLite  (sessions, events, world_objects, reports)
                              |
              idle sweeper ---+--> ThreatIntelReporter --> reports/*.md, *.yaml
                              +--> /dashboard (bypasses decoy pipeline)
```

**Authoritative-first rule.** The handler decides authorization, balances, and error codes. The LLM only dresses the JSON. If the provider is down, times out, or is `offline`, the attacker still sees a consistent API.

Control headers (stripped before profiling so the eval harness cannot cheat):

| Header | Purpose |
| --- | --- |
| `X-AegisTrap-Session` | Force a session key from one host |
| `X-AegisTrap-Gt-Persona` | Ground-truth persona for evaluation |
| `X-AegisTrap-Gt-Techniques` | Comma-separated ATT&CK IDs |
| `X-AegisTrap-Experiment` | Tag (e.g. `section9`) |

---

## 6. Decoy API and fake world

Emulated product: **Northwind Capital API** v2.4.1 (fintech) or **Northwind Shop** (ecommerce). Set `AEGISTRAP_PERSONA`.

World generation (`aegistrap/decoy/world.py`) is deterministic from `SHA-256(session_id)`. Different attackers see different banks; the same session always sees the same one, including across process restart.

All PII is synthetic (synopsis §10):

| Field | Guarantee |
| --- | --- |
| Email | `*.example.com` / `*.example.net` / `*.invalid` (RFC 2606) |
| Phone | `+1-555-01xx` (fictional) |
| IBAN | Starts with `XX` (not an assigned country code) |
| PAN | `411111…` test range, masked in public views |

Emails include a numeric suffix so logins cannot hit the wrong row when first-initial + surname collides.

`INTERNAL_FIELDS` (password hashes, `ledger_shard`, `pan_full`, `cvv`, API key secrets, …) exist in the store so the **excessive data exposure** weakness has something consistent to leak. Public serialisation drops them unless the policy and a `fields=` / GraphQL selection ask for them.

Seeded weaknesses (gated by persona rank) include IDOR on accounts, user enumeration at login, JWT `alg=none`, missing lockout, GraphQL introspection and depth abuse, mass assignment on `PATCH /users/me` and `updateProfile`, CORS origin reflection, verbose SQL errors, path traversal on export, SSRF-shaped webhook URLs, debug/config dumps, honey credentials, and an undocumented `/api/v0` shadow router. None of these are reachable at rank 0 (`benign`).

Fake JWTs are structurally real (HS256, `kid`, `iss`, `aud`) but signed with a **per-session** key, so they authenticate nothing outside that fake world. When policy unlocks `JWT_ALG_NONE`, unsigned tokens are accepted — a classic library-misconfiguration bait (CWE-347).

---

## 7. Session state store

SQLite schema (see `aegistrap/store.py`):

- `sessions` — persona, confidence, scores, signals, LLM token totals, consistency violation count, optional ground-truth columns for eval
- `events` — one row per request (method, path, query, headers, body, status, generator, weaknesses)
- `world_objects` — generic `(collection, object_id, data JSON)` so fintech and shop share one store
- `world_counters` — monotonic IDs for transfers / new accounts
- `reports` — generated documents

Writes are serialized with a re-entrant lock. SQLite is not the bottleneck relative to LLM calls.

Idle sessions are closed by `SessionSweeper` (default every 60s; idle gap 300s), then auto-reported if enabled.

---

## 8. Attacker profiling

Implemented in `aegistrap/profiler/`. Default mode: **heuristic**. Optional modes: `ml`, `hybrid`.

The profiler runs **before** the handler, on the last 60 events plus the in-flight request, so this request can change the surface it is answered with.

### 8.1 Feature extraction

Four groups named in synopsis §6, plus response-reactivity:

| Group | Examples |
| --- | --- |
| Timing | `requests_per_second`, mean inter-arrival, **coefficient of variation** of intervals (low CV ⇒ machine-regular) |
| Header fingerprint | User-Agent class, browser-header score (`sec-fetch-*`, `accept-language`, …), header-count, UA changes |
| Payload complexity | Family set (sqli, xss, ssrf, cmdi, traversal, nosqli), max/mean **sophistication 1–4**, encoding layers |
| Tool signatures | Token match on UA: sqlmap, ffuf, nuclei, burp, langchain, … |
| Reactivity | Reuse of tokens that only appeared in earlier **responses** (IDs, `ledger_shard`, …). Scanners almost never do this; humans and agents do. |
| GraphQL | Request count, introspection, max `{` depth |
| Canary | Whether the session echoed `AEGIS-VERIFY-…` or prompt-injection bait |

Sophistication ordinal (payload signatures):

1. Cheat-sheet (`' OR 1=1--`)
2. Textbook but correct
3. Target-adapted / evasion-aware
4. Blind / inferential / chained

The numeric vector for the ML arm is 23 continuous fields + 5 one-hot client classes + 3 booleans (introspection, canary echo, prompt-injection echo) = **31 features**. Order is fixed in `SessionFeatures.VECTOR_FIELDS`.

### 8.2 Client classification

`classify_client(user_agent, header_names)`:

- Offensive-tool tokens → `scanner`
- `curl` / `python-requests` / `Go-http-client` → `library`
- `Mozilla/5.0` **and** browser headers → `browser`
- Browser UA with no browser headers → not believed (scripted lie)

### 8.3 Heuristic classifier (default)

Weighted expert rules (`aegistrap/profiler/heuristic.py`). Each rule is `(persona, weight, human-readable label, predicate)`.

Positive weights vote for a class; negative weights veto (e.g. a sqlmap UA strongly vetoes “benign”).

**Scoring**

1. Sum weights of rules that fire, per class.
2. Clamp negatives to 0 (actively contradicted personas do not compete).
3. Temperature **softmax** with \(T = 1.25\):

   \[
   p_i = \frac{e^{(s_i - s_{\max})/T}}{\sum_j e^{(s_j - s_{\max})/T}}
   \]

4. Evidence ramp so one request cannot open the deep surface:

   \[
   \text{confidence} = p_{\text{top}} \cdot \min(1,\; 0.45 + 0.11 \cdot n_{\text{requests}})
   \]

5. Emit `unknown` unless all of:
   - raw score of the winner \(> 0\)
   - confidence \(\ge 0.30\) (`MIN_CONFIDENCE`)
   - gap to runner-up \(\ge 0.06\) (`MIN_MARGIN`)

Fired rule labels are stored on the session and shown on the dashboard. That is why heuristics are the default: a misclassification is explainable.

On the committed 24-session fixture export, heuristic labels agreed with generator ground truth on **24/24 (1.0)**. Generators are noisy on purpose; a larger sample can still disagree.

### 8.4 Optional ML arm (Random Forest)

`aegistrap/profiler/ml.py`

| Hyperparameter | Value |
| --- | --- |
| Algorithm | `sklearn.ensemble.RandomForestClassifier` |
| Trees | 300 |
| `min_samples_leaf` | 2 |
| `class_weight` | `balanced` |
| Split | 75/25, stratified, `random_state=20260831` |
| Features | `SessionFeatures.to_vector()` (31-d) |
| Labels | `benign` / `attacker` from **synthetic generators or CSIC 2010**, not from heuristic decisions |

Training on generator labels (the behavioural definition) rather than heuristic outputs means the forest can disagree with the rules. That disagreement is the point of the Section 9 “rule-based baseline vs ML” comparison.

If scikit-learn or `data/profiler_model.joblib` is missing, the service logs a warning and stays on heuristics.

### 8.5 Hybrid mode

Equal blend of the two probability distributions, then argmax. If the blended winner is \(< 0.3\), emit `unknown`.

Neither classifier is allowed to override the other: heuristics encode domain knowledge the forest cannot see; the forest catches feature combinations no single rule covers.

### 8.6 Public corpora (CSIC 2010)

`aegistrap/profiler/public_data.py` turns HTTP Dataset CSIC 2010 dumps into the same `(class, events)` pairs the synthetic generators emit.

| Dataset field | AegisTrap class |
| --- | --- |
| normal / valid | `benign` |
| anomalous / attack | `attacker` |

Requests are grouped by `JSESSIONID`, or into windows of 10 if the cookie is missing. Feature extraction is unchanged (31-d). Public HTTP datasets do not label skill tiers, so those classes are not part of the model.

Download the CSIC 2010 files from the original CSIC / ITEFI distribution (search for “HTTP Dataset CSIC 2010”). This repo does not vendor the corpus.

---

## 9. Deception policy

`aegistrap/decoy/policy.py` maps class → `DeceptionPolicy`.

| Class | Errors | IDOR leak p | LLM? | Notes |
| --- | --- | --- | --- | --- |
| Benign | terse | 0 | no | Ordinary API, no bait |
| Unknown | standard | 0.15 | yes | Stay plausible |
| Attacker | debug | 0.80 | yes, high | Deep surface, honey creds |

`AEGISTRAP_ADAPTIVE_DECEPTION=false` uses a fixed mid-tier `BASELINE_POLICY` (the ablation arm).

If confidence \(< 0.35\), policy pulls back to `unknown` rather than opening the attack surface on a weak guess.

Probabilistic deception (IDOR coin-flips) is **seeded on `(session_id, object_id)`**. Retrying `GET /accounts/1002` always yields the same leak-or-403. A flaw that appears and disappears is itself a honeypot tell.

---

## 10. LLM response engine

`aegistrap/llm/`

### 10.1 Providers

| Name | Transport | Default model | `generative` |
| --- | --- | --- | --- |
| `offline` | none | `deterministic-template` | false |
| `anthropic` | `POST /v1/messages` | `claude-sonnet-4-20250514` | true |
| `openai` | `POST /v1/chat/completions` | `gpt-4o-mini` | true |
| `ollama` | `POST /api/chat` | `llama3.1:8b` | true |

No fine-tuning. Prompts use:

- **In-context learning** — few-shot examples of “authoritative payload → enriched body” that teach numeric preservation.
- **Chain-of-thought** — a `_reasoning` field inside the JSON envelope, stripped before the attacker sees anything. Keeping CoT inside JSON avoids a second parse.

Default sampling: temperature **0.4**, max output tokens **1200**, timeout **12s**.

### 10.2 Grounding (the consistency algorithm)

`reconcile(grounded, generated)` walks both trees:

- Authoritative keys/values always win.
- The model may **add** sibling fields (`request_id`, `_links`, prose).
- The model may **not** change numbers, drop keys, or replace an object with a different type.
- Narrative keys (`message`, `hint`, `trace`, …) are presentation; grounded values still win if both supply one.

Every repair is a `consistency_violation` counted on the session — the Section 9 consistency metric, measured rather than estimated.

### 10.3 Latency mitigations (synopsis §13)

- **Do not LLM** scanners, benign clients, health, or 404 fanout.
- **TTL cache** (900s, 2048 entries), keyed on session + method + path + query + body + persona + verbosity + **authoritative payload hash**. If state moved, the key changes; a cache hit cannot serve a stale balance.
- **Circuit breaker**: 3 consecutive provider failures → 60s suspension, serve grounded templates.
- **Latency floor** (default 40ms + 0–90ms jitter) so template replies are not 0.4ms.

### 10.4 Canaries for response-reading clients

Verbose/debug responses may embed:

```text
X-Diagnostic-Token: AEGIS-VERIFY-<10 hex>
```

Only a client that **read the previous body** would send that header back. Signature scanners have no reason to. Echoing it votes for `attacker` and vetoes `benign`.

---

## 11. Threat-intelligence auto-reporter

**Rules first, model second.** `intel.tagger` extracts evidence deterministically from paths, payload signatures, and weaknesses the decoy actually exposed. The LLM (if any) writes prose and severity over that evidence. A model failure costs narrative, never tags.

Closed vocabulary: proposed ATT&CK / OWASP IDs not in `intel/catalogue.py` are dropped and counted. Invented technique IDs are worse than missing tags.

Report contents:

- Title, summary, severity, confidence
- Attacker persona + signals
- Attack timeline by ATT&CK tactic
- MITRE ATT&CK techniques with URLs
- OWASP API Security Top 10 **2023**
- OWASP Top 10 **2025** (projected from 2021 letter-IDs)
- CWE list
- Weaknesses exercised vs merely attempted
- Recommended defender actions (from the catalogue `defender_note`s)
- Evidence table (seq, request, status, observation)
- Ethics footer: all data synthetic

Offline reporter output is already a complete, framework-mapped report. That is the auto-reporting contribution even without an API key.

---

## 12. Dashboard

`/dashboard` does **not** go through the decoy pipeline. Refreshing it never creates a honeypot session.

JSON API (same origin):

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/dashboard/api/overview` | Counts, engine stats, persona mix |
| GET | `/dashboard/api/sessions` | Session list |
| GET | `/dashboard/api/sessions/{id}` | Transcript + analysis |
| POST | `/dashboard/api/sessions/{id}/report` | Generate report now |
| GET | `/dashboard/api/reports` | Report index |
| GET | `/dashboard/api/policies` | Persona → unlocked weaknesses |
| POST | `/dashboard/api/sweep` | Close idle sessions / write reports |

---

## 13. Fingerprint evasion

Stretch goal, **off** by default (`AEGISTRAP_FINGERPRINT_EVASION=false`).

When on, `FingerprintMutator` picks a banner profile (nginx, envoy, gunicorn, Apache, cloudflare, …) **stable within a session**, rotating across sessions/epochs. A `Server` header that changes between two requests from the same client is more obviously fake than a static one.

Uvicorn’s own `Server` header is always disabled at process start.

---

## 14. Evaluation harness

`python -m aegistrap eval` implements synopsis §9 as far as a prototype can without a human red-team:

| Metric | How |
| --- | --- |
| Profiling accuracy | Precision/recall/F1 vs synthetic generator labels (heuristic, optional RF) |
| Auto-report quality | ATT&CK F1 vs **request-only** ground truth (`eval.labels`), not vs the decoy’s own weakness log |
| Consistency | Authenticated GET → transfer → GET; HTTP body must match SQLite |
| Latency / cost | p50/p95 of live TestClient path; token counters when a generative provider is on |
| Adaptive surface | Weaknesses actually unlocked per session class |
| Deception fidelity | **Not automated** — blind mix of real vs honeypot responses is a human study |

---

## 15. Synthetic test data

Committed under `data/synthetic/` (runtime `data/*.sqlite3` stays gitignored).

Regenerate: `python scripts/export_synthetic_fixtures.py` (seed `20260831`).

| File | What it is |
| --- | --- |
| `manifest.json` | Index, seed, heuristic agreement on this export |
| `world_fintech.json` | Full Northwind Capital world: users, accounts, transactions, cards, API keys, config, **test_credentials** |
| `world_ecommerce.json` | Shop users, products, orders |
| `sessions.jsonl` | 24 labelled sessions (12 per class): features, heuristic verdict, truncated event transcript |
| `feature_matrix.csv` | Same 24 rows as a 31-d numeric matrix for notebooks / RF experiments |
| `payload_catalogue.json` | Signature-scanner test vectors (benign + known families) |
| `http/<class>.json` | HTTP replay scripts (`benign.json`, `attacker.json`) |

Example fixture login (valid **inside `world_fintech.json`**, not necessarily on a live random session):

```text
email:    a.alrashid.1@example.com
password: admin123
role:     customer
```

These passwords exist only in synthetic honeypot state. They authenticate to nothing real.

Load sessions in Python:

```python
import json
from pathlib import Path

for line in Path("data/synthetic/sessions.jsonl").read_text().splitlines():
    row = json.loads(line)
    print(row["id"], row["ground_truth_persona"], row["heuristic_persona"])
```

Train the RF on the CSV (or use `python -m aegistrap train-profiler`, which generates a larger set on the fly).

---

## 16. HTTP and GraphQL surface

Prefix `/api/v1` unless noted. Auth: `Authorization: Bearer <jwt>` on protected routes.

### Fintech REST

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/v1/health` | Always public |
| POST | `/api/v1/auth/login` | `{email, password}` |
| GET | `/api/v1/users/me` | Current principal |
| PATCH | `/api/v1/users/me` | Mass-assignment bait when unlocked |
| GET | `/api/v1/users/{id}` | |
| GET | `/api/v1/accounts` | Pagination `limit`/`offset` |
| GET | `/api/v1/accounts/{id}` | IDOR-gated |
| GET | `/api/v1/accounts/{id}/transactions` | |
| GET | `/api/v1/transactions` | |
| GET | `/api/v1/accounts/{id}/cards` | |
| POST | `/api/v1/transfers` | `{from_account, to_account, amount_minor}` — **mutates the ledger** |
| GET | `/api/v1/search` | |
| GET | `/api/v1/reports/export` | Traversal bait on `file=` |
| POST | `/api/v1/webhooks` | SSRF-shaped URL bait |
| GET | `/api/v1/debug` | Hidden diagnostics |
| GET | `/api/v1/admin/*` | Users, config, api-keys, audit — BFLA bait |
| GET | `/api/v0/accounts` | Undocumented shadow inventory |

### Ecommerce REST (when `AEGISTRAP_PERSONA=ecommerce`)

`/api/v1/products`, `/api/v1/products/{id}`, `/api/v1/orders`, `/api/v1/orders/{id}` plus common auth/health/admin.

### GraphQL (`POST` or `GET /graphql`)

Hand-rolled parser (no graphql-core). Typical queries:

```graphql
{ accounts(limit: 5) { id balanceMinor owner { id email } } }
{ me { id role } }
mutation { updateProfile(role: "admin") { id role } }
{ __schema { types { name } } }
```

Introspection, depth, aliases, and internal fields are policy-gated. Errors use a GraphQL envelope with HTTP 200 (spec-like), never a FastAPI `{"detail":...}` body.

Meta: `GET /`, `/docs`, `/openapi.json`, `/graphql/schema`, `/.well-known/security.txt`.

Unknown paths: decoy JSON 404 (or HTML if `Accept: text/html`). Wrong method on a known path: 405 + `Allow`.

---

## 17. Configuration reference

All variables use prefix `AEGISTRAP_`. See `.env.example`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `LLM_PROVIDER` | `offline` | `offline` \| `anthropic` \| `openai` \| `ollama` |
| `ANTHROPIC_API_KEY` / `MODEL` | (empty) / `claude-sonnet-4-20250514` | Claude |
| `OPENAI_API_KEY` / `MODEL` | (empty) / `gpt-4o-mini` | GPT |
| `OLLAMA_BASE_URL` / `MODEL` | `http://localhost:11434` / `llama3.1:8b` | Local Llama/Mistral |
| `REPORTER_PROVIDER` | (reuse response engine) | Separate model for reports |
| `LLM_TIMEOUT_SECONDS` | `12` | Provider timeout |
| `LLM_MAX_OUTPUT_TOKENS` | `1200` | |
| `LLM_TEMPERATURE` | `0.4` | |
| `LLM_CACHE_ENABLED` | `true` | |
| `LLM_CACHE_TTL_SECONDS` | `900` | |
| `PERSONA` | `fintech` | `fintech` \| `ecommerce` |
| `ADAPTIVE_DECEPTION` | `true` | Persona-gated surface |
| `FINGERPRINT_EVASION` | `false` | Banner mutation |
| `LATENCY_FLOOR_MS` | `40` | |
| `LATENCY_JITTER_MS` | `90` | |
| `DB_PATH` | `data/aegistrap.sqlite3` | |
| `REPORT_DIR` | `reports` | |
| `SESSION_IDLE_SECONDS` | `300` | Close + auto-report |
| `AUTO_REPORT_ENABLED` | `true` | |
| `REPORT_SWEEP_SECONDS` | `60` | Sweeper period |
| `ANONYMISE_IPS` | `false` | Truncate to /24 or /48 |
| `LOG_RETENTION_DAYS` | `90` | Policy value (documented) |
| `MAX_BODY_CAPTURE_BYTES` | `8192` | |
| `DASHBOARD_ENABLED` | `true` | |
| `DASHBOARD_TOKEN` | empty | Shared secret |
| `SERVICE_NAME` | `Northwind Capital API` | Banner |
| `SERVICE_VERSION` | `2.4.1` | |
| `SERVER_BANNER` | `nginx` | When evasion is off |
| `LOG_LEVEL` | `INFO` | |

---

## 18. Tests, Docker, ethics

```powershell
pytest                          # full suite
pytest tests/test_profiler.py   # classifier
pytest tests/test_eval.py       # Section 9 harness smoke
docker compose up --build       # 127.0.0.1:8000
```

Ethics (synopsis §10):

- Isolated infrastructure only. Compose binds loopback on the host.
- No real customer data. Worlds use reserved ranges.
- A honeypot logs attacks that would have happened; it must not solicit them.
- If you expose it publicly: set a dashboard token, consider `ANONYMISE_IPS=true`, and follow institutional retention policy.

---

## 19. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `Server: uvicorn` | Started with raw uvicorn | Use `python -m aegistrap` |
| Login `unknown_user` | Credentials from a different session’s world | Login with users from **this** session’s SQLite row |
| Login `invalid_password` | Email collision (fixed) or wrong world | Use `password_plaintext` from the same user object |
| Dashboard 404 | `DASHBOARD_TOKEN` set | Pass `?token=` or `X-Dashboard-Token` |
| Slow replies | Latency floor + LLM timeout | `AEGISTRAP_LATENCY_FLOOR_MS=0` in tests; scanners never call the LLM |
| Model latency spikes | Provider down | Circuit breaker serves templates after 3 failures |
| No reports | Session still active | Wait 300s idle, or POST `/dashboard/api/sweep`, or POST `.../report` |
| Profiler stuck on `unknown` | Too few requests / mixed signals | Send more traffic; check `persona_signals` on the session |
| `ModuleNotFoundError: aegistrap` | Running a script without PYTHONPATH | `$env:PYTHONPATH = "."` or `pip install -e .` |

---

## Academic context

Minor project, Department of Electronics and Communication Engineering, MAIT. Arnav Chopra and Anshika Chaubey, guided by Lalit Agarwal.

Related work the design is positioned against: Shellm, HoneyLLM, LLM Agent Honeypot, LDAP LLM honeypot, Honeyval — all SSH/shell/generic HTTP, none combining stateful business-API deception, benign-vs-attacker adaptive surface, and ATT&CK-mapped auto-reporting.
