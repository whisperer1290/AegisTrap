# AegisTrap

An LLM-powered adaptive **API honeypot**. It emulates a stateful fintech (or e-commerce) REST and GraphQL backend, profiles each session as benign or attacker, changes how much of the fake vulnerability surface that session can reach, and turns the transcript into a MITRE ATT&CK / OWASP incident report.

This is a deception system for research and isolated-lab use. Every account, balance, name, and secret it serves is synthetic.

## Why this exists

Most honeypots still answer from a script. Patient attackers fingerprint them in a few requests and leave. Published LLM honeypots mostly fake SSH shells. The attack surface of modern software is REST and GraphQL, where a fake bank has to remember an account balance across fifteen requests without contradicting itself.

AegisTrap sits in that gap:

1. **Decoy business API** — OpenAPI-documented Northwind Capital (or a shop API) with seeded, policy-gated flaws (IDOR, verbose errors, GraphQL introspection, a hidden admin surface).
2. **Session state store** — SQLite holds a consistent fake world per attacker. The LLM renders state; it never invents it.
3. **Attacker profiler** — buckets a session as benign or attacker, then adapts the exposed surface.
4. **LLM response engine** — optional Claude / GPT / Ollama generation, always reconciled against the store. Offline mode is a first-class static baseline.
5. **Threat-intel auto-reporter** — on idle timeout, emits Markdown + YAML tagged with ATT&CK, OWASP API Top 10 (2023), OWASP Top 10 (2025), and CWE.

Fingerprint-evasion header mutation is implemented and off by default (synopsis stretch goal).

## Quick start

Python 3.11+. From this directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
copy .env.example .env
python -m aegistrap --host 127.0.0.1 --port 8000
```

Then:

| URL | What it is |
| --- | --- |
| http://127.0.0.1:8000/api/v1/health | Decoy health probe |
| http://127.0.0.1:8000/docs | Swagger UI for the fake bank |
| http://127.0.0.1:8000/graphql | GraphQL endpoint |
| http://127.0.0.1:8000/dashboard | Operator console (sessions, classes, reports) |

The default LLM provider is `offline`: deterministic, no API key, no outbound calls. That is also the static baseline used in evaluation.

**Full technical reference** (run every command, tech stack, classifiers, LLM methods, synthetic data): [TECHNICAL.md](TECHNICAL.md). Fixtures: [data/synthetic/](data/synthetic/).

```powershell
pytest
python -m aegistrap eval
```

## Architecture

```
attacker  -->  FastAPI decoy (REST + GraphQL)
                  |  1. resolve session (IP + User-Agent, or X-AegisTrap-Session)
                  |  2. profile session (benign / attacker)  -->  deception policy
                  |  3. handler reads/writes SQLite world (authoritative)
                  |  4. response engine dresses the payload (LLM or template)
                  |  5. latency shaping + banner
                  v
               event log
                  |
                  +--> idle sweeper --> ATT&CK / OWASP report (Markdown + YAML)
                  +--> /dashboard
```

Handlers decide *whether* a check passes. The model only decides *how the JSON looks*. Divergent fields are repaired and counted as consistency violations.

## Session classes

| Class | Surface | LLM spend |
| --- | --- | --- |
| Benign | Ordinary API, no bait | none |
| Attacker | Deep surface, schema hints, planted credentials | high |

Set `AEGISTRAP_ADAPTIVE_DECEPTION=false` for the no-profiling ablation in Section 9.

## Configuration

Copy `.env.example` to `.env`. All keys are prefixed `AEGISTRAP_`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `LLM_PROVIDER` | `offline` | `offline` / `anthropic` / `openai` / `ollama` |
| `PROFILER_MODE` | `heuristic` | `heuristic` / `ml` / `hybrid` (ML needs `train-profiler`) |
| `PERSONA` | `fintech` | `fintech` or `ecommerce` |
| `ADAPTIVE_DECEPTION` | `true` | Class-gated vulnerability surface |
| `FINGERPRINT_EVASION` | `false` | Mutate banners per session |
| `DASHBOARD_TOKEN` | empty | Shared secret for `/dashboard` (recommended if exposed) |
| `ANONYMISE_IPS` | `false` | Truncate captured source addresses |
| `SESSION_IDLE_SECONDS` | `300` | Idle gap before auto-report |

Hosted providers are for prototype quality. For a real deployment, use Ollama or `offline` so attacker payloads never leave the box.

## CLI

```text
python -m aegistrap serve --host 127.0.0.1 --port 8000
python -m aegistrap                          # same as serve
python -m aegistrap eval --output artifacts/eval
python -m aegistrap train-profiler           # synthetic benign vs attacker
python -m aegistrap train-profiler --csic-dir path\to\csic2010
python -m aegistrap report <session-id>
```

Always start with `python -m aegistrap`, not a raw `uvicorn` invocation. Uvicorn would inject a `Server: uvicorn` header that identifies the runtime; the entrypoint disables that so the decoy owns the banner.

## Evaluation (synopsis Section 9)

`python -m aegistrap eval` writes `artifacts/eval/results.md` with:

- **Profiling accuracy** — precision / recall / F1 against labelled benign vs attacker sessions
- **Auto-report F1** — ATT&CK tags vs request-only ground truth
- **Consistency** — GET → transfer → GET on the fake ledger
- **Latency** — p50 / p95 of the live decoy path

Deception fidelity (a blind mix of real API vs honeypot responses) is a human / red-team study and is not automated.

## Docker

Binds localhost only, matching the isolated-infrastructure rule in Section 10:

```powershell
docker compose up --build
```

## Ethics

- Deploy only on infrastructure you control. Never on a shared or production network.
- No real user data. Worlds are generated from reserved ranges (RFC 2606 emails, `555-01xx` phones, `XX` IBANs, test-range PANs).
- A honeypot logs attacks that would have happened anyway. It must not solicit them.
- If you put this on the public internet, set `AEGISTRAP_DASHBOARD_TOKEN`, enable IP anonymisation, and follow your institution's data-retention policy.

## Layout

```text
aegistrap/
  decoy/       REST + GraphQL handlers, fake world, policy
  profiler/    features, heuristics, optional ML, synthetic traffic
  llm/         providers, cache, state grounding
  intel/       ATT&CK / OWASP / CWE catalogue, tagger, reporter
  eval/        Section 9 harness
  static/      dashboard UI
  store.py     SQLite session + world store
tests/
```

## License / academic context

Minor project, Department of Electronics and Communication Engineering, MAIT. Submitted by Arnav Chopra and Anshika Chaubey, under the guidance of Lalit Agarwal.
