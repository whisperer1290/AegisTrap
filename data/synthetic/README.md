# Synthetic test fixtures

Labelled data for profiler tests, notebooks, and live HTTP replay. All identities are fake (RFC 2606 emails, `555-01xx` phones, `XX` IBANs).

Regenerate (fixed seed `20260831`):

```powershell
$env:PYTHONPATH = "."
python scripts/export_synthetic_fixtures.py
```

Replay against a running decoy:

```powershell
python scripts/replay_synthetic.py --base http://127.0.0.1:8000
```

| File | Contents |
| --- | --- |
| `manifest.json` | Seed, file index, heuristic accuracy on this export |
| `world_fintech.json` | Northwind Capital fake world + `test_credentials` |
| `world_ecommerce.json` | Shop fake world + `test_credentials` |
| `sessions.jsonl` | 24 sessions (12 per class) with features and transcripts |
| `feature_matrix.csv` | Numeric 31-d vectors for the Random Forest arm |
| `payload_catalogue.json` | Signature-scanner test vectors |
| `http/*.json` | HTTP replay scripts for `benign` and `attacker` |

See [TECHNICAL.md](../../TECHNICAL.md) §15 for how these files are produced and consumed.

Fixture login example (only valid inside `world_fintech.json`, not on an arbitrary live session):

```text
a.alrashid.1@example.com / admin123
```
