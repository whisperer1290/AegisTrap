"""CLI: ``python -m aegistrap`` (serve, eval, train-profiler, report)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import uvicorn

from aegistrap.config import REPO_ROOT, get_settings

_COMMANDS = ("serve", "eval", "train-profiler", "report")


def build_serve_parser(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: %(default)s)")
    parser.add_argument("--port", type=int, default=8000, help="bind port (default: %(default)s)")
    parser.add_argument(
        "--reload", action="store_true", help="reload on source changes (development only)"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in _COMMANDS:
        command, rest = argv[0], argv[1:]
    else:
        command, rest = "serve", argv

    if command == "serve":
        return _serve(rest)
    if command == "eval":
        return _eval(rest)
    if command == "train-profiler":
        return _train(rest)
    if command == "report":
        return _report(rest)
    raise SystemExit(f"unknown command {command!r}")


def _serve(argv: list[str]) -> int:
    parser = build_serve_parser(
        argparse.ArgumentParser(
            prog="python -m aegistrap",
            description="Run the AegisTrap adaptive API honeypot.",
        )
    )
    args = parser.parse_args(argv)
    settings = get_settings()
    settings.ensure_directories()

    uvicorn.run(
        "aegistrap.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        server_header=False,
        date_header=True,
        access_log=False,
        log_level=settings.log_level.lower(),
    )
    return 0


def _eval(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aegistrap eval",
        description="Run the Section 9 evaluation harness (offline by default).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "artifacts" / "eval",
        help="directory for results.json / results.md",
    )
    parser.add_argument("--per-persona", type=int, default=40)
    parser.add_argument("--live-per-persona", type=int, default=2)
    parser.add_argument("--seed", type=int, default=20260831)
    parser.add_argument(
        "--train-ml",
        action="store_true",
        help="also train and score the optional scikit-learn comparison arm",
    )
    args = parser.parse_args(argv)

    from aegistrap.eval.harness import run_evaluation

    result = run_evaluation(
        output_dir=args.output,
        per_persona=args.per_persona,
        live_per_persona=args.live_per_persona,
        seed=args.seed,
        train_ml=args.train_ml,
    )
    print(
        json.dumps(
            {
                "heuristic_accuracy": result.profiling["heuristic"]["accuracy"],
                "report_mean_f1": result.reporting["mean_f1"],
                "consistency_ok": result.consistency.get("ok"),
                "written": str(args.output / "results.md"),
            },
            indent=2,
        )
    )
    return 0 if result.consistency.get("ok") else 1


def _train(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aegistrap train-profiler",
        description="Train the optional ML profiler on synthetic labelled sessions.",
    )
    parser.add_argument("--per-persona", type=int, default=300)
    parser.add_argument("--seed", type=int, default=20260831)
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "data" / "profiler_model.joblib",
    )
    args = parser.parse_args(argv)

    from aegistrap.profiler.ml import MLProfiler

    model, metrics = MLProfiler.train(per_persona=args.per_persona, seed=args.seed)
    path = model.save(args.output)
    print(json.dumps({"saved": str(path), "samples": metrics["samples"]}, indent=2))
    return 0


def _report(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aegistrap report",
        description="Generate a threat-intel report for a stored session id.",
    )
    parser.add_argument("session_id")
    args = parser.parse_args(argv)

    import asyncio

    from aegistrap.app_state import build_runtime, shutdown_runtime

    runtime = build_runtime()
    session = runtime.store.get_session(args.session_id)
    if session is None:
        print(f"unknown session: {args.session_id}", file=sys.stderr)
        return 1
    bundle = asyncio.run(runtime.reporter.report_session(session))
    asyncio.run(shutdown_runtime(runtime))
    print(bundle.markdown_path or bundle.markdown)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
