"""Replay benign/attacker HTTP fixtures against a running AegisTrap decoy."""

from __future__ import annotations

import argparse
import json
import time

import httpx

from aegistrap.config import REPO_ROOT

HTTP_DIR = REPO_ROOT / "data" / "synthetic" / "http"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replay synthetic benign/attacker traffic at a live decoy."
    )
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument(
        "--persona",
        default="all",
        choices=["all", "benign", "attacker"],
    )
    parser.add_argument("--delay-ms", type=int, default=80, help="pause between requests")
    args = parser.parse_args(argv)

    personas = (
        ["benign", "attacker"]
        if args.persona == "all"
        else [args.persona]
    )

    with httpx.Client(timeout=20.0, follow_redirects=True) as client:
        for persona in personas:
            path = HTTP_DIR / f"{persona}.json"
            bundle = json.loads(path.read_text(encoding="utf-8"))
            session_header = {
                "x-aegistrap-session": f"replay-{persona}",
                "x-aegistrap-gt-persona": persona,
            }
            print(f"\n== {persona} ({len(bundle['steps'])} steps) ==")
            for index, step in enumerate(bundle["steps"], start=1):
                headers = {**step.get("headers", {}), **session_header}
                kwargs: dict = {"headers": headers}
                if "json" in step:
                    kwargs["json"] = step["json"]
                url = args.base + step["path"]
                if step.get("query"):
                    kwargs["params"] = step["query"]
                response = client.request(step["method"], url, **kwargs)
                print(
                    f"  {index:02d} {step['method']:6} {step['path'][:60]:60} -> {response.status_code}"
                )
                time.sleep(args.delay_ms / 1000)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
