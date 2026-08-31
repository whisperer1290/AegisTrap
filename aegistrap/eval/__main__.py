"""``python -m aegistrap.eval`` — convenience wrapper around the eval subcommand."""

from __future__ import annotations

import sys

from aegistrap.__main__ import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(["eval", *sys.argv[1:]]))
