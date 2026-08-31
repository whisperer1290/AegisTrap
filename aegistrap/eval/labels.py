"""Independent ground-truth labelling used to score auto-reports.

This is the stand-in for the "manually labelled ground truth" in Section 9.
It is intentionally simpler than ``intel.tagger``: it looks only at the
request (path, query, body) and never at what the honeypot chose to expose.
Scoring the reporter against this function measures whether the report
describes what the *attacker did*, not whether it restates the decoy's own
weakness log.
"""

from __future__ import annotations

from aegistrap.intel.catalogue import TECHNIQUES
from aegistrap.profiler.signatures import looks_like_wordlist_path, scan_payload
from aegistrap.store import Event

_FAMILY_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "sqli": ("T1190",),
    "nosqli": ("T1190",),
    "xss": ("T1059",),
    "ssrf": ("T1190",),
    "cmdi": ("T1059", "T1190"),
    "traversal": ("T1083", "T1190"),
}


def expected_techniques(events: list[Event]) -> list[str]:
    """ATT&CK IDs a human analyst would assign from the raw requests alone."""
    ids: set[str] = set()
    if events:
        ids.add("T1071.001")
    login_posts = 0
    for event in events:
        blob = f"{event.path} {event.query_string} {event.body}"
        for match in scan_payload(blob):
            ids.update(_FAMILY_TECHNIQUES.get(match.family, ()))
        path = event.path.lower()
        if looks_like_wordlist_path(event.path):
            ids.update(("T1595", "T1595.003"))
        if path.rstrip("/").endswith("/openapi.json") or path.endswith("/docs"):
            ids.add("T1592")
        if "/admin" in path:
            ids.add("T1068")
        if "/graphql" in path:
            ids.add("T1592")
        if "/accounts/" in path or path.rstrip("/").endswith("/accounts"):
            ids.add("T1087")
        if event.method.upper() == "POST" and "login" in path:
            login_posts += 1
    if login_posts >= 3:
        ids.add("T1110")
        ids.add("T1110.001")
    return [tid for tid in sorted(ids) if tid in TECHNIQUES]
