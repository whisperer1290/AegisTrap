"""Load public HTTP corpora into AegisTrap's binary session labels.

CSIC 2010 (HTTP Dataset CSIC 2010) annotates each request as normal or
anomalous. That maps onto ``benign`` / ``attacker``. The dump has no skill-tier
labels, which is why the profiler no longer emits them.

Requests are grouped into sessions (``JSESSIONID`` when present, otherwise a
fixed-size window) so ``extract_features`` can run unchanged.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Sequence
from pathlib import Path
from urllib.parse import urlparse

from aegistrap.logging_setup import get_logger
from aegistrap.models import AttackerPersona
from aegistrap.store import Event

log = get_logger("profiler.public_data")

_REQUEST_LINE = re.compile(
    r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?\s*$",
    re.IGNORECASE,
)
_JSESSION = re.compile(r"JSESSIONID=([^;\s]+)", re.IGNORECASE)
_WINDOW = 10

_ATTACK_HINTS = ("anomal", "attack", "malicious", "odd")
_BENIGN_HINTS = ("normal", "benign", "valid")


def infer_label_from_name(path: Path) -> AttackerPersona | None:
    name = path.name.lower()
    if any(hint in name for hint in _ATTACK_HINTS):
        return AttackerPersona.ATTACKER
    if any(hint in name for hint in _BENIGN_HINTS):
        return AttackerPersona.BENIGN
    return None


def parse_csic_http_dump(text: str) -> list[dict[str, str | dict[str, str]]]:
    """Split a CSIC-style raw HTTP dump into request records."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    records: list[dict[str, str | dict[str, str]]] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        match = _REQUEST_LINE.match(line.strip())
        if not match:
            i += 1
            continue
        method, target = match.group(1).upper(), match.group(2)
        i += 1
        headers: dict[str, str] = {}
        while i < n and lines[i].strip():
            raw = lines[i]
            if ":" in raw:
                key, value = raw.split(":", 1)
                headers[key.strip().lower()] = value.strip()
            i += 1
        while i < n and not lines[i].strip():
            i += 1
        body_lines: list[str] = []
        if method in {"POST", "PUT", "PATCH"}:
            while i < n and not _REQUEST_LINE.match(lines[i].strip()):
                body_lines.append(lines[i])
                i += 1
        body = "\n".join(body_lines).strip()
        records.append({"method": method, "target": target, "headers": headers, "body": body})
    return records


def _cookie_session_key(headers: dict[str, str]) -> str | None:
    match = _JSESSION.search(headers.get("cookie", ""))
    return match.group(1) if match else None


def _records_to_events(
    records: Sequence[dict[str, str | dict[str, str]]],
    *,
    session_id: str,
    label: AttackerPersona,
) -> list[Event]:
    events: list[Event] = []
    ts = 1_700_000_000.0
    for seq, record in enumerate(records, start=1):
        target = str(record["target"])
        parsed = urlparse(target)
        path = parsed.path or target.split("?", 1)[0]
        query = parsed.query
        if "?" in target and not query and not parsed.scheme:
            _, _, rest = target.partition("?")
            query = rest
        headers = dict(record["headers"])  # type: ignore[arg-type]
        ts += 0.08
        events.append(
            Event(
                id=seq,
                session_id=session_id,
                seq=seq,
                ts=ts,
                method=str(record["method"]),
                path=path or "/",
                query_string=query,
                headers=headers,
                body=str(record["body"]),
                status_code=200,
                response="",
                generator="csic2010",
                latency_ms=12.0,
                llm_tokens=0,
                weaknesses=[],
                persona_at_time=label.value,
            )
        )
    return events


def sessions_from_records(
    records: Sequence[dict[str, str | dict[str, str]]],
    *,
    label: AttackerPersona,
    source: str = "csic",
) -> list[tuple[AttackerPersona, list[Event]]]:
    keyed: list[tuple[str, dict[str, str | dict[str, str]]]] = []
    unkeyed: list[dict[str, str | dict[str, str]]] = []
    for record in records:
        headers = dict(record["headers"])  # type: ignore[arg-type]
        key = _cookie_session_key(headers)
        if key:
            keyed.append((key, record))
        else:
            unkeyed.append(record)

    # CSIC 2010 mints a fresh JSESSIONID for every request, so cookie grouping
    # would produce one-request "sessions" and erase every session-level
    # feature. Only trust the cookie when it actually groups more than one
    # request; otherwise fall back to fixed-size windows over the whole dump.
    cookie_keys = [key for key, _ in keyed]
    if len(set(cookie_keys)) == len(cookie_keys):
        if keyed:
            log.info(
                "%s: no repeated session cookies; using %d-request windows",
                source,
                _WINDOW,
            )
        unkeyed = list(records)
        keyed = []

    grouped: dict[str, list[dict[str, str | dict[str, str]]]] = defaultdict(list)
    for key, record in keyed:
        grouped[key].append(record)

    sessions: list[tuple[AttackerPersona, list[Event]]] = []
    for key, chunk in grouped.items():
        session_id = f"{source}-{label.value}-{key[:16]}"
        events = _records_to_events(chunk, session_id=session_id, label=label)
        if events:
            sessions.append((label, events))

    for index in range(0, len(unkeyed), _WINDOW):
        chunk = unkeyed[index : index + _WINDOW]
        session_id = f"{source}-{label.value}-win{index // _WINDOW:04d}"
        events = _records_to_events(chunk, session_id=session_id, label=label)
        if events:
            sessions.append((label, events))

    return sessions


def load_csic_file(
    path: Path | str, *, label: AttackerPersona | None = None
) -> list[tuple[AttackerPersona, list[Event]]]:
    file_path = Path(path)
    resolved = label or infer_label_from_name(file_path)
    if resolved is None:
        raise ValueError(
            f"cannot infer benign/attacker label from {file_path.name}; "
            "name the file normal*.txt / anomalous*.txt or pass label="
        )
    text = file_path.read_text(encoding="latin-1")
    records = parse_csic_http_dump(text)
    return sessions_from_records(records, label=resolved, source=file_path.stem)


def load_csic_directory(path: Path | str) -> list[tuple[AttackerPersona, list[Event]]]:
    """Load every CSIC dump in a directory whose filename encodes the label."""
    directory = Path(path)
    if not directory.is_dir():
        raise FileNotFoundError(
            f"CSIC directory not found: {directory}. "
            "Download HTTP Dataset CSIC 2010 and point --csic-dir at the folder "
            "that contains normalTrafficTraining.txt and anomalousTrafficTest.txt."
        )
    files = sorted(
        p for p in directory.iterdir() if p.is_file() and p.suffix.lower() in {".txt", ".http"}
    )
    labelled = [(p, infer_label_from_name(p)) for p in files]
    usable = [(p, label) for p, label in labelled if label is not None]
    if not usable:
        names = ", ".join(p.name for p in files) or "(empty directory)"
        raise FileNotFoundError(
            "no CSIC dumps with inferable labels in "
            f"{directory} (saw {names}). Expected files such as "
            "normalTrafficTraining.txt and anomalousTrafficTest.txt."
        )

    sessions: list[tuple[AttackerPersona, list[Event]]] = []
    for file_path, label in usable:
        assert label is not None
        loaded = load_csic_file(file_path, label=label)
        log.info("loaded %s sessions from %s as %s", len(loaded), file_path.name, label.value)
        sessions.extend(loaded)

    counts = {
        AttackerPersona.BENIGN.value: sum(1 for persona, _ in sessions if persona is AttackerPersona.BENIGN),
        AttackerPersona.ATTACKER.value: sum(
            1 for persona, _ in sessions if persona is AttackerPersona.ATTACKER
        ),
    }
    if counts["benign"] == 0 or counts["attacker"] == 0:
        raise ValueError(
            f"CSIC directory {directory} must contain both normal and anomalous dumps "
            f"(got {counts})."
        )
    return sessions


def summarize_sessions(
    sessions: Iterable[tuple[AttackerPersona, list[Event]]],
) -> dict[str, int]:
    rows = list(sessions)
    return {
        "sessions": len(rows),
        "benign": sum(1 for persona, _ in rows if persona is AttackerPersona.BENIGN),
        "attacker": sum(1 for persona, _ in rows if persona is AttackerPersona.ATTACKER),
        "requests": sum(len(events) for _, events in rows),
    }
