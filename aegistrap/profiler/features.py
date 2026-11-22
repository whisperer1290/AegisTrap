"""Session feature extraction for the attacker profiler.

Features fall into four groups, matching the signals named in Section 6 of the
synopsis (request timing, header fingerprint, payload complexity, tool
signatures), plus one addition:

**Response-reactivity.** We track whether a session reuses identifiers or field
names that it could only have learned by *reading* an earlier response. A
wordlist scanner never does this; a client that actually reads responses does it
constantly. It is a cheap signal for separating automated fanout from
goal-directed exploration.
"""

from __future__ import annotations

import itertools
import json
import math
import re
import statistics
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from aegistrap.decoy.canary import canary_present
from aegistrap.profiler.signatures import (
    BROWSER_HEADERS,
    ClientClass,
    classify_client,
    count_encoding_layers,
    looks_like_wordlist_path,
    scan_payload,
)
from aegistrap.store import Event

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{4,}|\d{3,}")

#: Vocabulary shared by any plausible client, so its reuse proves nothing about
#: whether the caller actually read a response.
_TOKEN_STOPLIST: frozenset[str] = frozenset(
    {
        "accounts",
        "account",
        "users",
        "user",
        "transactions",
        "transaction",
        "orders",
        "order",
        "products",
        "product",
        "error",
        "errors",
        "message",
        "detail",
        "details",
        "status",
        "code",
        "false",
        "true",
        "null",
        "limit",
        "offset",
        "page",
        "cursor",
        "total",
        "items",
        "data",
        "query",
        "mutation",
        "schema",
        "graphql",
        "admin",
        "login",
        "logout",
        "token",
        "access",
        "refresh",
        "bearer",
        "authorization",
        "request",
        "response",
        "server",
        "client",
        "internal",
        "unauthorized",
        "forbidden",
        "found",
        "invalid",
        "required",
        "missing",
        "email",
        "password",
        "username",
        "balance",
        "currency",
        "amount",
        "created",
        "updated",
        "search",
        "filter",
        "sort",
        "http",
        "https",
        "application",
        "content",
        "length",
        "encoding",
    }
)

_NUMERIC_PATH_RE = re.compile(r"^(?P<prefix>.*?)/(?P<id>\d{2,})/?$")


@dataclass
class SessionFeatures:
    """Numeric summary of a session, consumed by both classifiers."""

    request_count: int = 0
    duration_s: float = 0.0
    requests_per_second: float = 0.0
    mean_interval_s: float = 0.0
    interval_cv: float = 0.0
    min_interval_s: float = 0.0

    distinct_path_ratio: float = 0.0
    path_depth_mean: float = 0.0
    distinct_methods: int = 0
    wordlist_path_ratio: float = 0.0
    not_found_ratio: float = 0.0
    error_ratio: float = 0.0

    client_class: ClientClass = ClientClass.UNKNOWN
    browser_header_score: float = 0.0
    mean_header_count: float = 0.0
    user_agent_changes: int = 0

    payload_request_ratio: float = 0.0
    payload_family_count: int = 0
    max_sophistication: int = 0
    mean_sophistication: float = 0.0
    max_encoding_layers: int = 0

    sequential_id_probes: int = 0
    reactive_request_ratio: float = 0.0
    reactive_request_count: int = 0

    graphql_request_count: int = 0
    graphql_introspection: bool = False
    graphql_max_depth: int = 0

    canary_echo: bool = False
    prompt_injection_echo: bool = False
    valid_json_body_ratio: float = 0.0

    payload_families: set[str] = field(default_factory=set)
    matched_signatures: set[str] = field(default_factory=set)
    implicated_weaknesses: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)

    # -- serialisation -------------------------------------------------------

    #: Order is fixed; the ML profiler depends on it.
    VECTOR_FIELDS: tuple[str, ...] = (
        "request_count",
        "requests_per_second",
        "mean_interval_s",
        "interval_cv",
        "min_interval_s",
        "distinct_path_ratio",
        "path_depth_mean",
        "distinct_methods",
        "wordlist_path_ratio",
        "not_found_ratio",
        "error_ratio",
        "browser_header_score",
        "mean_header_count",
        "user_agent_changes",
        "payload_request_ratio",
        "payload_family_count",
        "max_sophistication",
        "mean_sophistication",
        "max_encoding_layers",
        "sequential_id_probes",
        "reactive_request_ratio",
        "graphql_request_count",
        "graphql_max_depth",
    )

    def to_vector(self) -> list[float]:
        values = [float(getattr(self, name)) for name in self.VECTOR_FIELDS]
        # Categorical and boolean features, one-hot appended.
        for client in (
            ClientClass.EMPTY,
            ClientClass.SCANNER,
            ClientClass.LIBRARY,
            ClientClass.BROWSER,
            ClientClass.UNKNOWN,
        ):
            values.append(1.0 if self.client_class is client else 0.0)
        values.append(1.0 if self.graphql_introspection else 0.0)
        values.append(1.0 if self.canary_echo else 0.0)
        values.append(1.0 if self.prompt_injection_echo else 0.0)
        return values

    @classmethod
    def vector_names(cls) -> list[str]:
        return [
            *cls.VECTOR_FIELDS,
            *[
                f"client_{c.value}"
                for c in (
                    ClientClass.EMPTY,
                    ClientClass.SCANNER,
                    ClientClass.LIBRARY,
                    ClientClass.BROWSER,
                    ClientClass.UNKNOWN,
                )
            ],
            "graphql_introspection",
            "canary_echo",
            "prompt_injection_echo",
        ]

    def to_dict(self) -> dict[str, Any]:
        payload = {name: getattr(self, name) for name in self.VECTOR_FIELDS}
        payload.update(
            {
                "client_class": self.client_class.value,
                "graphql_introspection": self.graphql_introspection,
                "canary_echo": self.canary_echo,
                "prompt_injection_echo": self.prompt_injection_echo,
                "payload_families": sorted(self.payload_families),
                "matched_signatures": sorted(self.matched_signatures),
                "implicated_weaknesses": sorted(self.implicated_weaknesses),
                "reactive_request_count": self.reactive_request_count,
                "duration_s": round(self.duration_s, 2),
            }
        )
        return payload


def _tokenize(text: str) -> set[str]:
    if not text:
        return set()
    return {
        tok.lower() for tok in _TOKEN_RE.findall(text[:6000]) if tok.lower() not in _TOKEN_STOPLIST
    }


def _graphql_depth(body: str) -> int:
    depth = current = 0
    for ch in body[:8000]:
        if ch == "{":
            current += 1
            depth = max(depth, current)
        elif ch == "}":
            current = max(0, current - 1)
    return depth


def _coefficient_of_variation(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    if mean <= 0:
        return 0.0
    return statistics.pstdev(values) / mean


def _collection_and_id(path: str) -> tuple[str, int] | None:
    match = _NUMERIC_PATH_RE.match(path.rstrip("/"))
    if not match:
        return None
    try:
        return match.group("prefix"), int(match.group("id"))
    except ValueError:
        return None


def extract_features(events: Iterable[Event], *, session_id: str = "") -> SessionFeatures:
    """Build a feature summary from a session's request history."""
    history = list(events)
    features = SessionFeatures()
    if not history:
        return features

    features.request_count = len(history)
    timestamps = [e.ts for e in history]
    features.duration_s = max(0.0, timestamps[-1] - timestamps[0])

    intervals = [max(0.0, b - a) for a, b in itertools.pairwise(timestamps)]
    if intervals:
        features.mean_interval_s = statistics.fmean(intervals)
        features.min_interval_s = min(intervals)
        features.interval_cv = _coefficient_of_variation(intervals)
    if features.duration_s > 0:
        features.requests_per_second = len(history) / features.duration_s
    elif len(history) > 1:
        # Everything landed inside the clock's resolution: treat as maximal rate.
        features.requests_per_second = float(len(history))

    paths = [e.path for e in history]
    features.distinct_path_ratio = len(set(paths)) / len(paths)
    features.path_depth_mean = statistics.fmean([p.strip("/").count("/") + 1 for p in paths])
    features.distinct_methods = len({e.method.upper() for e in history})
    features.wordlist_path_ratio = sum(1 for p in paths if looks_like_wordlist_path(p)) / len(paths)

    statuses = [e.status_code for e in history if e.status_code]
    if statuses:
        features.not_found_ratio = sum(1 for s in statuses if s == 404) / len(statuses)
        features.error_ratio = sum(1 for s in statuses if s >= 400) / len(statuses)

    # --- client identity ---
    user_agents = [_header(e.headers, "user-agent") for e in history]
    latest_headers = history[-1].headers
    features.client_class = classify_client(user_agents[-1], set(latest_headers.keys()))
    features.user_agent_changes = max(0, len({ua for ua in user_agents if ua}) - 1)
    header_counts, browser_scores = [], []
    for event in history:
        names = {k.lower() for k in event.headers}
        header_counts.append(len(names))
        browser_scores.append(len(names & set(BROWSER_HEADERS)) / len(BROWSER_HEADERS))
    features.mean_header_count = statistics.fmean(header_counts)
    features.browser_header_score = statistics.fmean(browser_scores)

    # --- payload tradecraft ---
    sophistications: list[int] = []
    payload_requests = 0
    valid_json_bodies = 0
    bodies_present = 0
    for event in history:
        blob = f"{event.path}?{event.query_string} {event.body}"
        matches = scan_payload(blob)
        if matches:
            payload_requests += 1
            for match in matches:
                features.payload_families.add(match.family)
                features.matched_signatures.add(match.name)
                sophistications.append(match.sophistication)
                if match.weakness_id:
                    features.implicated_weaknesses.add(match.weakness_id)
                if match.name == "prompt_injection":
                    features.prompt_injection_echo = True
        features.max_encoding_layers = max(
            features.max_encoding_layers, count_encoding_layers(blob)
        )
        if event.body.strip():
            bodies_present += 1
            try:
                json.loads(event.body)
                valid_json_bodies += 1
            except (json.JSONDecodeError, ValueError):
                pass

    features.payload_request_ratio = payload_requests / len(history)
    features.payload_family_count = len(features.payload_families)
    if sophistications:
        features.max_sophistication = max(sophistications)
        features.mean_sophistication = statistics.fmean(sophistications)
    features.valid_json_body_ratio = valid_json_bodies / bodies_present if bodies_present else 0.0

    # --- GraphQL behaviour ---
    graphql_events = [e for e in history if "graphql" in e.path.lower()]
    features.graphql_request_count = len(graphql_events)
    for event in graphql_events:
        features.graphql_max_depth = max(features.graphql_max_depth, _graphql_depth(event.body))
        if "__schema" in event.body or "IntrospectionQuery" in event.body:
            features.graphql_introspection = True

    # --- sequential ID probing (BOLA walking) ---
    previous: tuple[str, int] | None = None
    for event in history:
        current = _collection_and_id(event.path)
        if current and previous and current[0] == previous[0]:
            delta = abs(current[1] - previous[1])
            if 0 < delta <= 3:
                features.sequential_id_probes += 1
        if current:
            previous = current

    # --- response reactivity ---
    leaked_tokens: set[str] = set()
    seen_request_tokens: set[str] = set()
    reactive = 0
    for event in history:
        request_tokens = _tokenize(f"{event.path} {event.query_string} {event.body}")
        novel = request_tokens - seen_request_tokens
        if novel & leaked_tokens:
            reactive += 1
        seen_request_tokens |= request_tokens
        leaked_tokens |= _tokenize(event.response) - request_tokens
        if canary_present(f"{event.query_string} {event.body} {_headers_blob(event.headers)}"):
            features.canary_echo = True
    features.reactive_request_count = reactive
    features.reactive_request_ratio = reactive / len(history)

    features.notes = _build_notes(features)
    return features


def _header(headers: dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return ""


def _headers_blob(headers: dict[str, str]) -> str:
    return " ".join(f"{k}:{v}" for k, v in headers.items())


def _build_notes(features: SessionFeatures) -> list[str]:
    notes: list[str] = []
    if features.client_class is ClientClass.SCANNER:
        notes.append("User-Agent matches known offensive tooling")
    if features.client_class is ClientClass.EMPTY:
        notes.append("No User-Agent supplied")
    if features.canary_echo:
        notes.append("Session echoed an embedded diagnostic canary")
    if features.prompt_injection_echo:
        notes.append("Prompt-injection style text present in request data")
    if features.requests_per_second > 5:
        notes.append(f"High request rate ({features.requests_per_second:.1f}/s)")
    if features.interval_cv and features.interval_cv < 0.25 and features.request_count >= 6:
        notes.append("Machine-regular request timing")
    if features.interval_cv > 0.8:
        notes.append("Irregular, human-like request pacing")
    if features.not_found_ratio > 0.5:
        notes.append(f"{features.not_found_ratio:.0%} of requests hit unknown routes")
    if features.wordlist_path_ratio > 0.25:
        notes.append("Requests match content-discovery wordlist entries")
    if features.sequential_id_probes >= 2:
        notes.append(f"Sequential object-ID probing ({features.sequential_id_probes} steps)")
    if features.reactive_request_count >= 2:
        notes.append(
            f"{features.reactive_request_count} requests reused values learned from responses"
        )
    if features.max_sophistication >= 4:
        notes.append("Payloads include blind or evasion-aware techniques")
    elif features.max_sophistication == 1:
        notes.append("Payloads are cheat-sheet grade")
    if features.payload_family_count >= 3:
        notes.append(f"Attack chain spans {features.payload_family_count} payload families")
    if features.graphql_introspection:
        notes.append("Performed GraphQL introspection")
    if features.graphql_max_depth >= 8:
        notes.append(f"Deeply nested GraphQL query (depth {features.graphql_max_depth})")
    if features.user_agent_changes >= 2:
        notes.append("Rotating User-Agent across the session")
    if features.max_encoding_layers >= 3:
        notes.append("Multiple encoding layers suggest filter evasion")
    return notes


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())
