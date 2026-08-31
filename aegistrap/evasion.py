"""Fingerprint-evasion self-tuning (the Section 4 stretch goal).

Off by default, and treated as future work in the write-up unless the earlier
phases finish ahead of schedule.

The mechanism periodically mutates the server's outward appearance — banner,
header set, header ordering, and latency profile — so that a fingerprint
harvested from one deployment does not identify the next.

One design point matters more than the mutation itself: **mutation must be
stable within a session.** A server whose ``Server`` header changes between two
requests from the same client is more obviously fake than one that never
changes it at all. Variation is therefore keyed on a session-and-epoch seed, so
an attacker sees one coherent server for the whole session while separate
sessions and later epochs see different ones.
"""

from __future__ import annotations

import hashlib
import random
import time
from dataclasses import dataclass
from typing import Any

#: Plausible edge/runtime combinations for a service of this kind. Deliberately
#: excludes ``uvicorn``: it is the runtime actually serving this app, so
#: presenting it would confirm a Python ASGI service rather than disguise one.
_BANNER_PROFILES: tuple[dict[str, str], ...] = (
    {"server": "nginx", "x-powered-by": ""},
    {"server": "nginx/1.24.0", "x-powered-by": ""},
    {"server": "envoy", "x-envoy-upstream-service-time": ""},
    {"server": "gunicorn/21.2.0", "x-powered-by": ""},
    {"server": "Apache/2.4.57 (Ubuntu)", "x-powered-by": ""},
    {"server": "cloudflare", "cf-ray": ""},
    {"server": "AmazonS3", "x-amz-request-id": ""},
    {"server": "", "via": "1.1 google"},
)

_OPTIONAL_HEADERS: tuple[str, ...] = (
    "x-request-id",
    "x-served-by",
    "x-cache",
    "x-runtime",
    "x-correlation-id",
    "x-envoy-upstream-service-time",
    "cf-ray",
    "x-amz-request-id",
)

_CACHE_VALUES = ("HIT", "MISS", "PASS", "BYPASS")


@dataclass
class Fingerprint:
    """The outward appearance presented to one session."""

    banner: dict[str, str]
    optional_headers: tuple[str, ...]
    latency_floor_ms: int
    latency_jitter_ms: int
    epoch: int

    def describe(self) -> dict[str, Any]:
        return {
            "server": self.banner.get("server", ""),
            "optional_headers": list(self.optional_headers),
            "latency_floor_ms": self.latency_floor_ms,
            "latency_jitter_ms": self.latency_jitter_ms,
            "epoch": self.epoch,
        }


class FingerprintMutator:
    def __init__(
        self,
        *,
        enabled: bool = False,
        service_name: str = "AegisTrap",
        service_version: str = "1.0.0",
        base_latency_floor_ms: int = 40,
        base_latency_jitter_ms: int = 90,
        epoch_seconds: int = 3600,
        seed: str = "",
        banner: str = "nginx",
    ) -> None:
        self.enabled = enabled
        self.service_name = service_name
        self.service_version = service_version
        self.base_latency_floor_ms = base_latency_floor_ms
        self.base_latency_jitter_ms = base_latency_jitter_ms
        self.epoch_seconds = max(60, epoch_seconds)
        self.seed = seed or hashlib.sha256(service_name.encode()).hexdigest()[:16]
        self._static = Fingerprint(
            banner={"server": banner},
            optional_headers=("x-request-id",),
            latency_floor_ms=base_latency_floor_ms,
            latency_jitter_ms=base_latency_jitter_ms,
            epoch=0,
        )

    def current_epoch(self, now: float | None = None) -> int:
        return int((now or time.time()) // self.epoch_seconds)

    def fingerprint_for(self, session_id: str, now: float | None = None) -> Fingerprint:
        if not self.enabled:
            return self._static
        epoch = self.current_epoch(now)
        rng = random.Random(f"{self.seed}:{session_id}:{epoch}")
        banner = dict(rng.choice(_BANNER_PROFILES))
        optional = tuple(rng.sample(_OPTIONAL_HEADERS, rng.randint(1, 3)))
        return Fingerprint(
            banner=banner,
            optional_headers=optional,
            latency_floor_ms=int(self.base_latency_floor_ms * rng.uniform(0.6, 1.8)),
            latency_jitter_ms=int(self.base_latency_jitter_ms * rng.uniform(0.5, 2.0)),
            epoch=epoch,
        )

    def response_headers(
        self, session_id: str, *, seq: int, now: float | None = None
    ) -> dict[str, str]:
        """Headers to attach to one response."""
        fingerprint = self.fingerprint_for(session_id, now)
        rng = random.Random(f"{self.seed}:{session_id}:{seq}")
        headers: dict[str, str] = {}

        for name, value in fingerprint.banner.items():
            if not name:
                continue
            headers[name] = value or self._banner_value(name, rng)

        for name in fingerprint.optional_headers:
            headers.setdefault(name, self._optional_value(name, session_id, seq, rng))

        return {k: v for k, v in headers.items() if v}

    def _banner_value(self, name: str, rng: random.Random) -> str:
        if name == "x-powered-by":
            return rng.choice(("Express", "PHP/8.2.12", "ASP.NET"))
        if name == "cf-ray":
            return f"{rng.randrange(16**16):016x}-AMS"
        if name == "x-amz-request-id":
            return f"{rng.randrange(16**16):016X}"
        if name == "x-envoy-upstream-service-time":
            return str(rng.randint(3, 180))
        return ""

    def _optional_value(self, name: str, session_id: str, seq: int, rng: random.Random) -> str:
        digest = hashlib.sha1(f"{session_id}{seq}{name}".encode()).hexdigest()
        if name == "x-request-id":
            return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"
        if name == "x-correlation-id":
            return digest[:24]
        if name == "x-served-by":
            return f"cache-ams{rng.randint(1000, 9999)}-AMS"
        if name == "x-cache":
            return rng.choice(_CACHE_VALUES)
        if name == "x-runtime":
            return f"{rng.uniform(0.004, 0.180):.6f}"
        if name == "x-envoy-upstream-service-time":
            return str(rng.randint(3, 180))
        if name == "cf-ray":
            return f"{digest[:16]}-AMS"
        if name == "x-amz-request-id":
            return digest[:16].upper()
        return digest[:16]

    def latency_profile(self, session_id: str) -> tuple[int, int]:
        fingerprint = self.fingerprint_for(session_id)
        return fingerprint.latency_floor_ms, fingerprint.latency_jitter_ms

    def describe(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "epoch_seconds": self.epoch_seconds,
            "current_epoch": self.current_epoch(),
            "banner_pool_size": len(_BANNER_PROFILES),
        }
