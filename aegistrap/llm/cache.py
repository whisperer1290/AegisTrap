"""TTL cache for generated responses.

Section 13 names LLM latency as a way attackers notice a honeypot, and
prescribes caching common responses plus reserving full generation for
genuinely interesting requests. Caching keys on the *authoritative state* as
well as the request, so a cache hit can never serve a body that contradicts
current state - if state moved, the key changes and the entry misses.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class CacheEntry:
    payload: dict[str, Any]
    stored_at: float
    #: Recency ordinal from the cache's own counter, not a timestamp. The
    #: system clock is too coarse on some platforms to distinguish accesses
    #: made in the same millisecond, which would silently turn the eviction
    #: policy back into FIFO.
    last_used: int


class ResponseCache:
    def __init__(self, *, ttl_seconds: int = 900, max_entries: int = 2048) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._entries: dict[str, CacheEntry] = {}
        self._lock = threading.Lock()
        self._tick = 0
        self.hits = 0
        self.misses = 0

    @staticmethod
    def make_key(
        *,
        session_id: str,
        method: str,
        path: str,
        query: str,
        body: str,
        persona: str,
        verbosity: str,
        grounded_payload: Any,
    ) -> str:
        """Build a cache key.

        ``session_id`` is part of the key and must stay that way. Each session
        gets its own generated world, so a key without it would let one
        attacker be served a body describing another attacker's accounts —
        both a cross-session leak and a visible contradiction.
        """
        material = json.dumps(
            {
                "s": session_id,
                "m": method.upper(),
                "p": path,
                "q": query,
                "b": body[:512],
                "persona": persona,
                "verbosity": verbosity,
                "state": grounded_payload,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(material.encode()).hexdigest()

    def get(self, key: str) -> dict[str, Any] | None:
        now = time.time()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self.misses += 1
                return None
            # ``>=`` so that a TTL of zero disables caching outright, rather
            # than caching for the remainder of the current instant.
            if now - entry.stored_at >= self.ttl_seconds:
                del self._entries[key]
                self.misses += 1
                return None
            self._tick += 1
            entry.last_used = self._tick
            self.hits += 1
            return entry.payload

    def put(self, key: str, payload: dict[str, Any]) -> None:
        if self.ttl_seconds <= 0:
            return
        now = time.time()
        with self._lock:
            self._tick += 1
            if key not in self._entries and len(self._entries) >= self.max_entries:
                # Evict a batch by least-recent *use*, not insertion order: a
                # path the attacker keeps re-probing is exactly the entry worth
                # keeping, and it would be the first to go under FIFO.
                victims = sorted(self._entries.items(), key=lambda kv: kv[1].last_used)
                for victim_key, _ in victims[: max(1, self.max_entries // 4)]:
                    self._entries.pop(victim_key, None)
            self._entries[key] = CacheEntry(payload=payload, stored_at=now, last_used=self._tick)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def stats(self) -> dict[str, Any]:
        total = self.hits + self.misses
        return {
            "entries": len(self._entries),
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hits / total, 4) if total else 0.0,
        }
