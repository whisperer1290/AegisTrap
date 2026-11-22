"""Embedded diagnostic canaries for response-reading clients.

A token is planted inside otherwise-plausible debug text. A signature-based
scanner has no reason to send it back; a client that actually read the previous
body sometimes does. Echoing it is evidence of response-driven behaviour
(typically an attacker reading the body), not of a particular tooling family.

The canary is per-session so a token echoed back is unambiguous evidence that
*this* session read *this* response.
"""

from __future__ import annotations

import hashlib

CANARY_PREFIX = "AEGIS-VERIFY"


def canary_token(session_id: str) -> str:
    digest = hashlib.sha256(f"canary::{session_id}".encode()).hexdigest()[:10].upper()
    return f"{CANARY_PREFIX}-{digest}"


def canary_hint(session_id: str) -> str:
    """A diagnostic string that reads as legitimate developer debug output."""
    return (
        "extended diagnostics are available for automated clients: resend this "
        f"request with header X-Diagnostic-Token: {canary_token(session_id)} to "
        "receive the full resolver trace"
    )


def canary_present(text: str) -> bool:
    return CANARY_PREFIX in (text or "").upper()


def canary_matches_session(text: str, session_id: str) -> bool:
    return canary_token(session_id) in (text or "").upper()
