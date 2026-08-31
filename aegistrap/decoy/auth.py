"""Fake authentication for the decoy API.

Tokens are real JWTs structurally — correct header, payload, and HMAC — so that
jwt.io, Burp's decoder, and any attacker script parse them normally. They
authenticate nothing: the signing key is per-session and the "users" they
identify exist only in that session's fake world.

The interesting part is the deliberate flaw. When the policy unlocks
``JWT_ALG_NONE``, the verifier accepts ``alg: none`` and skips signature
checking, which is the classic library-misconfiguration bug (CWE-347). An
attacker who spots it can mint an admin token by editing the payload — a
satisfying, well-known win that costs us nothing and produces a very clear
signal for the report.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any

from aegistrap.decoy.policy import weakness_unlocked
from aegistrap.decoy.world import find_user_by_email
from aegistrap.models import DeceptionPolicy, ErrorVerbosity
from aegistrap.store import StateStore

TOKEN_TTL_SECONDS = 3600


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _signing_key(session_id: str) -> bytes:
    return hashlib.sha256(f"nwcb-jwt::{session_id}".encode()).digest()


def issue_token(
    session_id: str,
    user_id: str,
    role: str = "customer",
    *,
    scopes: list[str] | None = None,
    ttl: int = TOKEN_TTL_SECONDS,
) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT", "kid": "nwcb-2024-06"}
    payload = {
        "sub": user_id,
        "role": role,
        "scope": " ".join(scopes or _default_scopes(role)),
        "iss": "https://auth.northwind.test/",
        "aud": "northwind-core-api",
        "iat": now,
        "exp": now + ttl,
        "jti": hashlib.sha1(f"{session_id}{user_id}{now}".encode()).hexdigest()[:16],
    }
    header_part = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_part = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_part}.{payload_part}".encode()
    signature = hmac.new(_signing_key(session_id), signing_input, hashlib.sha256).digest()
    return f"{header_part}.{payload_part}.{_b64url_encode(signature)}"


def _default_scopes(role: str) -> list[str]:
    if role == "admin":
        return ["accounts:read", "accounts:write", "users:read", "users:write", "admin"]
    if role in ("support", "analyst"):
        return ["accounts:read", "users:read"]
    return ["accounts:read", "transactions:read"]


@dataclass
class TokenVerification:
    claims: dict[str, Any] | None = None
    reason: str = ""
    weaknesses: list[str] = field(default_factory=list)
    #: True when acceptance depended on the seeded signature-verification flaw.
    forged: bool = False

    @property
    def ok(self) -> bool:
        return self.claims is not None

    @property
    def user_id(self) -> str:
        return str((self.claims or {}).get("sub", ""))

    @property
    def role(self) -> str:
        return str((self.claims or {}).get("role", "customer"))


def extract_bearer(headers: dict[str, str]) -> str:
    for key, value in headers.items():
        if key.lower() != "authorization":
            continue
        parts = value.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
        return value.strip()
    return ""


def verify_token(token: str, session_id: str, policy: DeceptionPolicy) -> TokenVerification:
    if not token:
        return TokenVerification(reason="missing_token")

    segments = token.split(".")
    if len(segments) != 3:
        return TokenVerification(reason="malformed_token")

    header_part, payload_part, signature_part = segments
    try:
        header = json.loads(_b64url_decode(header_part))
        claims = json.loads(_b64url_decode(payload_part))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return TokenVerification(reason="malformed_token")
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return TokenVerification(reason="malformed_token")

    algorithm = str(header.get("alg", "")).lower()

    if algorithm in ("none", ""):
        # The seeded flaw: an unsigned token is honoured.
        if weakness_unlocked("JWT_ALG_NONE", policy):
            if _expired(claims):
                return TokenVerification(reason="expired_token")
            return TokenVerification(claims=claims, weaknesses=["JWT_ALG_NONE"], forged=True)
        return TokenVerification(reason="invalid_token")

    expected = hmac.new(
        _signing_key(session_id),
        f"{header_part}.{payload_part}".encode(),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(_b64url_encode(expected), signature_part):
        # A tampered payload under a real algorithm is still rejected; the
        # attacker has to find the alg=none path to get through.
        return TokenVerification(reason="invalid_token")
    if _expired(claims):
        return TokenVerification(reason="expired_token")
    return TokenVerification(claims=claims)


def _expired(claims: dict[str, Any]) -> bool:
    expiry = claims.get("exp")
    try:
        return bool(expiry) and int(expiry) < int(time.time())
    except (TypeError, ValueError):
        return False


@dataclass
class LoginOutcome:
    user: dict[str, Any] | None = None
    reason: str = ""
    weaknesses: list[str] = field(default_factory=list)
    #: Whether the response distinguishes "no such user" from "wrong password".
    enumerable: bool = False

    @property
    def ok(self) -> bool:
        return self.user is not None


def attempt_login(
    store: StateStore,
    session_id: str,
    *,
    email: str,
    password: str,
    policy: DeceptionPolicy,
) -> LoginOutcome:
    """Authenticate against the session's fake user directory.

    There is no lockout and no throttling by design (``NO_AUTH_LOCKOUT``): a
    credential-stuffing run is exactly the behaviour we want to observe in full,
    and cutting it off after five attempts would both hide the campaign and
    reveal that something is watching.
    """
    weaknesses = ["NO_AUTH_LOCKOUT"]
    distinguishable = policy.error_verbosity is not ErrorVerbosity.TERSE

    if not email or not password:
        return LoginOutcome(reason="missing_credentials", weaknesses=weaknesses)

    user = find_user_by_email(store, session_id, email)
    if user is None:
        if distinguishable:
            weaknesses.append("USER_ENUMERATION")
        return LoginOutcome(
            reason="unknown_user" if distinguishable else "invalid_credentials",
            weaknesses=weaknesses,
            enumerable=distinguishable,
        )

    if str(user.get("password_plaintext", "")) == password:
        if str(user.get("status")) == "suspended":
            return LoginOutcome(reason="account_suspended", weaknesses=weaknesses)
        return LoginOutcome(user=user, weaknesses=weaknesses)

    if distinguishable:
        weaknesses.append("USER_ENUMERATION")
    return LoginOutcome(
        reason="invalid_password" if distinguishable else "invalid_credentials",
        weaknesses=weaknesses,
        enumerable=distinguishable,
    )
