"""Error rendering for the decoy API.

Error responses do more work than success responses in a honeypot. They are
where a real service accidentally leaks schema detail, and they are the main
lever the deception policy pulls: the same missing account produces a bare
``404 not_found`` for a scanner and a resolver-level Postgres error naming four
real column names for a skilled human.

Two constraints shaped this module:

* **Framework tells are fatal.** FastAPI's default 422 validation envelope and
  Starlette's default 404 body are both trivially fingerprintable. Every error
  the service can emit is therefore rendered here, in one house style, and the
  framework's own handlers are replaced.
* **Leaks must be consistent.** A verbose error names columns that genuinely
  exist in the session's fake world, so an attacker who then queries those
  columns gets sensible answers rather than a contradiction.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from typing import Any

from aegistrap.decoy.canary import canary_hint
from aegistrap.models import DeceptionPolicy, ErrorVerbosity

#: Columns per collection, used when a verbose error leaks schema detail. These
#: mirror the fields actually stored in the fake world.
_SCHEMA_COLUMNS: dict[str, tuple[str, ...]] = {
    "accounts": (
        "id",
        "owner_id",
        "iban",
        "product",
        "currency",
        "balance_minor",
        "available_minor",
        "status",
        "opened_at",
        "ledger_shard",
        "risk_band",
    ),
    "users": (
        "id",
        "email",
        "full_name",
        "role",
        "status",
        "mfa_enabled",
        "phone",
        "kyc_status",
        "password_hash",
        "risk_score",
    ),
    "transactions": (
        "id",
        "account_id",
        "direction",
        "amount_minor",
        "currency",
        "counterparty_iban",
        "category",
        "status",
        "booked_at",
        "fraud_score",
    ),
    "cards": ("id", "account_id", "brand", "pan_masked", "expiry", "status"),
    "orders": ("id", "user_id", "status", "total_minor", "currency", "placed_at", "margin_minor"),
    "products": ("id", "name", "category", "price_minor", "stock", "cost_minor"),
}

_SERVICE_PATHS = {
    "accounts": "/srv/nwcb-core/app/repositories/accounts.py",
    "users": "/srv/nwcb-core/app/repositories/identity.py",
    "transactions": "/srv/nwcb-core/app/repositories/ledger.py",
    "cards": "/srv/nwcb-core/app/repositories/cards.py",
    "orders": "/srv/nwcb-shop/app/repositories/orders.py",
    "products": "/srv/nwcb-shop/app/repositories/catalog.py",
}


@dataclass
class DecoyError:
    status: int
    payload: dict[str, Any]
    weaknesses: list[str]


def request_id(session_id: str, seq: int) -> str:
    digest = hashlib.sha1(f"{session_id}:{seq}".encode()).hexdigest()[:12]
    return f"req_{digest}"


def render_error(
    *,
    code: str,
    message: str,
    status: int,
    policy: DeceptionPolicy,
    session_id: str,
    seq: int,
    collection: str = "",
    detail: str = "",
    resource_id: str = "",
    extra: dict[str, Any] | None = None,
) -> DecoyError:
    """Build an error body scaled to the caller's disclosure budget."""
    verbosity = policy.error_verbosity
    weaknesses: list[str] = []
    payload: dict[str, Any] = {"error": code}

    if verbosity is ErrorVerbosity.TERSE:
        if extra:
            payload.update(extra)
        return DecoyError(status=status, payload=payload, weaknesses=weaknesses)

    payload["message"] = message
    if resource_id:
        payload["resource_id"] = resource_id
    if collection:
        payload["resource"] = collection.rstrip("s") or collection

    if verbosity in (ErrorVerbosity.VERBOSE, ErrorVerbosity.DEBUG):
        weaknesses.append("VERBOSE_ERROR")
        payload["request_id"] = request_id(session_id, seq)
        if detail:
            payload["detail"] = detail
        elif collection and policy.leak_schema_hints:
            columns = _SCHEMA_COLUMNS.get(collection, ())
            if columns:
                payload["detail"] = (
                    f"{collection}.resolve: no row for key in ({', '.join(columns[:6])})"
                )
        if policy.leak_schema_hints and collection:
            payload["_schema"] = {
                "table": collection,
                "columns": list(_SCHEMA_COLUMNS.get(collection, ())),
            }
            weaknesses.append("EXCESSIVE_DATA_EXPOSURE")

    if verbosity is ErrorVerbosity.DEBUG:
        payload["_debug"] = {
            "service": "northwind-core-api",
            "node": f"api-{(seq % 4) + 1}.eu-west-1.internal",
            "trace_id": hashlib.sha1(f"trace{session_id}{seq}".encode()).hexdigest()[:16],
            "hint": canary_hint(session_id),
        }
        if policy.expose_admin_hints:
            payload["_debug"]["admin_console"] = "/api/v1/admin"
            weaknesses.append("BFLA_ADMIN_ROUTE")

    if extra:
        payload.update(extra)
    return DecoyError(status=status, payload=payload, weaknesses=weaknesses)


def sql_injection_error(
    *,
    policy: DeceptionPolicy,
    session_id: str,
    seq: int,
    collection: str,
    injected_value: str,
    rng: random.Random | None = None,
) -> DecoyError:
    """A database error that confirms injectability and leaks the query shape.

    This is the highest-value bait in the catalogue: it tells the attacker their
    payload reached SQL, names real columns, and invites a follow-up UNION or
    blind probe - all of which are far more informative to profile than the
    initial ``' OR 1=1``.
    """
    rng = rng or random.Random(f"{session_id}{seq}")
    columns = _SCHEMA_COLUMNS.get(collection, _SCHEMA_COLUMNS["accounts"])
    projection = ", ".join(columns[:6])
    query = (
        f"SELECT {projection} FROM {collection} "
        f"WHERE id = '{injected_value[:180]}' AND deleted_at IS NULL"
    )
    weaknesses = ["SQL_INJECTION", "VERBOSE_ERROR"]

    if policy.error_verbosity is ErrorVerbosity.TERSE:
        return DecoyError(
            status=500,
            payload={"error": "internal_error"},
            weaknesses=["SQL_INJECTION"],
        )

    payload: dict[str, Any] = {
        "error": "internal_error",
        "message": "Unhandled exception while resolving request.",
        "request_id": request_id(session_id, seq),
    }

    if policy.error_verbosity in (ErrorVerbosity.VERBOSE, ErrorVerbosity.DEBUG):
        payload["detail"] = 'asyncpg.exceptions.PostgresSyntaxError: syntax error at or near "\'"'
        if policy.leak_schema_hints:
            payload["query"] = query
            weaknesses.append("EXCESSIVE_DATA_EXPOSURE")

    if policy.error_verbosity is ErrorVerbosity.DEBUG and policy.expose_stack_traces:
        module_path = _SERVICE_PATHS.get(collection, _SERVICE_PATHS["accounts"])
        payload["_traceback"] = [
            "Traceback (most recent call last):",
            f'  File "{module_path}", line {rng.randint(180, 260)}, in fetch_by_id',
            "    row = await conn.fetchrow(sql, *args)",
            '  File "/usr/local/lib/python3.11/site-packages/asyncpg/connection.py", '
            "line 675, in fetchrow",
            "    return await self._execute(query, args, 0, timeout)",
            '  File "/usr/local/lib/python3.11/site-packages/asyncpg/connection.py", '
            "line 1746, in _execute",
            "    result, _ = await self.__execute(",
            'asyncpg.exceptions.PostgresSyntaxError: syntax error at or near "\'"',
            f"QUERY: {query}",
        ]
        payload["_debug"] = {
            "hint": canary_hint(session_id),
            "shard": f"eu-w1-shard-{rng.randint(1, 8)}",
        }
        weaknesses.append("DEBUG_ENDPOINT")

    return DecoyError(status=500, payload=payload, weaknesses=weaknesses)


def not_found(
    *,
    policy: DeceptionPolicy,
    session_id: str,
    seq: int,
    path: str,
    collection: str = "",
    resource_id: str = "",
) -> DecoyError:
    if collection:
        return render_error(
            code="not_found",
            message=(
                f"No {collection.rstrip('s')} matching id "
                f"'{resource_id}' for the current principal."
            ),
            status=404,
            policy=policy,
            session_id=session_id,
            seq=seq,
            collection=collection,
            resource_id=resource_id,
        )
    return render_error(
        code="not_found",
        message=f"The requested path '{path}' does not exist on this service.",
        status=404,
        policy=policy,
        session_id=session_id,
        seq=seq,
    )


def unauthorized(
    *, policy: DeceptionPolicy, session_id: str, seq: int, reason: str = "missing_token"
) -> DecoyError:
    messages = {
        "missing_token": "Authorization header is required for this endpoint.",
        "invalid_token": "The supplied access token could not be verified.",
        "expired_token": "The supplied access token has expired.",
    }
    return render_error(
        code="unauthorized",
        message=messages.get(reason, messages["missing_token"]),
        status=401,
        policy=policy,
        session_id=session_id,
        seq=seq,
        extra={"www_authenticate": 'Bearer realm="northwind", error="invalid_token"'},
    )


def forbidden(
    *, policy: DeceptionPolicy, session_id: str, seq: int, required_scope: str = ""
) -> DecoyError:
    extra: dict[str, Any] = {}
    if required_scope and policy.leak_schema_hints:
        extra["required_scope"] = required_scope
    return render_error(
        code="forbidden",
        message="The authenticated principal is not permitted to perform this action.",
        status=403,
        policy=policy,
        session_id=session_id,
        seq=seq,
        extra=extra,
    )


def bad_request(
    *,
    policy: DeceptionPolicy,
    session_id: str,
    seq: int,
    message: str,
    field: str = "",
) -> DecoyError:
    extra: dict[str, Any] = {}
    if field:
        extra["field"] = field
    return render_error(
        code="invalid_request",
        message=message,
        status=400,
        policy=policy,
        session_id=session_id,
        seq=seq,
        extra=extra,
    )


def method_not_allowed(
    *, policy: DeceptionPolicy, session_id: str, seq: int, method: str, allowed: list[str]
) -> DecoyError:
    return render_error(
        code="method_not_allowed",
        message=f"{method} is not supported for this resource.",
        status=405,
        policy=policy,
        session_id=session_id,
        seq=seq,
        extra={"allowed": allowed},
    )


def rate_limited(*, policy: DeceptionPolicy, session_id: str, seq: int) -> DecoyError:
    return render_error(
        code="rate_limited",
        message="Request quota exceeded for this client.",
        status=429,
        policy=policy,
        session_id=session_id,
        seq=seq,
        extra={"retry_after": 30},
    )
