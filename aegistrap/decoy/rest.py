"""Decoy REST surface (Core Module 1).

A realistic, OpenAPI-documented fintech backend with deliberately interesting
flaws. Every flaw is gated on the deception policy, so the surface an attacker
can reach depends on how the profiler has classified them.

Three implementation rules run through this module:

1. **Authoritative first.** Handlers read state, compute the exact payload, and
   hand it to the response engine. The LLM never decides whether an
   authorization check passes, only how the answer is dressed.
2. **Deterministic probabilistic deception.** Where a weakness fires on a
   coin-flip, the coin is seeded on the session and the target object. Retrying
   ``GET /accounts/1002`` must give the same answer twice; a flaw that appears
   and disappears is the clearest honeypot tell there is.
3. **State transitions are real.** A transfer actually moves the fake balance,
   so a ``GET`` after a ``POST`` reflects it. This is the consistency problem
   the synopsis singles out as harder than a shell session.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from aegistrap.decoy import errors
from aegistrap.decoy.auth import issue_token
from aegistrap.decoy.canary import canary_hint
from aegistrap.decoy.context import DecoyContext, build_context
from aegistrap.decoy.policy import weakness_unlocked
from aegistrap.decoy.world import public_view
from aegistrap.profiler.signatures import scan_payload

Ctx = Depends(build_context)

#: Endpoint metadata handed to the LLM so generated responses match the
#: documented contract rather than the model's guess at it.
ENDPOINTS: dict[str, dict[str, Any]] = {
    "health": {"summary": "Service health probe", "returns": "status object"},
    "login": {
        "summary": "Password authentication",
        "returns": "access_token, token_type, expires_in, principal",
    },
    "account_get": {
        "summary": "Retrieve one account",
        "returns": "account object with id, iban, currency, balance_minor, status",
    },
    "account_list": {
        "summary": "List accounts visible to the principal",
        "returns": "items array plus total, limit, offset",
    },
    "transaction_list": {
        "summary": "List transactions for an account",
        "returns": "items array of transaction objects plus pagination metadata",
    },
    "transfer": {
        "summary": "Initiate an internal transfer",
        "returns": "transfer receipt with id, status, debited account and new balance",
    },
    "user_me": {"summary": "Current principal profile", "returns": "user object"},
    "admin": {"summary": "Administrative surface", "returns": "administrative payload"},
    "search": {"summary": "Cross-entity search", "returns": "matches array"},
    "export": {"summary": "Statement export", "returns": "export descriptor or file body"},
    "webhook": {"summary": "Webhook registration", "returns": "subscription object"},
}


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


def _sqli_attempt(value: str) -> str:
    """Return the matched payload if the value looks like SQL injection."""
    for match in scan_payload(value):
        if match.family in ("sqli", "nosqli"):
            return match.excerpt
    return ""


def _traversal_attempt(value: str) -> str:
    for match in scan_payload(value):
        if match.family == "traversal":
            return match.excerpt
    return ""


def _cmdi_attempt(value: str) -> str:
    for match in scan_payload(value):
        if match.family == "cmdi":
            return match.excerpt
    return ""


def _xss_attempt(value: str) -> str:
    for match in scan_payload(value):
        if match.family == "xss":
            return match.excerpt
    return ""


def _ssrf_attempt(value: str) -> str:
    for match in scan_payload(value):
        if match.family == "ssrf":
            return match.excerpt
    return ""


def _leak_internal_fields(ctx: DecoyContext) -> bool:
    """Whether this request should receive internal-only object fields.

    Gated on the policy *and* on the attacker having asked for them, via a
    field-selection parameter. That makes the flaw discoverable by someone who
    read a schema hint, rather than something the API volunteers to everyone.
    """
    if not weakness_unlocked("EXCESSIVE_DATA_EXPOSURE", ctx.policy):
        return False
    requested = (
        f"{ctx.query_value('fields')} {ctx.query_value('expand')} {ctx.query_value('include')}"
    )
    if requested.strip():
        internal_markers = (
            "password",
            "hash",
            "risk",
            "internal",
            "notes",
            "aml",
            "shard",
            "fraud",
            "processor",
            "cost",
            "margin",
            "secret",
            "cvv",
            "pan_full",
            "all",
            "*",
        )
        if any(marker in requested.lower() for marker in internal_markers):
            return True
    return False


def _serialise(ctx: DecoyContext, collection: str, data: dict[str, Any]) -> dict[str, Any]:
    leak = _leak_internal_fields(ctx)
    if leak:
        ctx.note_weakness("EXCESSIVE_DATA_EXPOSURE")
    return public_view(collection, data, leak_internal=leak)


def _current_user(ctx: DecoyContext) -> dict[str, Any] | None:
    if not ctx.auth.ok:
        return None
    obj = ctx.store.get_object(ctx.session_id, "users", ctx.auth.user_id)
    if obj is not None:
        return obj.data
    # A forged alg=none token can name a principal that does not exist. A real
    # service with this bug would trust the claims, so synthesise a shell user
    # and keep it in state so later requests stay consistent.
    if ctx.auth.forged:
        shell = {
            "id": ctx.auth.user_id or "usr_unknown",
            "email": f"{(ctx.auth.user_id or 'unknown')}@example.com",
            "full_name": "Unresolved Principal",
            "role": ctx.auth.role,
            "status": "active",
            "mfa_enabled": False,
            "kyc_status": "pending",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        ctx.store.put_object(ctx.session_id, "users", shell["id"], shell, owner_id=shell["id"])
        return shell
    return None


def _require_auth(ctx: DecoyContext) -> errors.DecoyError | None:
    if ctx.auth.ok:
        return None
    reason = ctx.auth.reason or "missing_token"
    if reason not in ("missing_token", "invalid_token", "expired_token"):
        reason = "invalid_token"
    return errors.unauthorized(
        policy=ctx.policy, session_id=ctx.session_id, seq=ctx.seq, reason=reason
    )


def _page(ctx: DecoyContext) -> tuple[int, int, bool]:
    """Resolve pagination, recording the missing-ceiling weakness."""
    requested = ctx.int_query("limit", 25, minimum=1, maximum=10_000)
    unlimited = weakness_unlocked("NO_RATE_LIMIT", ctx.policy)
    if requested > ctx.policy.max_page_size and not unlimited:
        limit = ctx.policy.max_page_size
    else:
        limit = requested
    if requested > ctx.policy.max_page_size and unlimited:
        ctx.note_weakness("NO_RATE_LIMIT")
    return limit, ctx.int_query("offset", 0, maximum=100_000), requested > limit


def _admin_gate(ctx: DecoyContext) -> errors.DecoyError | None:
    """Authorization for the administrative surface.

    The seeded flaw (``BFLA_ADMIN_ROUTE``) is that presence of *any* valid
    token is accepted as authorisation, which is a very common real-world bug:
    the route is behind authentication middleware but nobody checked the role.
    """
    unauthorised = _require_auth(ctx)
    if unauthorised is not None:
        return unauthorised
    if ctx.auth.role == "admin":
        return None
    if weakness_unlocked("BFLA_ADMIN_ROUTE", ctx.policy):
        ctx.note_weakness("BFLA_ADMIN_ROUTE")
        return None
    return errors.forbidden(
        policy=ctx.policy,
        session_id=ctx.session_id,
        seq=ctx.seq,
        required_scope="admin",
    )


def _object_authz(
    ctx: DecoyContext,
    collection: str,
    object_id: str,
    owner_id: str | None,
    weakness_id: str,
) -> tuple[bool, errors.DecoyError | None]:
    """Ownership check with a seeded BOLA flaw.

    Returns ``(allowed, error)``. When the caller does not own the object, the
    decision is a seeded coin-flip weighted by the policy's leak probability
    and keyed deterministically on the object, so the same probe always gets
    the same answer.
    """
    user = _current_user(ctx)
    if user is None:
        return False, _require_auth(ctx)
    if owner_id is None or owner_id == user["id"]:
        return True, None
    if user.get("role") in ("admin", "support"):
        return True, None

    if weakness_unlocked(weakness_id, ctx.policy):
        roll = ctx.rng(f"bola:{collection}:{object_id}").random()
        if roll < ctx.policy.idor_leak_probability:
            ctx.note_weakness(weakness_id)
            return True, None
    return False, errors.forbidden(
        policy=ctx.policy,
        session_id=ctx.session_id,
        seq=ctx.seq,
        required_scope=f"{collection}:read:any",
    )


# ---------------------------------------------------------------------------
# routers
# ---------------------------------------------------------------------------


def build_common_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["core"])

    @router.get("/health", summary="Service health probe")
    async def health(ctx: DecoyContext = Ctx) -> Response:
        payload = {
            "status": "ok",
            "service": ctx.runtime.settings.service_name,
            "version": ctx.runtime.settings.service_version,
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        # Health is polled constantly and reveals nothing; never worth a token.
        return await ctx.respond(payload, endpoint=ENDPOINTS["health"], allow_llm=False)

    @router.post("/auth/login", summary="Authenticate with email and password")
    async def login(ctx: DecoyContext = Ctx) -> Response:
        from aegistrap.decoy.auth import attempt_login

        body = ctx.json_body()
        if not isinstance(body, dict):
            return await ctx.respond_error(
                errors.bad_request(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    message="Request body must be a JSON object.",
                ),
                endpoint=ENDPOINTS["login"],
            )

        email = str(body.get("email") or body.get("username") or "")
        password = str(body.get("password") or "")

        injected = _sqli_attempt(f"{email} {password}")
        if injected and weakness_unlocked("SQL_INJECTION", ctx.policy):
            error = errors.sql_injection_error(
                policy=ctx.policy,
                session_id=ctx.session_id,
                seq=ctx.seq,
                collection="users",
                injected_value=email or password,
            )
            return await ctx.respond_error(error, endpoint=ENDPOINTS["login"])

        outcome = attempt_login(
            ctx.store, ctx.session_id, email=email, password=password, policy=ctx.policy
        )
        ctx.note_weakness(*outcome.weaknesses)

        if not outcome.ok:
            messages = {
                "unknown_user": "No account exists for that email address.",
                "invalid_password": "The password supplied for this account is incorrect.",
                "invalid_credentials": "Email or password is incorrect.",
                "missing_credentials": "Both email and password are required.",
                "account_suspended": "This account is suspended. Contact support.",
            }
            status = 400 if outcome.reason == "missing_credentials" else 401
            extra: dict[str, Any] = {}
            if outcome.enumerable:
                # The seeded enumeration flaw: the response confirms existence.
                extra["user_exists"] = outcome.reason != "unknown_user"
            return await ctx.respond_error(
                errors.render_error(
                    code=outcome.reason,
                    message=messages.get(outcome.reason, "Authentication failed."),
                    status=status,
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    extra=extra,
                ),
                endpoint=ENDPOINTS["login"],
            )

        user = outcome.user or {}
        token = issue_token(ctx.session_id, str(user["id"]), str(user.get("role", "customer")))
        ctx.store.set_authenticated_user(ctx.session_id, str(user["id"]))
        payload = {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": " ".join(["accounts:read", "transactions:read"]),
            "principal": {
                "id": user["id"],
                "email": user["email"],
                "full_name": user["full_name"],
                "role": user.get("role", "customer"),
                "mfa_enabled": user.get("mfa_enabled", False),
            },
        }
        return await ctx.respond(payload, endpoint=ENDPOINTS["login"])

    @router.get("/users/me", summary="Current principal profile")
    async def users_me(ctx: DecoyContext = Ctx) -> Response:
        user = _current_user(ctx)
        if user is None:
            return await ctx.respond_error(
                _require_auth(ctx)
                or errors.unauthorized(policy=ctx.policy, session_id=ctx.session_id, seq=ctx.seq),
                endpoint=ENDPOINTS["user_me"],
            )
        return await ctx.respond(_serialise(ctx, "users", user), endpoint=ENDPOINTS["user_me"])

    @router.patch("/users/me", summary="Update the current principal profile")
    async def patch_users_me(ctx: DecoyContext = Ctx) -> Response:
        user = _current_user(ctx)
        if user is None:
            return await ctx.respond_error(
                _require_auth(ctx)
                or errors.unauthorized(policy=ctx.policy, session_id=ctx.session_id, seq=ctx.seq),
                endpoint=ENDPOINTS["user_me"],
            )
        body = ctx.json_body()
        if not isinstance(body, dict):
            return await ctx.respond_error(
                errors.bad_request(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    message="Request body must be a JSON object.",
                ),
                endpoint=ENDPOINTS["user_me"],
            )

        # Fields a correct implementation would accept from the client.
        safe_fields = {"full_name", "phone", "city", "mfa_enabled"}
        privileged_fields = {"role", "kyc_status", "status", "risk_score", "id", "email"}
        updated = dict(user)
        applied: list[str] = []
        rejected: list[str] = []

        for key, value in body.items():
            if key in safe_fields:
                updated[key] = value
                applied.append(key)
            elif key in privileged_fields:
                if weakness_unlocked("MASS_ASSIGNMENT", ctx.policy):
                    # The seeded flaw: client JSON is merged wholesale.
                    updated[key] = value
                    applied.append(key)
                    ctx.note_weakness("MASS_ASSIGNMENT")
                else:
                    rejected.append(key)
            else:
                rejected.append(key)

        ctx.store.put_object(
            ctx.session_id, "users", str(updated["id"]), updated, owner_id=str(updated["id"])
        )
        payload = _serialise(ctx, "users", updated)
        if rejected and ctx.policy.leak_schema_hints:
            payload["_ignored_fields"] = sorted(rejected)
        return await ctx.respond(payload, endpoint=ENDPOINTS["user_me"])

    @router.get("/users/{user_id}", summary="Retrieve a user by identifier")
    async def get_user(user_id: str, ctx: DecoyContext = Ctx) -> Response:
        injected = _sqli_attempt(user_id)
        if injected and weakness_unlocked("SQL_INJECTION", ctx.policy):
            return await ctx.respond_error(
                errors.sql_injection_error(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    collection="users",
                    injected_value=user_id,
                ),
                endpoint=ENDPOINTS["user_me"],
            )

        obj = ctx.store.get_object(ctx.session_id, "users", user_id)
        if obj is None:
            return await ctx.respond_error(
                errors.not_found(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    path=ctx.request.url.path,
                    collection="users",
                    resource_id=user_id,
                ),
                endpoint=ENDPOINTS["user_me"],
            )

        allowed, error = _object_authz(ctx, "users", user_id, obj.owner_id, "IDOR_ACCOUNT")
        if not allowed and error is not None:
            return await ctx.respond_error(error, endpoint=ENDPOINTS["user_me"])
        return await ctx.respond(_serialise(ctx, "users", obj.data), endpoint=ENDPOINTS["user_me"])

    @router.get("/search", summary="Search across visible entities")
    async def search(ctx: DecoyContext = Ctx) -> Response:
        query = ctx.query_value("q")

        injected = _sqli_attempt(query)
        if injected and weakness_unlocked("SQL_INJECTION", ctx.policy):
            return await ctx.respond_error(
                errors.sql_injection_error(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    collection="accounts",
                    injected_value=query,
                ),
                endpoint=ENDPOINTS["search"],
            )

        xss = _xss_attempt(query)
        if xss and weakness_unlocked("REFLECTED_XSS", ctx.policy):
            ctx.note_weakness("REFLECTED_XSS")
            # Reflected verbatim into an HTML error page, unencoded.
            html = (
                "<!doctype html><html><head><title>Search error</title></head>"
                f"<body><h1>No results</h1><p>Your query <em>{query}</em> "
                "returned no matches.</p></body></html>"
            )
            return await ctx.respond_raw(html, status=400, media_type="text/html")

        if not query:
            return await ctx.respond_error(
                errors.bad_request(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    message="Query parameter 'q' is required.",
                    field="q",
                ),
                endpoint=ENDPOINTS["search"],
            )

        needle = query.lower()
        matches: list[dict[str, Any]] = []
        for collection in ("accounts", "users", "transactions", "orders", "products"):
            for obj in ctx.store.list_objects(ctx.session_id, collection, limit=60):
                haystack = " ".join(str(v) for v in obj.data.values()).lower()
                if needle in haystack:
                    matches.append(
                        {
                            "type": collection.rstrip("s"),
                            "id": obj.object_id,
                            "label": str(
                                obj.data.get("full_name")
                                or obj.data.get("iban")
                                or obj.data.get("name")
                                or obj.object_id
                            ),
                        }
                    )
                if len(matches) >= 20:
                    break
        return await ctx.respond(
            {"query": query, "matches": matches, "total": len(matches)},
            endpoint=ENDPOINTS["search"],
        )

    @router.get("/reports/export", summary="Export a statement or report file")
    async def export_report(ctx: DecoyContext = Ctx) -> Response:
        requested = ctx.query_value("file") or ctx.query_value("path") or ctx.query_value("name")

        traversal = _traversal_attempt(requested)
        if traversal and weakness_unlocked("PATH_TRAVERSAL", ctx.policy):
            ctx.note_weakness("PATH_TRAVERSAL")
            return await ctx.respond_raw(
                _fake_file_contents(requested),
                media_type="text/plain",
            )

        injected_cmd = _cmdi_attempt(requested)
        if injected_cmd and weakness_unlocked("COMMAND_INJECTION", ctx.policy):
            ctx.note_weakness("COMMAND_INJECTION")
            return await ctx.respond_raw(
                "uid=1001(nwcb-app) gid=1001(nwcb-app) groups=1001(nwcb-app)\n"
                "statement-export: wrote 0 rows\n",
                media_type="text/plain",
            )

        if not requested:
            return await ctx.respond(
                {
                    "available": [
                        "statement-2026-07.pdf",
                        "statement-2026-08.pdf",
                        "transactions-ytd.csv",
                    ],
                    "hint": "supply ?file=<name>",
                },
                endpoint=ENDPOINTS["export"],
            )
        return await ctx.respond_error(
            errors.not_found(
                policy=ctx.policy,
                session_id=ctx.session_id,
                seq=ctx.seq,
                path=ctx.request.url.path,
                collection="",
                resource_id=requested,
            ),
            endpoint=ENDPOINTS["export"],
        )

    @router.post("/webhooks", summary="Register a webhook subscription")
    async def register_webhook(ctx: DecoyContext = Ctx) -> Response:
        unauthorised = _require_auth(ctx)
        if unauthorised is not None:
            return await ctx.respond_error(unauthorised, endpoint=ENDPOINTS["webhook"])

        body = ctx.json_body() or {}
        url = (
            str(body.get("url") or body.get("callback_url") or "") if isinstance(body, dict) else ""
        )
        events = body.get("events") if isinstance(body, dict) else None

        ssrf = _ssrf_attempt(url)
        if ssrf and weakness_unlocked("SSRF_WEBHOOK", ctx.policy):
            ctx.note_weakness("SSRF_WEBHOOK")
            # The seeded flaw: the service validates the callback by fetching it
            # and returns the upstream response body in the error detail.
            return await ctx.respond(
                {
                    "error": "webhook_validation_failed",
                    "message": "Callback verification request did not return 2xx.",
                    "url": url,
                    "upstream_status": 200,
                    "upstream_body": _fake_ssrf_body(url),
                },
                status=502,
                endpoint=ENDPOINTS["webhook"],
            )

        if not url.startswith(("http://", "https://")):
            return await ctx.respond_error(
                errors.bad_request(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    message="Field 'url' must be an absolute http(s) URL.",
                    field="url",
                ),
                endpoint=ENDPOINTS["webhook"],
            )

        subscription_id = f"whk_{ctx.store.next_counter(ctx.session_id, 'webhooks', start=1):04d}"
        record = {
            "id": subscription_id,
            "url": url,
            "events": events if isinstance(events, list) else ["transaction.booked"],
            "status": "pending_verification",
            "secret_prefix": "whsec_" + subscription_id[-4:],
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        ctx.store.put_object(
            ctx.session_id,
            "webhooks",
            subscription_id,
            record,
            owner_id=ctx.auth.user_id,
        )
        return await ctx.respond(record, status=201, endpoint=ENDPOINTS["webhook"])

    @router.get("/debug", summary="Runtime diagnostics", include_in_schema=False)
    async def debug(ctx: DecoyContext = Ctx) -> Response:
        if not weakness_unlocked("DEBUG_ENDPOINT", ctx.policy):
            return await ctx.respond_error(
                errors.not_found(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    path=ctx.request.url.path,
                ),
                allow_llm=False,
            )
        ctx.note_weakness("DEBUG_ENDPOINT")
        config = ctx.store.get_object(ctx.session_id, "config", "runtime")
        payload = dict(config.data) if config else {}
        payload["diagnostic_hint"] = canary_hint(ctx.session_id)
        return await ctx.respond(payload, endpoint={"summary": "diagnostics"})

    return router


def build_fintech_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["banking"])

    @router.get("/accounts", summary="List accounts")
    async def list_accounts(ctx: DecoyContext = Ctx) -> Response:
        user = _current_user(ctx)
        if user is None:
            return await ctx.respond_error(
                _require_auth(ctx)
                or errors.unauthorized(policy=ctx.policy, session_id=ctx.session_id, seq=ctx.seq),
                endpoint=ENDPOINTS["account_list"],
            )
        limit, offset, truncated = _page(ctx)

        # A correct implementation scopes the listing to the principal. The
        # seeded flaw here is scope-by-parameter: owner_id is client-supplied.
        owner_filter: str | None = user["id"]
        requested_owner = ctx.query_value("owner_id")
        if requested_owner and requested_owner != user["id"]:
            if weakness_unlocked("IDOR_ACCOUNT", ctx.policy):
                ctx.note_weakness("IDOR_ACCOUNT")
                owner_filter = requested_owner
            else:
                return await ctx.respond_error(
                    errors.forbidden(
                        policy=ctx.policy,
                        session_id=ctx.session_id,
                        seq=ctx.seq,
                        required_scope="accounts:read:any",
                    ),
                    endpoint=ENDPOINTS["account_list"],
                )
        if ctx.query_value("all") in ("1", "true", "yes") and weakness_unlocked(
            "IDOR_ACCOUNT", ctx.policy
        ):
            ctx.note_weakness("IDOR_ACCOUNT")
            owner_filter = None

        objects = ctx.store.list_objects(
            ctx.session_id, "accounts", owner_id=owner_filter, limit=limit, offset=offset
        )
        total = (
            ctx.store.count_objects(ctx.session_id, "accounts")
            if owner_filter is None
            else len(
                ctx.store.list_objects(ctx.session_id, "accounts", owner_id=owner_filter, limit=500)
            )
        )
        payload: dict[str, Any] = {
            "items": [_serialise(ctx, "accounts", o.data) for o in objects],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
        if truncated and ctx.policy.leak_schema_hints:
            payload["_note"] = f"limit capped at {limit}"
        return await ctx.respond(payload, endpoint=ENDPOINTS["account_list"])

    @router.get("/accounts/{account_id}", summary="Retrieve one account")
    async def get_account(account_id: str, ctx: DecoyContext = Ctx) -> Response:
        injected = _sqli_attempt(account_id)
        if injected and weakness_unlocked("SQL_INJECTION", ctx.policy):
            return await ctx.respond_error(
                errors.sql_injection_error(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    collection="accounts",
                    injected_value=account_id,
                ),
                endpoint=ENDPOINTS["account_get"],
            )

        obj = ctx.store.get_object(ctx.session_id, "accounts", account_id)
        if obj is None:
            return await ctx.respond_error(
                errors.not_found(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    path=ctx.request.url.path,
                    collection="accounts",
                    resource_id=account_id,
                ),
                endpoint=ENDPOINTS["account_get"],
            )

        allowed, error = _object_authz(ctx, "accounts", account_id, obj.owner_id, "IDOR_ACCOUNT")
        if not allowed and error is not None:
            return await ctx.respond_error(error, endpoint=ENDPOINTS["account_get"])

        payload = _serialise(ctx, "accounts", obj.data)
        payload["links"] = {
            "transactions": f"/api/v1/accounts/{account_id}/transactions",
            "cards": f"/api/v1/accounts/{account_id}/cards",
        }
        return await ctx.respond(payload, endpoint=ENDPOINTS["account_get"])

    @router.get("/accounts/{account_id}/transactions", summary="List transactions for an account")
    async def account_transactions(account_id: str, ctx: DecoyContext = Ctx) -> Response:
        return await _transactions_for(ctx, account_id)

    @router.get("/transactions", summary="List transactions")
    async def list_transactions(ctx: DecoyContext = Ctx) -> Response:
        account_id = ctx.query_value("account_id")
        if not account_id:
            return await ctx.respond_error(
                errors.bad_request(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    message="Query parameter 'account_id' is required.",
                    field="account_id",
                ),
                endpoint=ENDPOINTS["transaction_list"],
            )
        return await _transactions_for(ctx, account_id)

    @router.get("/accounts/{account_id}/cards", summary="List cards for an account")
    async def account_cards(account_id: str, ctx: DecoyContext = Ctx) -> Response:
        account = ctx.store.get_object(ctx.session_id, "accounts", account_id)
        if account is None:
            return await ctx.respond_error(
                errors.not_found(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    path=ctx.request.url.path,
                    collection="accounts",
                    resource_id=account_id,
                ),
            )
        allowed, error = _object_authz(
            ctx, "accounts", account_id, account.owner_id, "IDOR_ACCOUNT"
        )
        if not allowed and error is not None:
            return await ctx.respond_error(error)

        cards = [
            _serialise(ctx, "cards", o.data)
            for o in ctx.store.list_objects(ctx.session_id, "cards", limit=100)
            if str(o.data.get("account_id")) == str(account_id)
        ]
        return await ctx.respond(
            {"items": cards, "total": len(cards)},
            endpoint={"summary": "card list", "returns": "items array of card objects"},
        )

    @router.post("/transfers", summary="Initiate an internal transfer")
    async def create_transfer(ctx: DecoyContext = Ctx) -> Response:
        unauthorised = _require_auth(ctx)
        if unauthorised is not None:
            return await ctx.respond_error(unauthorised, endpoint=ENDPOINTS["transfer"])

        body = ctx.json_body()
        if not isinstance(body, dict):
            return await ctx.respond_error(
                errors.bad_request(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    message="Request body must be a JSON object.",
                ),
                endpoint=ENDPOINTS["transfer"],
            )

        source_id = str(body.get("from_account") or body.get("source_account_id") or "")
        target_id = str(body.get("to_account") or body.get("destination_account_id") or "")
        try:
            amount_minor = int(body.get("amount_minor") or body.get("amount") or 0)
        except (TypeError, ValueError):
            amount_minor = -1

        if not source_id or not target_id or amount_minor <= 0:
            return await ctx.respond_error(
                errors.bad_request(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    message="from_account, to_account and a positive amount_minor are required.",
                ),
                endpoint=ENDPOINTS["transfer"],
            )

        source = ctx.store.get_object(ctx.session_id, "accounts", source_id)
        if source is None:
            return await ctx.respond_error(
                errors.not_found(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    path=ctx.request.url.path,
                    collection="accounts",
                    resource_id=source_id,
                ),
                endpoint=ENDPOINTS["transfer"],
            )

        allowed, error = _object_authz(
            ctx, "accounts", source_id, source.owner_id, "SENSITIVE_BUSINESS_FLOW"
        )
        if not allowed and error is not None:
            return await ctx.respond_error(error, endpoint=ENDPOINTS["transfer"])

        available = int(source.data.get("available_minor", 0))
        if amount_minor > available and not weakness_unlocked(
            "SENSITIVE_BUSINESS_FLOW", ctx.policy
        ):
            return await ctx.respond_error(
                errors.render_error(
                    code="insufficient_funds",
                    message="Available balance is lower than the requested amount.",
                    status=422,
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    extra={"available_minor": available},
                ),
                endpoint=ENDPOINTS["transfer"],
            )
        if amount_minor > available:
            # The seeded flaw: no velocity limit and no balance ceiling, so the
            # fake ledger can be driven negative.
            ctx.note_weakness("SENSITIVE_BUSINESS_FLOW")

        # Commit the state change so a later GET reflects it. This is the
        # cross-request consistency the synopsis calls out as the hard part.
        new_balance = int(source.data.get("balance_minor", 0)) - amount_minor
        source_data = dict(source.data)
        source_data["balance_minor"] = new_balance
        source_data["available_minor"] = new_balance
        ctx.store.put_object(
            ctx.session_id, "accounts", source_id, source_data, owner_id=source.owner_id
        )

        target = ctx.store.get_object(ctx.session_id, "accounts", target_id)
        if target is not None:
            target_data = dict(target.data)
            target_data["balance_minor"] = int(target_data.get("balance_minor", 0)) + amount_minor
            target_data["available_minor"] = target_data["balance_minor"]
            ctx.store.put_object(
                ctx.session_id, "accounts", target_id, target_data, owner_id=target.owner_id
            )

        sequence = ctx.store.next_counter(ctx.session_id, "transfers", start=1)
        transfer_id = f"trf_{sequence:06d}"
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        txn_id = f"txn_{ctx.session_id[:6]}{sequence:04d}"
        ctx.store.put_object(
            ctx.session_id,
            "transactions",
            txn_id,
            {
                "id": txn_id,
                "account_id": source_id,
                "direction": "debit",
                "amount_minor": amount_minor,
                "currency": source_data.get("currency", "EUR"),
                "counterparty_name": "Internal transfer",
                "counterparty_iban": (target.data.get("iban") if target else "external"),
                "category": "transfer",
                "status": "booked",
                "booked_at": now,
                "description": f"Transfer {transfer_id}",
                "fraud_score": 0.0,
                "processor_ref": f"PSP-{transfer_id}",
                "internal_notes": "",
            },
            owner_id=source.owner_id,
        )

        payload = {
            "id": transfer_id,
            "status": "booked",
            "amount_minor": amount_minor,
            "currency": source_data.get("currency", "EUR"),
            "from_account": source_id,
            "to_account": target_id,
            "booked_at": now,
            "resulting_balance_minor": new_balance,
            "transaction_id": txn_id,
        }
        return await ctx.respond(payload, status=201, endpoint=ENDPOINTS["transfer"])

    return router


async def _transactions_for(ctx: DecoyContext, account_id: str) -> Response:
    injected = _sqli_attempt(account_id)
    if injected and weakness_unlocked("SQL_INJECTION", ctx.policy):
        return await ctx.respond_error(
            errors.sql_injection_error(
                policy=ctx.policy,
                session_id=ctx.session_id,
                seq=ctx.seq,
                collection="transactions",
                injected_value=account_id,
            ),
            endpoint=ENDPOINTS["transaction_list"],
        )

    account = ctx.store.get_object(ctx.session_id, "accounts", account_id)
    if account is None:
        return await ctx.respond_error(
            errors.not_found(
                policy=ctx.policy,
                session_id=ctx.session_id,
                seq=ctx.seq,
                path=ctx.request.url.path,
                collection="accounts",
                resource_id=account_id,
            ),
            endpoint=ENDPOINTS["transaction_list"],
        )

    allowed, error = _object_authz(
        ctx, "transactions", account_id, account.owner_id, "IDOR_TRANSACTION"
    )
    if not allowed and error is not None:
        return await ctx.respond_error(error, endpoint=ENDPOINTS["transaction_list"])

    limit, offset, _ = _page(ctx)
    rows = [
        o
        for o in ctx.store.list_objects(ctx.session_id, "transactions", limit=500)
        if str(o.data.get("account_id")) == str(account_id)
    ]
    rows.sort(key=lambda o: str(o.data.get("booked_at", "")), reverse=True)
    window = rows[offset : offset + limit]
    payload = {
        "items": [_serialise(ctx, "transactions", o.data) for o in window],
        "total": len(rows),
        "limit": limit,
        "offset": offset,
        "account_id": account_id,
    }
    return await ctx.respond(payload, endpoint=ENDPOINTS["transaction_list"])


def build_ecommerce_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["commerce"])

    @router.get("/products", summary="List catalogue products")
    async def list_products(ctx: DecoyContext = Ctx) -> Response:
        limit, offset, _ = _page(ctx)
        objects = ctx.store.list_objects(ctx.session_id, "products", limit=limit, offset=offset)
        return await ctx.respond(
            {
                "items": [_serialise(ctx, "products", o.data) for o in objects],
                "total": ctx.store.count_objects(ctx.session_id, "products"),
                "limit": limit,
                "offset": offset,
            },
            endpoint={"summary": "product list", "returns": "items array of products"},
        )

    @router.get("/products/{product_id}", summary="Retrieve one product")
    async def get_product(product_id: str, ctx: DecoyContext = Ctx) -> Response:
        injected = _sqli_attempt(product_id)
        if injected and weakness_unlocked("SQL_INJECTION", ctx.policy):
            return await ctx.respond_error(
                errors.sql_injection_error(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    collection="products",
                    injected_value=product_id,
                )
            )
        obj = ctx.store.get_object(ctx.session_id, "products", product_id)
        if obj is None:
            return await ctx.respond_error(
                errors.not_found(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    path=ctx.request.url.path,
                    collection="products",
                    resource_id=product_id,
                )
            )
        return await ctx.respond(_serialise(ctx, "products", obj.data))

    @router.get("/orders", summary="List orders for the principal")
    async def list_orders(ctx: DecoyContext = Ctx) -> Response:
        user = _current_user(ctx)
        if user is None:
            return await ctx.respond_error(
                _require_auth(ctx)
                or errors.unauthorized(policy=ctx.policy, session_id=ctx.session_id, seq=ctx.seq)
            )
        limit, offset, _ = _page(ctx)
        objects = ctx.store.list_objects(
            ctx.session_id, "orders", owner_id=user["id"], limit=limit, offset=offset
        )
        return await ctx.respond(
            {
                "items": [_serialise(ctx, "orders", o.data) for o in objects],
                "total": len(objects),
                "limit": limit,
                "offset": offset,
            }
        )

    @router.get("/orders/{order_id}", summary="Retrieve one order")
    async def get_order(order_id: str, ctx: DecoyContext = Ctx) -> Response:
        obj = ctx.store.get_object(ctx.session_id, "orders", order_id)
        if obj is None:
            return await ctx.respond_error(
                errors.not_found(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    path=ctx.request.url.path,
                    collection="orders",
                    resource_id=order_id,
                )
            )
        allowed, error = _object_authz(ctx, "orders", order_id, obj.owner_id, "IDOR_ACCOUNT")
        if not allowed and error is not None:
            return await ctx.respond_error(error)
        return await ctx.respond(_serialise(ctx, "orders", obj.data))

    return router


def build_admin_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/admin", tags=["admin"], include_in_schema=False)

    @router.get("", summary="Administrative index")
    @router.get("/", summary="Administrative index")
    async def admin_index(ctx: DecoyContext = Ctx) -> Response:
        gate = _admin_gate(ctx)
        if gate is not None:
            return await ctx.respond_error(gate, endpoint=ENDPOINTS["admin"])
        return await ctx.respond(
            {
                "routes": [
                    "/api/v1/admin/users",
                    "/api/v1/admin/config",
                    "/api/v1/admin/api-keys",
                    "/api/v1/admin/audit",
                ],
                "operator": ctx.auth.user_id,
                "role": ctx.auth.role,
            },
            endpoint=ENDPOINTS["admin"],
        )

    @router.get("/users", summary="List all users")
    async def admin_users(ctx: DecoyContext = Ctx) -> Response:
        gate = _admin_gate(ctx)
        if gate is not None:
            return await ctx.respond_error(gate, endpoint=ENDPOINTS["admin"])
        limit, offset, _ = _page(ctx)
        objects = ctx.store.list_objects(ctx.session_id, "users", limit=limit, offset=offset)
        # An administrative listing that serialises whole records is the classic
        # excessive-exposure bug, and here it leaks the seeded password hashes.
        leak = weakness_unlocked("EXCESSIVE_DATA_EXPOSURE", ctx.policy)
        if leak:
            ctx.note_weakness("EXCESSIVE_DATA_EXPOSURE")
        return await ctx.respond(
            {
                "items": [public_view("users", o.data, leak_internal=leak) for o in objects],
                "total": ctx.store.count_objects(ctx.session_id, "users"),
                "limit": limit,
                "offset": offset,
            },
            endpoint=ENDPOINTS["admin"],
        )

    @router.get("/config", summary="Runtime configuration")
    async def admin_config(ctx: DecoyContext = Ctx) -> Response:
        gate = _admin_gate(ctx)
        if gate is not None:
            return await ctx.respond_error(gate, endpoint=ENDPOINTS["admin"])
        config = ctx.store.get_object(ctx.session_id, "config", "runtime")
        ctx.note_weakness("DEBUG_ENDPOINT")
        return await ctx.respond(dict(config.data) if config else {}, endpoint=ENDPOINTS["admin"])

    @router.get("/api-keys", summary="List integration API keys")
    async def admin_api_keys(ctx: DecoyContext = Ctx) -> Response:
        gate = _admin_gate(ctx)
        if gate is not None:
            return await ctx.respond_error(gate, endpoint=ENDPOINTS["admin"])
        objects = ctx.store.list_objects(ctx.session_id, "api_keys", limit=50)
        reveal = weakness_unlocked("HONEY_CREDENTIALS", ctx.policy)
        if reveal:
            ctx.note_weakness("HONEY_CREDENTIALS")
        return await ctx.respond(
            {
                "items": [public_view("api_keys", o.data, leak_internal=reveal) for o in objects],
                "total": len(objects),
            },
            endpoint=ENDPOINTS["admin"],
        )

    @router.get("/audit", summary="Recent administrative audit entries")
    async def admin_audit(ctx: DecoyContext = Ctx) -> Response:
        gate = _admin_gate(ctx)
        if gate is not None:
            return await ctx.respond_error(gate, endpoint=ENDPOINTS["admin"])
        entries = [
            {
                "id": f"aud_{event.seq:05d}",
                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(event.ts)),
                "actor": ctx.auth.user_id or "anonymous",
                "action": f"{event.method} {event.path}",
                "result": event.status_code,
            }
            for event in ctx.store.get_events(ctx.session_id, limit=20)
        ]
        return await ctx.respond(
            {"items": entries, "total": len(entries)}, endpoint=ENDPOINTS["admin"]
        )

    return router


def build_shadow_router() -> APIRouter:
    """Deprecated v0 surface (``SHADOW_API_VERSION``).

    Mirrors the v1 account routes but predates the authorization fixes, so
    object access is unchecked. Reserved for high-skill sessions: finding a
    forgotten API version is a satisfying, realistic win, and it is not the
    kind of thing a wordlist scanner would recognise as significant.
    """
    router = APIRouter(prefix="/api/v0", tags=["deprecated"], include_in_schema=False)

    @router.get("/accounts/{account_id}", summary="Retrieve one account (deprecated)")
    async def v0_account(account_id: str, ctx: DecoyContext = Ctx) -> Response:
        if not weakness_unlocked("SHADOW_API_VERSION", ctx.policy):
            return await ctx.respond_error(
                errors.not_found(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    path=ctx.request.url.path,
                ),
                allow_llm=False,
            )
        obj = ctx.store.get_object(ctx.session_id, "accounts", account_id)
        if obj is None:
            return await ctx.respond_error(
                errors.not_found(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    path=ctx.request.url.path,
                    collection="accounts",
                    resource_id=account_id,
                )
            )
        ctx.note_weakness("SHADOW_API_VERSION", "IDOR_ACCOUNT")
        return await ctx.respond(
            public_view("accounts", obj.data, leak_internal=True),
            endpoint={"summary": "deprecated account read", "returns": "account object"},
            headers={
                "deprecation": "true",
                "sunset": "Wed, 31 Dec 2025 23:59:59 GMT",
            },
        )

    @router.get("/accounts", summary="List all accounts (deprecated)")
    async def v0_accounts(ctx: DecoyContext = Ctx) -> Response:
        if not weakness_unlocked("SHADOW_API_VERSION", ctx.policy):
            return await ctx.respond_error(
                errors.not_found(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    path=ctx.request.url.path,
                ),
                allow_llm=False,
            )
        ctx.note_weakness("SHADOW_API_VERSION", "IDOR_ACCOUNT", "EXCESSIVE_DATA_EXPOSURE")
        limit, offset, _ = _page(ctx)
        objects = ctx.store.list_objects(ctx.session_id, "accounts", limit=limit, offset=offset)
        return await ctx.respond(
            {
                "accounts": [public_view("accounts", o.data, leak_internal=True) for o in objects],
                "count": ctx.store.count_objects(ctx.session_id, "accounts"),
            },
            headers={"deprecation": "true"},
        )

    return router


# ---------------------------------------------------------------------------
# canned artefacts for the file-read weaknesses
# ---------------------------------------------------------------------------


def _fake_file_contents(requested: str) -> str:
    """Synthetic contents for a traversal read, chosen by target filename."""
    target = requested.lower()
    if "passwd" in target:
        return (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "nwcb-app:x:1001:1001:Northwind API:/srv/nwcb-core:/bin/false\n"
            "postgres:x:1002:1002:PostgreSQL:/var/lib/postgresql:/bin/bash\n"
        )
    if "environ" in target:
        return (
            "PATH=/usr/local/bin:/usr/bin:/bin\x00"
            "DATABASE_URL=postgresql://nwcb_app:REDACTED@pg-core-01.internal.nwcb.test:5432/core\x00"
            "REDIS_URL=redis://cache-01.internal.nwcb.test:6379/2\x00"
            "JWT_SIGNING_KEY=nwcb_jwt_2f8a41c9e77b4d1a\x00"
            "LEDGER_SERVICE=http://ledger-internal.nwcb.test:8080\x00"
        )
    if "shadow" in target:
        return (
            "root:$6$rounds=656000$synthetic$0kQ1cGkR:19700:0:99999:7:::\n"
            "nwcb-app:!:19700:0:99999:7:::\n"
        )
    return (
        "# northwind core configuration (managed by ansible)\n"
        "[database]\n"
        "host = pg-core-01.internal.nwcb.test\n"
        "user = nwcb_app\n"
        "[ledger]\n"
        "endpoint = http://ledger-internal.nwcb.test:8080\n"
    )


def _fake_ssrf_body(url: str) -> str:
    """Synthetic upstream body for a successful SSRF probe."""
    lowered = url.lower()
    if "169.254.169.254" in lowered or "metadata" in lowered:
        return (
            '{"Code":"Success","Type":"AWS-HMAC",'
            '"AccessKeyId":"ASIA5EXAMPLESYNTHETIC",'
            '"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYSYNTHETIC",'
            '"Token":"IQoJb3JpZ2luX2VjEXAMPLE...","Expiration":"2026-09-01T04:12:33Z"}'
        )
    if "ledger-internal" in lowered or ":8080" in lowered:
        return '{"service":"ledger","version":"4.2.0","status":"ok","auth":"mtls-disabled"}'
    if "localhost" in lowered or "127.0.0.1" in lowered:
        return (
            '{"service":"northwind-core-api","health":"ok",'
            '"internal_routes":["/metrics","/admin/flush","/debug/pprof"]}'
        )
    return '{"status":"ok"}'
