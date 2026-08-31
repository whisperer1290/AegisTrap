"""Decoy GraphQL surface.

The query parser here is hand-rolled rather than delegated to a GraphQL
library, for two reasons that both matter for deception quality:

* **Library errors are fingerprints.** Graphene, Strawberry, and Ariadne each
  emit distinctive validation messages and error envelopes. A honeypot that
  answers a malformed query with a recognisable library error has told the
  attacker which stack it is, and any mismatch with the rest of the emulated
  service is a contradiction.
* **We want the malicious query, not a rejection.** A spec-compliant parser
  rejects a deeply nested or alias-amplified query before we learn anything.
  A tolerant parser lets us record the attempt, measure its depth and
  amplification factor, and answer it the way a misconfigured service would.

The parser is therefore deliberately lenient: it extracts operation type,
selection structure, arguments, aliases, and depth, and skips anything it does
not understand instead of failing.

As in the REST layer, resolution reads authoritative state; the response engine
only dresses the result.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from aegistrap.decoy.context import DecoyContext, build_context
from aegistrap.decoy.policy import weakness_unlocked
from aegistrap.decoy.world import INTERNAL_FIELDS

Ctx = Depends(build_context)

MAX_DEPTH_TOLERATED = 12
DEPTH_ABUSE_THRESHOLD = 8
ALIAS_ABUSE_THRESHOLD = 6

#: Ceiling on parser recursion. Comfortably above :data:`MAX_DEPTH_TOLERATED`
#: so every query the service would really answer is parsed in full, while
#: still bounding stack use on hostile input.
PARSE_DEPTH_LIMIT = 40

_COMMENT_RE = re.compile(r"#[^\n\r]*")
_ARG_RE = re.compile(r"(\w+)\s*:\s*(\"[^\"]*\"|'[^']*'|\$\w+|[^,)\s]+)")
_NAME_RE = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")


# ---------------------------------------------------------------------------
# tolerant parser
# ---------------------------------------------------------------------------


@dataclass
class Selection:
    name: str
    alias: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    children: list[Selection] = field(default_factory=list)

    @property
    def key(self) -> str:
        return self.alias or self.name

    def child_names(self) -> list[str]:
        return [child.name for child in self.children]


@dataclass
class ParsedQuery:
    operation: str = "query"
    operation_name: str = ""
    selections: list[Selection] = field(default_factory=list)
    depth: int = 0
    alias_count: int = 0
    field_count: int = 0
    fragment_count: int = 0
    introspection: bool = False
    parse_error: str = ""
    raw: str = ""


def parse_query(text: str) -> ParsedQuery:
    parsed = ParsedQuery(raw=text or "")
    if not text or not text.strip():
        parsed.parse_error = "No GraphQL query supplied."
        return parsed

    cleaned = _COMMENT_RE.sub("", text)
    parsed.fragment_count = len(re.findall(r"\bfragment\s+\w+\s+on\s+\w+", cleaned))
    parsed.introspection = "__schema" in cleaned or "__type" in cleaned

    header = re.match(r"\s*(query|mutation|subscription)\s*(\w+)?", cleaned)
    if header:
        parsed.operation = header.group(1)
        parsed.operation_name = header.group(2) or ""

    start = cleaned.find("{")
    if start == -1:
        parsed.parse_error = "Syntax Error: expected '{'."
        return parsed

    selections, consumed = _parse_selection_set(cleaned, start)
    if not selections:
        parsed.parse_error = "Syntax Error: empty selection set."
    parsed.selections = selections
    parsed.depth = _measure_depth(cleaned)
    parsed.alias_count = _count_aliases(selections)
    parsed.field_count = _count_fields(selections)
    del consumed
    return parsed


def _parse_selection_set(text: str, open_index: int, depth: int = 0) -> tuple[list[Selection], int]:
    """Parse ``{ ... }`` starting at ``open_index``; returns (selections, end).

    Nesting is capped at :data:`PARSE_DEPTH_LIMIT`. Beyond it the braces are
    skipped without building selections: the point of tolerating an abusive
    query is to record and answer it, and crashing the parser on the attacker's
    input would be a denial of service against the honeypot itself. The real
    depth is measured separately by :func:`_measure_depth`, which counts braces
    iteratively, so the abuse signal survives the cap.
    """
    selections: list[Selection] = []
    index = open_index + 1
    length = len(text)
    guard = 0

    if depth >= PARSE_DEPTH_LIMIT:
        return selections, _skip_balanced(text, open_index)

    while index < length and guard < 20_000:
        guard += 1
        char = text[index]

        if char.isspace() or char in ",":
            index += 1
            continue
        if char == "}":
            return selections, index + 1
        if char == "{":
            # A selection set with no parent field; attach to the last field.
            children, end = _parse_selection_set(text, index, depth + 1)
            if selections:
                selections[-1].children.extend(children)
            index = end
            continue
        if char == ".":  # spread fragment: ...Fields
            match = re.match(r"\.\.\.\s*(on\s+\w+|\w+)?", text[index:])
            index += match.end() if match else 1
            continue
        if char == "@":  # directive
            match = re.match(r"@\w+(\([^)]*\))?", text[index:])
            index += match.end() if match else 1
            continue

        name_match = _NAME_RE.match(text, index)
        if not name_match:
            index += 1
            continue

        first = name_match.group(0)
        index = name_match.end()
        alias = ""
        name = first

        # alias: field
        lookahead = index
        while lookahead < length and text[lookahead].isspace():
            lookahead += 1
        if lookahead < length and text[lookahead] == ":":
            lookahead += 1
            while lookahead < length and text[lookahead].isspace():
                lookahead += 1
            target = _NAME_RE.match(text, lookahead)
            if target:
                alias, name = first, target.group(0)
                index = target.end()

        selection = Selection(name=name, alias=alias)

        # arguments
        cursor = index
        while cursor < length and text[cursor].isspace():
            cursor += 1
        if cursor < length and text[cursor] == "(":
            close = text.find(")", cursor)
            if close != -1:
                selection.args = _parse_args(text[cursor + 1 : close])
                index = close + 1

        # nested selection set
        cursor = index
        while cursor < length and text[cursor].isspace():
            cursor += 1
        if cursor < length and text[cursor] == "{":
            children, end = _parse_selection_set(text, cursor, depth + 1)
            selection.children = children
            index = end

        selections.append(selection)

    return selections, index


def _skip_balanced(text: str, open_index: int) -> int:
    """Return the index just past the ``{...}`` block at ``open_index``."""
    level = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "{":
            level += 1
        elif char == "}":
            level -= 1
            if level == 0:
                return index + 1
    return len(text)


def _parse_args(text: str) -> dict[str, Any]:
    args: dict[str, Any] = {}
    for name, raw in _ARG_RE.findall(text):
        value: Any = raw.strip()
        if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
            value = value[1:-1]
        elif value in ("true", "false"):
            value = value == "true"
        elif value == "null":
            value = None
        else:
            with contextlib.suppress(ValueError):
                value = int(value)
        args[name] = value
    return args


def _measure_depth(text: str) -> int:
    depth = current = 0
    for char in text:
        if char == "{":
            current += 1
            depth = max(depth, current)
        elif char == "}":
            current = max(0, current - 1)
    return depth


def _count_aliases(selections: list[Selection]) -> int:
    return sum((1 if s.alias else 0) + _count_aliases(s.children) for s in selections)


def _count_fields(selections: list[Selection]) -> int:
    return sum(1 + _count_fields(s.children) for s in selections)


# ---------------------------------------------------------------------------
# schema (also the introspection payload)
# ---------------------------------------------------------------------------

_SCHEMA_TYPES: dict[str, dict[str, str]] = {
    "Account": {
        "id": "ID!",
        "iban": "String!",
        "product": "String!",
        "currency": "String!",
        "balanceMinor": "Int!",
        "availableMinor": "Int!",
        "status": "String!",
        "openedAt": "String!",
        "owner": "User",
        "transactions": "[Transaction!]!",
        "ledgerShard": "String",
        "riskBand": "String",
        "internalNotes": "String",
    },
    "User": {
        "id": "ID!",
        "email": "String!",
        "fullName": "String!",
        "role": "String!",
        "status": "String!",
        "mfaEnabled": "Boolean!",
        "phone": "String",
        "city": "String",
        "kycStatus": "String!",
        "createdAt": "String!",
        "accounts": "[Account!]!",
        "passwordHash": "String",
        "riskScore": "Float",
        "internalNotes": "String",
        "amlFlags": "[String!]",
    },
    "Transaction": {
        "id": "ID!",
        "accountId": "ID!",
        "direction": "String!",
        "amountMinor": "Int!",
        "currency": "String!",
        "counterpartyName": "String!",
        "counterpartyIban": "String!",
        "category": "String!",
        "status": "String!",
        "bookedAt": "String!",
        "description": "String",
        "fraudScore": "Float",
        "processorRef": "String",
    },
    "Query": {
        "me": "User",
        "account": "Account",
        "accounts": "[Account!]!",
        "user": "User",
        "users": "[User!]!",
        "transactions": "[Transaction!]!",
        "products": "[Product!]!",
        "orders": "[Order!]!",
    },
}

#: Internal-only GraphQL fields, mirroring the REST layer's hidden columns.
_INTERNAL_GRAPHQL_FIELDS: frozenset[str] = frozenset(
    {
        "ledgerShard",
        "riskBand",
        "internalNotes",
        "passwordHash",
        "riskScore",
        "amlFlags",
        "fraudScore",
        "processorRef",
        "costMinor",
        "marginMinor",
        "supplierRef",
        "panFull",
        "cvv",
    }
)


def _introspection_payload() -> dict[str, Any]:
    return {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "subscriptionType": None,
            "types": [
                {
                    "kind": "OBJECT",
                    "name": type_name,
                    "description": None,
                    "fields": [
                        {
                            "name": field_name,
                            "description": None,
                            "args": [],
                            "type": {"kind": "SCALAR", "name": field_type, "ofType": None},
                            "isDeprecated": False,
                            "deprecationReason": None,
                        }
                        for field_name, field_type in fields.items()
                    ],
                    "interfaces": [],
                    "enumValues": None,
                    "possibleTypes": None,
                }
                for type_name, fields in _SCHEMA_TYPES.items()
            ],
            "directives": [
                {"name": "include", "locations": ["FIELD"], "args": []},
                {"name": "skip", "locations": ["FIELD"], "args": []},
                {"name": "deprecated", "locations": ["FIELD_DEFINITION"], "args": []},
            ],
        }
    }


def schema_sdl() -> str:
    lines: list[str] = []
    for type_name, fields in _SCHEMA_TYPES.items():
        lines.append(f"type {type_name} {{")
        lines.extend(f"  {name}: {kind}" for name, kind in fields.items())
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# resolution
# ---------------------------------------------------------------------------


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(part.title() for part in rest)


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _project(
    ctx: DecoyContext,
    collection: str,
    data: dict[str, Any],
    selection: Selection,
    errors_out: list[dict[str, Any]],
    depth: int = 0,
) -> dict[str, Any]:
    """Resolve one object against the requested selection set."""
    hidden = set(INTERNAL_FIELDS.get(collection, ()))
    leak_allowed = weakness_unlocked("EXCESSIVE_DATA_EXPOSURE", ctx.policy)
    requested = selection.children or []
    if not requested:
        # No sub-selection: a real server would error, but returning the scalar
        # fields is the more useful (and more misconfigured-looking) behaviour.
        return {_camel(k): v for k, v in data.items() if k not in hidden}

    result: dict[str, Any] = {}
    for child in requested:
        snake = _snake(child.name)

        if child.name in ("owner", "user") and collection == "accounts":
            owner = ctx.store.get_object(ctx.session_id, "users", str(data.get("owner_id", "")))
            result[child.key] = (
                _project(ctx, "users", owner.data, child, errors_out, depth + 1) if owner else None
            )
            continue
        if child.name == "accounts" and collection == "users":
            owned = ctx.store.list_objects(
                ctx.session_id, "accounts", owner_id=str(data.get("id", "")), limit=25
            )
            result[child.key] = [
                _project(ctx, "accounts", o.data, child, errors_out, depth + 1) for o in owned
            ]
            continue
        if child.name == "transactions" and collection == "accounts":
            limit = int(child.args.get("limit", 10) or 10)
            rows = [
                o
                for o in ctx.store.list_objects(ctx.session_id, "transactions", limit=500)
                if str(o.data.get("account_id")) == str(data.get("id"))
            ][: max(1, min(limit, 200))]
            result[child.key] = [
                _project(ctx, "transactions", o.data, child, errors_out, depth + 1) for o in rows
            ]
            continue

        if child.name in _INTERNAL_GRAPHQL_FIELDS or snake in hidden:
            if leak_allowed:
                # Object property level authorization is not enforced per field.
                ctx.note_weakness("EXCESSIVE_DATA_EXPOSURE")
                result[child.key] = data.get(snake)
            else:
                result[child.key] = None
                errors_out.append(
                    {
                        "message": f"Field '{child.name}' is not accessible to this principal.",
                        "path": [selection.key, child.key],
                        "extensions": {"code": "FORBIDDEN_FIELD"},
                    }
                )
            continue

        if snake in data:
            result[child.key] = data[snake]
        elif child.name in data:
            result[child.key] = data[child.name]
        else:
            result[child.key] = None
            errors_out.append(
                {
                    "message": f"Cannot query field '{child.name}' on type "
                    f"'{collection.rstrip('s').title()}'.",
                    "path": [selection.key, child.key],
                    "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"},
                }
            )
    return result


def _resolve_root(ctx: DecoyContext, selection: Selection, errors_out: list[dict[str, Any]]) -> Any:
    from aegistrap.decoy.rest import _current_user, _object_authz

    name = selection.name
    store, session_id = ctx.store, ctx.session_id

    if name in ("__schema", "__type"):
        return None  # handled before resolution

    if name == "me":
        user = _current_user(ctx)
        if user is None:
            errors_out.append(
                {
                    "message": "Not authenticated.",
                    "path": [selection.key],
                    "extensions": {"code": "UNAUTHENTICATED"},
                }
            )
            return None
        return _project(ctx, "users", user, selection, errors_out)

    if name == "account":
        account_id = str(selection.args.get("id", ""))
        obj = store.get_object(session_id, "accounts", account_id)
        if obj is None:
            errors_out.append(
                {
                    "message": f"Account '{account_id}' not found.",
                    "path": [selection.key],
                    "extensions": {"code": "NOT_FOUND"},
                }
            )
            return None
        allowed, _error = _object_authz(ctx, "accounts", account_id, obj.owner_id, "IDOR_ACCOUNT")
        if not allowed:
            errors_out.append(
                {
                    "message": "Not authorised for this account.",
                    "path": [selection.key],
                    "extensions": {"code": "FORBIDDEN"},
                }
            )
            return None
        return _project(ctx, "accounts", obj.data, selection, errors_out)

    if name == "accounts":
        limit = _clamp_limit(ctx, selection.args.get("limit"))
        user = _current_user(ctx)
        owner = (
            None
            if weakness_unlocked("IDOR_ACCOUNT", ctx.policy)
            else (user["id"] if user else "__none__")
        )
        if owner is None:
            # The seeded flaw: the root list resolver applies no owner scope.
            ctx.note_weakness("IDOR_ACCOUNT")
        objects = store.list_objects(session_id, "accounts", owner_id=owner, limit=limit)
        return [_project(ctx, "accounts", o.data, selection, errors_out) for o in objects]

    if name == "user":
        user_id = str(selection.args.get("id", ""))
        obj = store.get_object(session_id, "users", user_id)
        if obj is None:
            errors_out.append(
                {
                    "message": f"User '{user_id}' not found.",
                    "path": [selection.key],
                    "extensions": {"code": "NOT_FOUND"},
                }
            )
            return None
        return _project(ctx, "users", obj.data, selection, errors_out)

    if name == "users":
        if not weakness_unlocked("BFLA_ADMIN_ROUTE", ctx.policy) and ctx.auth.role != "admin":
            errors_out.append(
                {
                    "message": "Field 'users' requires the admin role.",
                    "path": [selection.key],
                    "extensions": {"code": "FORBIDDEN"},
                }
            )
            return None
        ctx.note_weakness("BFLA_ADMIN_ROUTE")
        limit = _clamp_limit(ctx, selection.args.get("limit"))
        objects = store.list_objects(session_id, "users", limit=limit)
        return [_project(ctx, "users", o.data, selection, errors_out) for o in objects]

    if name == "transactions":
        account_id = str(selection.args.get("accountId") or selection.args.get("account_id") or "")
        limit = _clamp_limit(ctx, selection.args.get("limit"))
        rows = [
            o
            for o in store.list_objects(session_id, "transactions", limit=500)
            if not account_id or str(o.data.get("account_id")) == account_id
        ][:limit]
        return [_project(ctx, "transactions", o.data, selection, errors_out) for o in rows]

    for collection in ("products", "orders"):
        if name == collection:
            limit = _clamp_limit(ctx, selection.args.get("limit"))
            objects = store.list_objects(session_id, collection, limit=limit)
            return [_project(ctx, collection, o.data, selection, errors_out) for o in objects]

    errors_out.append(
        {
            "message": f"Cannot query field '{name}' on type 'Query'.",
            "path": [selection.key],
            "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"},
        }
    )
    return None


def _clamp_limit(ctx: DecoyContext, raw: Any) -> int:
    try:
        requested = int(raw) if raw is not None else 10
    except (TypeError, ValueError):
        requested = 10
    if requested > ctx.policy.max_page_size:
        if weakness_unlocked("NO_RATE_LIMIT", ctx.policy):
            ctx.note_weakness("NO_RATE_LIMIT")
            return max(1, min(requested, 500))
        return ctx.policy.max_page_size
    return max(1, requested)


# ---------------------------------------------------------------------------
# router
# ---------------------------------------------------------------------------


def build_graphql_router() -> APIRouter:
    router = APIRouter(tags=["graphql"])

    @router.post("/graphql", summary="GraphQL endpoint")
    async def graphql_post(ctx: DecoyContext = Ctx) -> Response:
        body = ctx.json_body()
        if isinstance(body, list):
            # Query batching: an amplification vector in its own right.
            ctx.note_weakness("GRAPHQL_DEPTH_ABUSE")
            results = []
            for item in body[:20]:
                query = str((item or {}).get("query", "")) if isinstance(item, dict) else ""
                results.append(_execute(ctx, query))
            return await ctx.respond(results, endpoint=_ENDPOINT)
        query = ""
        variables: Any = None
        if isinstance(body, dict):
            query = str(body.get("query") or "")
            variables = body.get("variables")
        if not query:
            query = ctx.query_value("query")
        del variables
        return await ctx.respond(_execute(ctx, query), endpoint=_ENDPOINT)

    @router.get("/graphql", summary="GraphQL endpoint (GET form)")
    async def graphql_get(ctx: DecoyContext = Ctx) -> Response:
        return await ctx.respond(_execute(ctx, ctx.query_value("query")), endpoint=_ENDPOINT)

    return router


_ENDPOINT = {
    "summary": "GraphQL endpoint",
    "returns": "GraphQL envelope: data and/or errors, optionally extensions",
    "notes": "Follow the GraphQL over HTTP response shape exactly.",
}


def _execute(ctx: DecoyContext, query_text: str) -> dict[str, Any]:
    """Execute a query against session state, returning a GraphQL envelope."""
    parsed = parse_query(query_text)

    if parsed.parse_error:
        return {
            "errors": [
                {
                    "message": parsed.parse_error,
                    "locations": [{"line": 1, "column": 1}],
                    "extensions": {"code": "GRAPHQL_PARSE_FAILED"},
                }
            ]
        }

    if parsed.depth > MAX_DEPTH_TOLERATED and not weakness_unlocked(
        "GRAPHQL_DEPTH_ABUSE", ctx.policy
    ):
        return {
            "errors": [
                {
                    "message": (
                        f"Query exceeds maximum depth of {MAX_DEPTH_TOLERATED} "
                        f"(received {parsed.depth})."
                    ),
                    "extensions": {"code": "QUERY_TOO_DEEP"},
                }
            ]
        }

    if parsed.depth >= DEPTH_ABUSE_THRESHOLD or parsed.alias_count >= ALIAS_ABUSE_THRESHOLD:
        ctx.note_weakness("GRAPHQL_DEPTH_ABUSE")

    if parsed.introspection:
        if not (
            ctx.policy.expose_graphql_introspection
            and weakness_unlocked("GRAPHQL_INTROSPECTION", ctx.policy)
        ):
            return {
                "errors": [
                    {
                        "message": (
                            "GraphQL introspection is not allowed, but the query "
                            "contained __schema or __type."
                        ),
                        "extensions": {"code": "INTROSPECTION_DISABLED"},
                    }
                ]
            }
        ctx.note_weakness("GRAPHQL_INTROSPECTION")
        return {"data": _introspection_payload()}

    if parsed.operation == "mutation":
        return _execute_mutation(ctx, parsed)

    errors_out: list[dict[str, Any]] = []
    data: dict[str, Any] = {}
    for selection in parsed.selections[:20]:
        data[selection.key] = _resolve_root(ctx, selection, errors_out)

    envelope: dict[str, Any] = {"data": data}
    if errors_out:
        envelope["errors"] = errors_out[:20]
    if parsed.depth >= DEPTH_ABUSE_THRESHOLD and ctx.policy.leak_schema_hints:
        envelope["extensions"] = {
            "cost": {
                "requestedQueryCost": parsed.field_count * max(1, parsed.depth),
                "maximumAvailable": 100_000,
                "actualQueryCost": parsed.field_count * max(1, parsed.depth),
            }
        }
    return envelope


def _execute_mutation(ctx: DecoyContext, parsed: ParsedQuery) -> dict[str, Any]:
    from aegistrap.decoy.rest import _current_user

    errors_out: list[dict[str, Any]] = []
    data: dict[str, Any] = {}

    for selection in parsed.selections[:10]:
        if selection.name in ("updateProfile", "updateUser"):
            user = _current_user(ctx)
            if user is None:
                errors_out.append(
                    {
                        "message": "Not authenticated.",
                        "path": [selection.key],
                        "extensions": {"code": "UNAUTHENTICATED"},
                    }
                )
                data[selection.key] = None
                continue
            updated = dict(user)
            for key, value in selection.args.items():
                snake = _snake(key)
                if snake in ("role", "kyc_status", "status"):
                    if weakness_unlocked("MASS_ASSIGNMENT", ctx.policy):
                        ctx.note_weakness("MASS_ASSIGNMENT")
                        updated[snake] = value
                    else:
                        errors_out.append(
                            {
                                "message": f"Field '{key}' is not writable.",
                                "path": [selection.key],
                                "extensions": {"code": "FORBIDDEN_FIELD"},
                            }
                        )
                elif snake in ("full_name", "phone", "city"):
                    updated[snake] = value
            ctx.store.put_object(
                ctx.session_id,
                "users",
                str(updated["id"]),
                updated,
                owner_id=str(updated["id"]),
            )
            data[selection.key] = _project(ctx, "users", updated, selection, errors_out)
            continue

        errors_out.append(
            {
                "message": f"Cannot query field '{selection.name}' on type 'Mutation'.",
                "path": [selection.key],
                "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"},
            }
        )
        data[selection.key] = None

    envelope: dict[str, Any] = {"data": data}
    if errors_out:
        envelope["errors"] = errors_out[:20]
    return envelope
