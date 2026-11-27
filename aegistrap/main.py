"""AegisTrap application entry point.

Run with::

    python -m aegistrap --host 0.0.0.0 --port 8000

Use that entrypoint rather than invoking ``uvicorn`` directly: it disables
Uvicorn's own ``Server`` header, which the application cannot strip and which
would otherwise identify the honeypot's runtime. See :mod:`aegistrap.__main__`.

Route registration order matters. The catch-all is registered last so that it
absorbs every request the documented surface does not claim — unknown paths,
unsupported methods, preflights, wordlist probes. Without it, Starlette's own
404 and 405 bodies would reach the attacker, and those bodies identify the
framework immediately.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import AsyncIterator

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from aegistrap.app_state import AppRuntime, SessionSweeper, build_runtime, shutdown_runtime
from aegistrap.config import Settings, get_settings
from aegistrap.dashboard import build_dashboard_router
from aegistrap.decoy import errors
from aegistrap.decoy.context import DecoyContext, build_context
from aegistrap.decoy.graphql import build_graphql_router, schema_sdl
from aegistrap.decoy.policy import weakness_unlocked
from aegistrap.decoy.rest import (
    build_admin_router,
    build_common_router,
    build_ecommerce_router,
    build_fintech_router,
    build_shadow_router,
)
from aegistrap.logging_setup import configure_logging, get_logger
from aegistrap.profiler.service import ProfilerMode

log = get_logger("main")

#: Methods the catch-all answers, so nothing falls through to the framework.
_ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


def create_app(
    settings: Settings | None = None,
    *,
    profiler_mode: ProfilerMode | None = None,
    runtime: AppRuntime | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    @contextlib.asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.runtime = runtime or build_runtime(settings, profiler_mode=profiler_mode)
        sweeper = SessionSweeper(application.state.runtime)
        application.state.sweeper = sweeper
        sweeper.start()
        log.info("AegisTrap ready (persona=%s)", settings.persona)
        try:
            yield
        finally:
            await sweeper.stop()
            if runtime is None:
                await shutdown_runtime(application.state.runtime)

    app = FastAPI(
        title=settings.service_name,
        version=settings.service_version,
        description=(
            "Northwind Capital public API. Account, transaction, and payment "
            "operations for retail and business customers."
        ),
        # The framework's own docs endpoints are replaced with instrumented
        # equivalents so that fetching the schema is captured as attacker
        # reconnaissance rather than served silently.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    app.include_router(build_common_router())
    if settings.persona == "ecommerce":
        app.include_router(build_ecommerce_router())
    else:
        app.include_router(build_fintech_router())
    app.include_router(build_admin_router())
    app.include_router(build_shadow_router())
    app.include_router(build_graphql_router())

    if settings.dashboard_enabled:
        app.include_router(build_dashboard_router())

    _register_meta_routes(app, settings)
    _register_exception_handlers(app)
    _register_catch_all(app)
    return app


def _register_meta_routes(app: FastAPI, settings: Settings) -> None:
    ctx_dep = Depends(build_context)

    @app.get("/", include_in_schema=False, name="service_root")
    async def root(ctx: DecoyContext = ctx_dep) -> Response:
        payload = {
            "service": settings.service_name,
            "version": settings.service_version,
            "documentation": "/docs",
            "openapi": "/openapi.json",
            "graphql": "/graphql",
            "status": "operational",
        }
        return await ctx.respond(
            payload,
            endpoint={"summary": "service index", "returns": "service descriptor"},
            allow_llm=False,
        )

    @app.get("/openapi.json", include_in_schema=False)
    async def openapi_document(ctx: DecoyContext = ctx_dep) -> Response:
        # A public machine-readable inventory is itself a finding (API9:2023).
        ctx.note_weakness("OPENAPI_EXPOSED")
        schema = app.openapi()
        return await ctx.respond(
            schema,
            endpoint={"summary": "OpenAPI document"},
            allow_llm=False,
        )

    @app.get("/docs", include_in_schema=False)
    async def docs(ctx: DecoyContext = ctx_dep) -> Response:
        ctx.note_weakness("OPENAPI_EXPOSED")
        html = (
            "<!doctype html><html><head><title>"
            f"{settings.service_name} - API reference</title>"
            '<meta charset="utf-8"><meta name="viewport" content="width=device-width,'
            ' initial-scale=1">'
            '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">'
            '</head><body><div id="swagger-ui"></div>'
            '<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>'
            "<script>window.onload=function(){SwaggerUIBundle({url:'/openapi.json',"
            "dom_id:'#swagger-ui'});};</script></body></html>"
        )
        return await ctx.respond_raw(html, media_type="text/html")

    @app.get("/graphql/schema", include_in_schema=False)
    async def graphql_schema(ctx: DecoyContext = ctx_dep) -> Response:
        if not weakness_unlocked("GRAPHQL_INTROSPECTION", ctx.policy):
            return await ctx.respond_error(
                errors.not_found(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    path=ctx.request.url.path,
                ),
                allow_llm=False,
            )
        ctx.note_weakness("GRAPHQL_INTROSPECTION")
        return await ctx.respond_raw(schema_sdl(), media_type="text/plain")

    @app.get("/.well-known/security.txt", include_in_schema=False)
    async def security_txt(ctx: DecoyContext = ctx_dep) -> Response:
        body = (
            "Contact: mailto:security@northwind.test\n"
            "Expires: 2027-01-01T00:00:00.000Z\n"
            "Preferred-Languages: en\n"
            "Canonical: https://api.northwind.test/.well-known/security.txt\n"
        )
        return await ctx.respond_raw(body, media_type="text/plain")


def _register_exception_handlers(app: FastAPI) -> None:
    """Replace every framework-generated error body with a decoy one."""

    async def decoy_error_response(
        request: Request, status: int, code: str, message: str
    ) -> Response:
        try:
            ctx = await build_context(request)
        except Exception:
            return JSONResponse({"error": code}, status_code=status)
        return await ctx.respond_error(
            errors.render_error(
                code=code,
                message=message,
                status=status,
                policy=ctx.policy,
                session_id=ctx.session_id,
                seq=ctx.seq,
            ),
            allow_llm=False,
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception(request: Request, exc: StarletteHTTPException) -> Response:
        mapping = {
            404: ("not_found", "The requested path does not exist on this service."),
            405: ("method_not_allowed", "That method is not supported for this resource."),
            401: ("unauthorized", "Authorization is required for this endpoint."),
            403: ("forbidden", "This principal is not permitted to perform that action."),
        }
        code, message = mapping.get(
            exc.status_code, ("request_failed", str(exc.detail or "Request failed."))
        )
        return await decoy_error_response(request, exc.status_code, code, message)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> Response:
        del exc
        return await decoy_error_response(
            request, 400, "invalid_request", "The request could not be validated."
        )

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception) -> Response:
        log.exception("unhandled error serving %s %s", request.method, request.url.path)
        del exc
        return await decoy_error_response(
            request, 500, "internal_error", "Unhandled exception while resolving request."
        )


def _collect_route_methods(app: FastAPI) -> list[tuple[re.Pattern[str], set[str]]]:
    """Flatten the route tree into (path pattern, allowed methods) pairs.

    Needed so the catch-all can answer a known path with an unsupported method
    as ``405 Method Not Allowed`` and a correct ``Allow`` header, the way a real
    service does. Returning 404 there would be a subtle but real inconsistency.

    Routers are nested rather than flattened in current FastAPI, so this walks
    ``original_router`` and ``routes`` recursively.
    """
    collected: list[tuple[re.Pattern[str], set[str]]] = []
    seen: set[int] = set()

    def walk(routes: object) -> None:
        for route in routes or ():  # type: ignore[union-attr]
            if id(route) in seen:
                continue
            seen.add(id(route))
            nested = getattr(route, "original_router", None)
            if nested is not None:
                walk(getattr(nested, "routes", ()))
                continue
            if hasattr(route, "routes"):
                walk(route.routes)
                continue
            pattern = getattr(route, "path_regex", None)
            methods = getattr(route, "methods", None)
            name = getattr(route, "name", "")
            if pattern is None or not methods or name == "catch_all":
                continue
            collected.append((pattern, {m.upper() for m in methods}))

    walk(app.routes)
    return collected


def _register_catch_all(app: FastAPI) -> None:
    ctx_dep = Depends(build_context)
    method_index: list[tuple[re.Pattern[str], set[str]]] = []

    def allowed_methods_for(path: str) -> set[str]:
        nonlocal method_index
        if not method_index:
            method_index = _collect_route_methods(app)
        allowed: set[str] = set()
        for pattern, methods in method_index:
            if pattern.fullmatch(path) or pattern.match(path):
                allowed |= methods
        return allowed

    @app.api_route(
        "/{full_path:path}",
        methods=_ALL_METHODS,
        include_in_schema=False,
        name="catch_all",
    )
    async def catch_all(full_path: str, ctx: DecoyContext = ctx_dep) -> Response:
        method = ctx.request.method.upper()

        if method == "OPTIONS":
            return await ctx.respond_raw(
                "",
                status=204,
                media_type="text/plain",
                headers={
                    "allow": ", ".join(_ALL_METHODS),
                    "access-control-allow-methods": ", ".join(_ALL_METHODS),
                    "access-control-allow-headers": "authorization, content-type",
                    "access-control-max-age": "600",
                },
            )

        path = ctx.request.url.path
        allowed = allowed_methods_for(path)
        if allowed and method not in allowed:
            ordered = sorted(allowed | {"OPTIONS"})
            return await ctx.respond_error(
                errors.method_not_allowed(
                    policy=ctx.policy,
                    session_id=ctx.session_id,
                    seq=ctx.seq,
                    method=method,
                    allowed=ordered,
                ),
                allow_llm=False,
                headers={"allow": ", ".join(ordered)},
            )

        # An HTML-looking probe gets an HTML error page; an API probe gets JSON.
        # Mixing the two is a give-away for a service that fronts both.
        accept = ctx.headers.get("accept", "")
        wants_html = "text/html" in accept and "application/json" not in accept

        error = errors.not_found(
            policy=ctx.policy,
            session_id=ctx.session_id,
            seq=ctx.seq,
            path=f"/{full_path}",
        )
        if wants_html:
            return await ctx.respond_raw(
                _html_not_found(f"/{full_path}"),
                status=404,
                media_type="text/html",
                headers={},
            )
        # 404 fanout is the highest-volume traffic a honeypot sees and the least
        # informative, so it never spends a generation call.
        return await ctx.respond_error(error, allow_llm=False)


def _html_not_found(path: str) -> str:
    return (
        "<!doctype html><html><head><title>404 Not Found</title></head><body>"
        "<h1>Not Found</h1><p>The requested URL "
        f"{path} was not found on this server.</p><hr>"
        "<address>Northwind Capital API</address></body></html>"
    )


app = create_app()
