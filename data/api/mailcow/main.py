"""FastAPI application: the mailcow UI/API server (replaces php-fpm + all PHP entry points)."""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

import psycopg
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from . import __version__
from .config import settings
from .db import close_pool, get_pool, wait_for_db
from .redisclient import get_redis, wait_for_redis
from .routers import api_v1, internal, ui
from .schema import init_db_schema

logging.basicConfig(level=logging.DEBUG if settings.dev_mode else logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("mailcow")
for _noisy in ("httpx", "httpcore", "asyncio"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

QUARANTINE_DEFAULTS = {
    "Q_RETENTION_SIZE": "10",
    "Q_MAX_SIZE": "10",
    "Q_MAX_AGE": "365",
    "Q_MAX_SCORE": "9999.0",
    "Q_RELEASE_FORMAT": "raw",
    "Q_SENDER": "quarantine@localhost",
    "Q_SUBJ": "Spam Quarantine Notification",
    "Q_EXCLUDE_DOMAINS": "[]",
}


def bootstrap() -> None:
    """Wait for dependencies, create/upgrade the schema and seed Redis defaults."""
    wait_for_db()
    wait_for_redis()
    with psycopg.connect(settings.dsn) as conn:
        init_db_schema(conn, settings.mailbox_default_attributes, is_master=settings.master)
        # rebuild the Redis DOMAIN_MAP used by rspamd/quarantine from the database
        r = get_redis()
        with conn.cursor() as cur:
            cur.execute("SELECT domain FROM domain UNION SELECT alias_domain FROM alias_domain")
            for (dom,) in cur.fetchall():
                r.hset("DOMAIN_MAP", dom, 1)
    r = get_redis()
    for key, val in QUARANTINE_DEFAULTS.items():
        r.set(key, val, nx=True)
    if not r.exists("PASSWD_POLICY"):
        r.hset("PASSWD_POLICY", mapping={"length": "6", "chars": "0", "special_chars": "0", "lowerupper": "0", "numbers": "0"})
    get_pool()


@asynccontextmanager
async def lifespan(app: FastAPI):
    import asyncio

    await asyncio.get_running_loop().run_in_executor(None, bootstrap)
    log.info("mailcow API %s ready", __version__)
    yield
    close_pool()


class SessionCookieMiddleware(BaseHTTPMiddleware):
    """Set/refresh the session cookie and add defensive headers on every response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        ctx = getattr(request.state, "ctx", None)
        if ctx is not None and not ctx.is_api:
            sess = ctx.session
            if sess.destroyed:
                response.delete_cookie(settings.session_cookie_name, path="/")
            elif sess.new or sess.rotated or request.cookies.get(settings.session_cookie_name) != sess.sid:
                response.set_cookie(
                    settings.session_cookie_name,
                    sess.sid or "",
                    max_age=settings.session_lifetime,
                    path="/",
                    httponly=True,
                    secure=ctx.is_https,
                    samesite="lax",
                )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "strict-origin")
        response.headers.setdefault("Cache-Control", "no-store")
        if "server" in response.headers:
            del response.headers["server"]
        return response


def create_app() -> FastAPI:
    app = FastAPI(title="mailcow API", version=__version__, lifespan=lifespan, docs_url="/api/docs" if settings.dev_mode else None, redoc_url=None, openapi_url="/api/openapi.json" if settings.dev_mode else None)
    app.add_middleware(SessionCookieMiddleware)
    app.include_router(internal.router)
    app.include_router(api_v1.router)
    app.include_router(ui.router)
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    if os.path.isdir(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.exception_handler(HTTPException)
    async def http_exc(request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, dict) else {"type": "error", "msg": str(exc.detail)}
        return JSONResponse(detail, status_code=exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(Exception)
    async def any_exc(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error")
        msg = str(exc) if settings.dev_mode else "internal error"
        return JSONResponse({"type": "error", "msg": msg}, status_code=500)

    return app


app = create_app()
