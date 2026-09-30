"""Per-request context: DB connection, Redis, session, identity, message buffer.

This replaces PHP's globals ($pdo, $redis, $_SESSION, $_SESSION['return']).
"""
from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException, Request

from ..config import settings
from ..db import DB
from ..redisclient import get_redis
from ..validators import ip_acl, is_email, valid_ip
from .session import Session, SessionStore

log = logging.getLogger("mailcow.ctx")


class AccessDenied(Exception):
    pass


@dataclass
class Message:
    type: str  # success | danger | warning | info
    log: list
    msg: Any

    def as_dict(self) -> dict:
        return {"type": self.type, "log": self.log, "msg": self.msg}


@dataclass
class Context:
    db: DB
    redis: Any
    session: Session
    remote_ip: str
    real_ip: str
    user_agent: str
    is_https: bool
    messages: list[Message] = field(default_factory=list)
    access_all_exception: bool = False  # PHP $_SESSION['access_all_exception']
    request: Request | None = None

    # ----- identity -------------------------------------------------------
    @property
    def username(self) -> str | None:
        return self.session.get("mailcow_cc_username")

    @property
    def role(self) -> str | None:
        return self.session.get("mailcow_cc_role")

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_api(self) -> bool:
        return bool(self.session.get("mailcow_cc_api"))

    @property
    def api_access(self) -> str | None:
        return self.session.get("mailcow_cc_api_access")

    @property
    def acl(self) -> dict[str, Any]:
        return self.session.get("acl") or {}

    def has_acl(self, key: str) -> bool:
        if self.access_all_exception:
            return True
        return str(self.acl.get(key, "0")) == "1"

    # ----- messages -------------------------------------------------------
    def add(self, type_: str, log_: list, msg: Any) -> None:
        self.messages.append(Message(type_, log_, msg))

    def ok(self, log_: list, msg: Any) -> None:
        self.add("success", log_, msg)

    def err(self, log_: list, msg: Any) -> None:
        self.add("danger", log_, msg)

    def warn(self, log_: list, msg: Any) -> None:
        self.add("warning", log_, msg)

    def info(self, log_: list, msg: Any) -> None:
        self.add("info", log_, msg)

    def denied(self, log_: list, obj: str | None = None) -> None:
        self.err(log_, ["access_denied", obj] if obj else "access_denied")

    # ----- logging (port of logger()) -------------------------------------
    def flush_log(self) -> None:
        if not self.messages:
            return
        task = secrets.token_hex(3).upper()
        dual = self.session.get("dual-login") or {}
        if dual.get("username"):
            user = f"{dual['username']} => {self.username}"
            role = f"{dual.get('role')} => {self.role}"
        elif self.username:
            user, role = self.username, self.role or ""
        else:
            user = role = "unauthenticated"
        import json as _json

        for m in self.messages:
            try:
                self.db.exec(
                    "INSERT INTO logs (type, task, msg, call, username, role, remote, time) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        m.type,
                        task,
                        _json.dumps(m.msg, ensure_ascii=False),
                        _json.dumps(m.log, ensure_ascii=False, default=str),
                        user[:64],
                        role[:32],
                        self.remote_ip[:39],
                        int(time.time()),
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                log.error("cannot write log row: %s", exc)
        self.messages = []


def client_ips(request: Request) -> tuple[str, str]:
    """Return (remote_ip, real_ip). nginx sets X-Real-IP after set_real_ip_from."""
    remote = request.client.host if request.client else "0.0.0.0"
    real = request.headers.get("x-real-ip") or remote
    if not valid_ip(remote):
        remote = "0.0.0.0"
    if not valid_ip(real):
        real = remote
    return remote, real


def request_is_https(request: Request) -> bool:
    xfp = request.headers.get("x-forwarded-proto", "")
    return request.url.scheme == "https" or xfp.lower() == "https"


def authenticate_api_key(ctx: Context, api_key: str) -> None:
    """Port of the X-API-Key branch of sessions.inc.php. Raises HTTPException(401) on failure."""
    key = "".join(ch for ch in api_key if ch.isalnum() or ch == "-")
    row = ctx.db.one("SELECT * FROM api WHERE api_key = %s AND active = 1", (key,))
    if row and row.get("api_key"):
        skip_ip_check = int(row["skip_ip_check"]) == 1
        allow_from = [x.strip() for x in (row["allow_from"] or "").replace(";", ",").replace("\n", ",").replace(" ", ",").split(",")]
        if skip_ip_check or ip_acl(ctx.remote_ip, allow_from):
            ctx.session["mailcow_cc_username"] = "API"
            ctx.session["mailcow_cc_role"] = "admin"
            ctx.session["mailcow_cc_api"] = True
            ctx.session["mailcow_cc_api_access"] = "rw" if row["access"] == "rw" else "ro"
            return
        _publish_failed_login(ctx, "API_USER")
        raise HTTPException(status_code=401, detail={"type": "error", "msg": f"api access denied for ip {ctx.remote_ip}"})
    _publish_failed_login(ctx, "API_USER")
    raise HTTPException(status_code=401, detail={"type": "error", "msg": "authentication failed"})


def _publish_failed_login(ctx: Context, user: str) -> None:
    # netfilter (fail2ban replacement) listens on this channel with a fixed regex - keep the exact wording
    try:
        ctx.redis.publish("F2B_CHANNEL", f"mailcow UI: Invalid password for {user} by {ctx.remote_ip}")
    except Exception as exc:  # noqa: BLE001
        log.error("redis publish failed: %s", exc)
    log.warning("mailcow UI: Invalid password for %s by %s", user, ctx.remote_ip)


def build_context(request: Request, db: DB) -> Context:
    """Create the request context: resolve API key or cookie session, apply UA binding and idle timeout."""
    r = get_redis()
    store = SessionStore(r)
    remote, real = client_ips(request)
    ua = request.headers.get("user-agent", "")
    https = request_is_https(request)

    api_key = request.headers.get("x-api-key")
    if api_key:
        # API requests are stateless: no cookie, fresh in-memory session
        session = Session(store, None, {}, new=True)
        ctx = Context(db=db, redis=r, session=session, remote_ip=remote, real_ip=real, user_agent=ua, is_https=https, request=request)
        authenticate_api_key(ctx, api_key)
        return ctx

    sid = request.cookies.get(settings.session_cookie_name)
    session = store.load(sid)
    ctx = Context(db=db, redis=r, session=session, remote_ip=remote, real_ip=real, user_agent=ua, is_https=https, request=request)

    if "SESS_REMOTE_UA" not in session:
        session["SESS_REMOTE_UA"] = ua
    elif session.get("mailcow_cc_role") and session["SESS_REMOTE_UA"] != ua:
        # session_check(): UA changed -> do not honour the session
        ctx.warn(["session_check"], "session_ua")
        session.destroy()
        session = store.load(None)
        session["SESS_REMOTE_UA"] = ua
        ctx.session = session

    session["LAST_ACTIVITY"] = int(time.time())
    if "CSRF" not in session:
        session.new_csrf()
    return ctx


def check_csrf(ctx: Context, token: str | None) -> bool:
    """Port of the CSRF part of session_check(): compare and rotate."""
    if ctx.is_api:
        return True
    current = ctx.session.csrf_token
    if not token or not secrets.compare_digest(str(token), current):
        ctx.warn(["session_check"], "session_token")
        return False
    ctx.session.new_csrf()
    return True


def require_login(ctx: Context) -> None:
    if not ctx.role:
        raise HTTPException(status_code=401, detail={"type": "error", "msg": "authentication failed"})


def require_rw(ctx: Context) -> None:
    if ctx.is_api and ctx.api_access != "rw":
        raise HTTPException(status_code=403, detail={"type": "error", "msg": "API read/write access denied"})


def valid_login_username(user: str | None) -> bool:
    if not user:
        return False
    return is_email(user) or all(ch.isalnum() or ch in "_.-" for ch in user)
