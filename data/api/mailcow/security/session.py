"""Server-side sessions stored in Redis.

Security properties kept from the PHP implementation (sessions.inc.php):
  * session id is 256 bits of CSPRNG entropy, only ever sent as an HttpOnly cookie
  * cookie is flagged Secure when the request arrived over HTTPS (directly or via X-Forwarded-Proto)
  * SameSite=Lax
  * idle timeout = SESSION_LIFETIME (default 3h), enforced server-side via LAST_ACTIVITY and Redis TTL
  * session is bound to the User-Agent that created it
  * a CSRF token (256 bit) is issued per session and rotated after every state-changing request
  * on login the session id is regenerated (session fixation protection)
"""
from __future__ import annotations

import json
import secrets
import time
from typing import Any

import redis

from ..config import settings

SESSION_PREFIX = "mailcow:sess:"


class Session(dict):
    """A dict with a Redis backing store. Call save() after mutations."""

    def __init__(self, store: "SessionStore", sid: str | None, data: dict[str, Any] | None = None, new: bool = False):
        super().__init__(data or {})
        self.store = store
        self.sid = sid
        self.new = new
        self.destroyed = False
        self.rotated = False

    def save(self) -> None:
        if self.destroyed or self.sid is None:
            return
        self.store.write(self.sid, dict(self))

    def destroy(self) -> None:
        if self.sid:
            self.store.delete(self.sid)
        self.clear()
        self.destroyed = True

    def regenerate_id(self) -> None:
        """session_regenerate_id(true): new id, old id removed."""
        old = self.sid
        self.sid = self.store.new_id()
        self.rotated = True
        self.new = True
        if old:
            self.store.delete(old)

    # convenience accessors ------------------------------------------------
    @property
    def username(self) -> str | None:
        return self.get("mailcow_cc_username")

    @property
    def role(self) -> str | None:
        return self.get("mailcow_cc_role")

    @property
    def is_api(self) -> bool:
        return bool(self.get("mailcow_cc_api"))

    @property
    def acl(self) -> dict[str, Any]:
        return self.get("acl") or {}

    def new_csrf(self) -> str:
        token = secrets.token_hex(32)
        self["CSRF"] = {"TOKEN": token, "TIME": int(time.time())}
        return token

    @property
    def csrf_token(self) -> str:
        if not isinstance(self.get("CSRF"), dict) or not self["CSRF"].get("TOKEN"):
            return self.new_csrf()
        return self["CSRF"]["TOKEN"]


class SessionStore:
    def __init__(self, client: redis.Redis, lifetime: int | None = None):
        self.client = client
        self.lifetime = lifetime or settings.session_lifetime

    @staticmethod
    def new_id() -> str:
        return secrets.token_urlsafe(32)

    def load(self, sid: str | None) -> Session:
        if sid and 20 <= len(sid) <= 128:
            raw = self.client.get(SESSION_PREFIX + sid)
            if raw:
                try:
                    data = json.loads(raw)
                except ValueError:
                    data = None
                if isinstance(data, dict):
                    last = int(data.get("LAST_ACTIVITY", 0))
                    if last and time.time() - last > self.lifetime:
                        self.delete(sid)
                        return Session(self, self.new_id(), new=True)
                    return Session(self, sid, data)
        return Session(self, self.new_id(), new=True)

    def write(self, sid: str, data: dict[str, Any]) -> None:
        self.client.set(SESSION_PREFIX + sid, json.dumps(data, default=str), ex=self.lifetime)

    def delete(self, sid: str) -> None:
        self.client.delete(SESSION_PREFIX + sid)
