"""Login logic: port of functions.auth.inc.php (check_login, admin_login, domainadmin_login, user_login, apppass_login).

Behavioural guarantees kept:
  * password hashes are verified with constant-time comparisons for every Dovecot scheme
  * inactive mailboxes/domains never authenticate
  * an active second factor turns a successful password check into a "pending" login
  * every failed UI login is published to F2B_CHANNEL (netfilter bans) and slowed down with an
    increasing per-session delay (0.5 s per failure)
  * app passwords are per-protocol and only valid for active mailboxes in active domains
"""
from __future__ import annotations

import logging
import time
from typing import Any

from .context import Context, valid_login_username
from .passwords import verify_hash
from .tfa import get_tfa

log = logging.getLogger("mailcow.auth")

RESOURCE_KIND_RE = r"location|thing|group"


def _set_pending(ctx: Context, user: str, role: str, authenticators: dict, provider: str | None = None) -> str:
    ctx.session["pending_mailcow_cc_username"] = user
    ctx.session["pending_mailcow_cc_role"] = role
    ctx.session["pending_tfa_methods"] = authenticators.get("additional")
    ctx.session.pop("ldelay", None)
    log_ = ["user_login" if role == "user" else f"{role}_login", user, "*"]
    if provider:
        log_.append(f"Provider: {provider}")
    ctx.info(log_, "awaiting_tfa_confirmation")
    return "pending"


def _finish_login(ctx: Context, user: str, role: str, fn: str, provider: str | None = None, is_internal: bool = False) -> str:
    if not is_internal:
        ctx.session.pop("ldelay", None)
        # Reactivate TFA if it was set to "deactivate TFA for next login"
        ctx.db.exec("UPDATE tfa SET active = 1 WHERE username = %s", (user,))
        log_ = [fn, user, "*"]
        if provider:
            log_.append(f"Provider: {provider}")
        ctx.ok(log_, ["logged_in_as", user])
    return role


def admin_login(ctx: Context, user: str, password: str, is_internal: bool = False) -> str | bool:
    if not valid_login_username(user):
        if not is_internal:
            ctx.err(["admin_login", user, "*"], "malformed_username")
        return False
    user = user.strip().lower()
    row = ctx.db.one("SELECT password FROM admin WHERE superadmin = 1 AND active = 1 AND username = %s", (user,))
    if row and verify_hash(row["password"], password):
        auth = get_tfa(ctx, user)
        if auth and auth.get("additional"):
            return _set_pending(ctx, user, "admin", auth)
        return _finish_login(ctx, user, "admin", "admin_login")
    return False


def domainadmin_login(ctx: Context, user: str, password: str, is_internal: bool = False) -> str | bool:
    if not valid_login_username(user):
        if not is_internal:
            ctx.err(["domainadmin_login", user, "*"], "malformed_username")
        return False
    row = ctx.db.one("SELECT password FROM admin WHERE superadmin = 0 AND active = 1 AND username = %s", (user,))
    if row and verify_hash(row["password"], password):
        auth = get_tfa(ctx, user)
        if auth and auth.get("additional"):
            return _set_pending(ctx, user, "domainadmin", auth)
        return _finish_login(ctx, user, "domainadmin", "domainadmin_login")
    return False


def user_login(ctx: Context, user: str, password: str, is_internal: bool = False) -> str | bool:
    if not valid_login_username(user):
        if not is_internal:
            ctx.err(["user_login", user, "*"], "malformed_username")
        return False
    row = ctx.db.one(
        """SELECT mailbox.*, domain.active AS d_active FROM mailbox
           INNER JOIN domain ON mailbox.domain = domain.domain
           WHERE kind !~ %s AND username = %s""",
        (RESOURCE_KIND_RE, user),
    )
    if not row:
        # External identity providers (keycloak/ldap) are not part of this port.
        return False
    authsource = row.get("authsource") or "mailcow"
    if authsource != "mailcow":
        log.warning("user %s has authsource %s which is not supported by the Python API", user, authsource)
        return False
    if int(row["active"]) != 1 or int(row["d_active"]) != 1:
        return False
    if not verify_hash(row["password"], password):
        return False
    auth = get_tfa(ctx, user)
    if auth and auth.get("additional") and not is_internal:
        return _set_pending(ctx, user, "user", auth, provider="mailcow")
    if auth and auth.get("additional") and is_internal:
        # internal (IMAP/SMTP) logins: TFA is a UI-only concept; the password alone authenticates
        return "user"
    return _finish_login(ctx, user, "user", "user_login", provider="mailcow", is_internal=is_internal)


def apppass_login(ctx: Context, user: str, password: str, app_passwd_data: dict[str, Any] | None, is_internal: bool = False) -> str | bool:
    if not valid_login_username(user):
        if not is_internal:
            ctx.err(["apppass_login", user, "*"], "malformed_username")
        return False
    app_passwd_data = app_passwd_data or {}
    protocol: str | None = None
    for proto in ("eas", "dav", "smtp", "imap", "sieve", "pop3"):
        if app_passwd_data.get(proto):
            protocol = proto
            break
    if protocol is None and not is_internal:
        return False
    rows = ctx.db.all(
        """SELECT app_passwd.*, app_passwd.id AS app_passwd_id FROM app_passwd
           INNER JOIN mailbox ON mailbox.username = app_passwd.mailbox
           INNER JOIN domain ON mailbox.domain = domain.domain
           WHERE mailbox.kind !~ %s
             AND mailbox.active = 1
             AND domain.active = 1
             AND app_passwd.active = 1
             AND app_passwd.mailbox = %s""",
        (RESOURCE_KIND_RE, user),
    )
    for row in rows:
        if protocol and int(row.get(f"{protocol}_access") or 0) != 1:
            continue
        if verify_hash(row["password"], password):
            ctx.session["app_passwd_id"] = row["app_passwd_id"]
            ctx.session.pop("ldelay", None)
            return "user"
    return False


def set_sasl_log(ctx: Context, username: str, real_rip: str, service: str) -> bool:
    app_password = ctx.session.get("app_passwd_id") or 0
    try:
        ctx.db.exec(
            """INSERT INTO sasl_log (username, real_rip, service, app_password, datetime)
               VALUES (%s, %s, %s, %s, NOW())
               ON CONFLICT (service, real_rip, username)
               DO UPDATE SET app_password = EXCLUDED.app_password, datetime = NOW()""",
            (username, real_rip, service, int(app_password)),
        )
    except Exception as exc:  # noqa: BLE001
        ctx.err(["set_sasl_log"], ["mysql_error", str(exc)])
        return False
    return True


def check_login(
    ctx: Context,
    user: str,
    password: str,
    app_passwd_data: dict[str, Any] | None = None,
    role: str | None = None,
    is_internal: bool = False,
) -> str | bool:
    """Returns 'admin' | 'domainadmin' | 'user' | 'pending' | False."""
    app_passwd_data = app_passwd_data or {}

    if role in (None, "admin"):
        result = admin_login(ctx, user, password, is_internal)
        if result:
            return result
    if role in (None, "domain_admin", "domainadmin"):
        result = domainadmin_login(ctx, user, password, is_internal)
        if result:
            return result
    if role in (None, "app"):
        result = apppass_login(ctx, user, password, app_passwd_data, is_internal)
        if result:
            service = "EAS" if app_passwd_data.get("eas") else "DAV" if app_passwd_data.get("dav") else "NONE"
            set_sasl_log(ctx, user, ctx.real_ip, service)
            return result
    if role in (None, "user"):
        result = user_login(ctx, user, password, is_internal)
        if result:
            service = "EAS" if app_passwd_data.get("eas") else "DAV" if app_passwd_data.get("dav") else "MAILCOWUI"
            set_sasl_log(ctx, user, ctx.real_ip, service)
            return result

    if is_internal:
        return False

    # failed UI login: publish for netfilter and slow down this session
    if "ldelay" not in ctx.session:
        ctx.session["ldelay"] = 0
    elif not ctx.session.get("mailcow_cc_username"):
        ctx.session["ldelay"] = float(ctx.session["ldelay"]) + 0.5
    try:
        ctx.redis.publish("F2B_CHANNEL", f"mailcow UI: Invalid password for {user} by {ctx.remote_ip}")
    except Exception as exc:  # noqa: BLE001
        log.error("redis publish failed: %s", exc)
    log.warning("mailcow UI: Invalid password for %s by %s", user, ctx.remote_ip)
    ctx.err(["check_login", user, "*"], "login_failed")
    delay = min(float(ctx.session.get("ldelay") or 0), 30.0)
    if delay:
        time.sleep(delay)
    return False


def set_user_loggedin_session(ctx: Context, user: str, role: str) -> None:
    """Complete a login: regenerate the session id, store identity, drop pending markers."""
    ctx.session.regenerate_id()
    ctx.session["mailcow_cc_username"] = user
    ctx.session["mailcow_cc_role"] = role
    for k in ("pending_mailcow_cc_username", "pending_mailcow_cc_role", "pending_tfa_methods", "ldelay"):
        ctx.session.pop(k, None)
    ctx.session.new_csrf()


def clear_session(ctx: Context) -> None:
    ctx.session.destroy()
