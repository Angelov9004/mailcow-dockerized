"""Access control helpers: port of hasDomainAccess/hasMailboxObjectAccess/hasAliasObjectAccess and acl()."""
from __future__ import annotations

from typing import Any

from ..validators import is_email, is_username, is_valid_domain_name
from .context import Context

USER_ACL_FIELDS = [
    "spam_alias", "tls_policy", "spam_score", "spam_policy", "delimiter_action", "syncjobs", "eas_reset",
    "sogo_profile_reset", "pushover", "quarantine", "quarantine_attachments", "quarantine_notification",
    "quarantine_category", "app_passwds", "pw_reset",
]
DA_ACL_FIELDS = [
    "syncjobs", "quarantine", "login_as", "sogo_access", "app_passwds", "bcc_maps", "pushover", "filters",
    "ratelimit", "spam_policy", "extend_sender_acl", "unlimited_quota", "protocol_access", "smtp_ip_access",
    "alias_domains", "mailbox_relayhost", "domain_relayhost", "domain_desc",
]


def has_domain_access(ctx: Context, username: str | None, role: str | None, domain: str | None) -> bool:
    if not domain or not is_valid_domain_name(domain):
        return False
    if ctx.access_all_exception:
        return True
    if not is_username(username):
        return False
    if role not in ("admin", "domainadmin"):
        return False
    if role == "admin":
        n = ctx.db.count("SELECT domain FROM domain WHERE domain = %s", (domain,))
        n += ctx.db.count("SELECT alias_domain FROM alias_domain WHERE alias_domain = %s", (domain,))
        return n != 0
    n = ctx.db.count(
        """SELECT domain FROM domain_admins
           WHERE active = 1 AND username = %s
             AND (domain = %s OR domain = (SELECT target_domain FROM alias_domain WHERE alias_domain = %s))""",
        (username, domain, domain),
    )
    return n != 0


def has_mailbox_object_access(ctx: Context, username: str | None, role: str | None, obj: str | None) -> bool:
    if ctx.access_all_exception:
        return True
    if not username or not role or not obj:
        return False
    if not is_username(username):
        return False
    if role not in ("admin", "domainadmin", "user"):
        return False
    if username == obj:
        return True
    row = ctx.db.one("SELECT domain FROM mailbox WHERE username = %s", (obj,))
    return bool(row and row.get("domain") and has_domain_access(ctx, username, role, row["domain"]))


def has_alias_object_access(ctx: Context, username: str | None, role: str | None, obj: str | None) -> bool:
    if ctx.access_all_exception:
        return True
    if not username or not role or not obj:
        return False
    if not is_username(username):
        return False
    if role not in ("admin", "domainadmin", "user"):
        return False
    row = ctx.db.one("SELECT domain FROM alias WHERE address = %s", (obj,))
    return bool(row and row.get("domain") and has_domain_access(ctx, username, role, row["domain"]))


def own_domain_access(ctx: Context, domain: str) -> bool:
    return has_domain_access(ctx, ctx.username, ctx.role, domain)


def own_mailbox_access(ctx: Context, obj: str) -> bool:
    return has_mailbox_object_access(ctx, ctx.username, ctx.role, obj)


def acl_get(ctx: Context, scope: str, username: str) -> dict[str, Any] | None:
    if scope == "user":
        if not own_mailbox_access(ctx, username):
            return None
        data = ctx.db.one("SELECT * FROM user_acl WHERE username = %s", (username,))
        if not data:
            return None
        if ctx.role == "domainadmin":
            # Domain admins cannot see, add or remove user ACLs they don't have access to by themselves
            self_da = acl_get(ctx, "domainadmin", ctx.username or "") or {}
            for k, v in self_da.items():
                if int(v or 0) == 0:
                    data.pop(k, None)
        data.pop("username", None)
        return data
    if scope == "domainadmin":
        if ctx.role not in ("admin", "domainadmin"):
            return None
        if ctx.role == "domainadmin" and ctx.username != username:
            return None
        data = ctx.db.one("SELECT * FROM da_acl WHERE username = %s", (username,))
        if not data:
            return None
        data.pop("username", None)
        return data
    return None


def acl_edit(ctx: Context, scope: str, data: dict[str, Any]) -> bool:
    usernames = data.get("username")
    usernames = usernames if isinstance(usernames, list) else [usernames]
    if scope == "user":
        acls = data.get("user_acl") or []
        acls = acls if isinstance(acls, list) else [acls]
        for username in usernames:
            if not own_mailbox_access(ctx, username) or (ctx.role not in ("admin", "domainadmin") and not ctx.access_all_exception):
                ctx.denied(["acl", "edit", scope, data])
                continue
            is_now = acl_get(ctx, "user", username)
            if not is_now:
                ctx.err(["acl", "edit", scope, data], "Cannot determine current ACL")
                continue
            for key in is_now:
                if key not in USER_ACL_FIELDS:
                    continue
                ctx.db.exec(f"UPDATE user_acl SET {key} = %s WHERE username = %s", (1 if key in acls else 0, username))
            ctx.ok(["acl", "edit", scope, data], ["acl_saved", username])
        return True
    if scope == "domainadmin":
        if ctx.role != "admin":
            ctx.denied(["acl", "edit", scope, data])
            return False
        acls = data.get("da_acl") or []
        acls = acls if isinstance(acls, list) else [acls]
        for username in usernames:
            is_now = acl_get(ctx, "domainadmin", username)
            if not is_now:
                ctx.err(["acl", "edit", scope, data], "Cannot determine current ACL")
                continue
            for key in is_now:
                if key not in DA_ACL_FIELDS:
                    continue
                ctx.db.exec(f"UPDATE da_acl SET {key} = %s WHERE username = %s", (1 if key in acls else 0, username))
            ctx.ok(["acl", "edit", scope, data], ["acl_saved", username])
        return True
    return False


def acl_to_session(ctx: Context) -> None:
    """Port of acl('to_session'): compute effective ACL for the logged in identity."""
    if not ctx.role:
        return
    acl: dict[str, Any] = {}
    dual = ctx.session.get("dual-login") or {}
    username = (ctx.username or "").strip().lower()
    if ctx.role == "admin" or dual.get("role") == "admin":
        for f in USER_ACL_FIELDS + DA_ACL_FIELDS:
            acl[f] = 1
    elif ctx.role == "domainadmin" or dual.get("role") == "domainadmin":
        for f in USER_ACL_FIELDS:
            acl[f] = 1
        row = ctx.db.one("SELECT * FROM da_acl WHERE username = %s", (dual.get("username") or username,))
        if row:
            for k, v in row.items():
                if k != "username":
                    acl[k] = v
    elif ctx.role == "user":
        row = ctx.db.one("SELECT * FROM user_acl WHERE username = %s", (username,))
        if row:
            row.pop("username", None)
            acl = dict(row)
    ctx.session["acl"] = acl
