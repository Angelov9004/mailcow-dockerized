"""Admin, domain admin, API key and app password management.

Ports of functions.admin.inc.php, functions.domain_admin.inc.php, admin_api() and functions.app_passwd.inc.php.
"""
from __future__ import annotations

import secrets
from datetime import datetime
from typing import Any

from ..security.acl import own_mailbox_access
from ..security.context import Context
from ..security.passwords import hash_password, verify_hash
from ..security.policy import password_check
from ..validators import api_key_token, as_list, htmlspecialchars, is_email, is_valid_domain_name, split_list, to_int, valid_network

_USERNAME_OK = lambda u: bool(u) and all(ch.isalnum() or ch in "_.-" for ch in u)  # noqa: E731


def _mask(data: dict) -> dict:
    out = dict(data)
    for k in ("password", "password2", "user_old_pass", "user_new_pass", "user_new_pass2", "app_passwd", "app_passwd2"):
        if k in out:
            out[k] = "*"
    return out


# ---------------------------------------------------------------------------
# admin()
# ---------------------------------------------------------------------------
def admin_get(ctx: Context) -> list[str]:
    if ctx.role != "admin":
        ctx.denied(["admin", "get"])
        return []
    return [r["username"] for r in ctx.db.all("SELECT username FROM admin WHERE superadmin = 1")]


def admin_details(ctx: Context, username: str) -> dict[str, Any] | None:
    if ctx.role != "admin":
        return None
    row = ctx.db.one(
        """SELECT tfa.active AS tfa_active, admin.username, admin.created, admin.active AS active
           FROM admin LEFT OUTER JOIN tfa ON tfa.username = admin.username
           WHERE admin.username = %s AND superadmin = 1""",
        (username,),
    )
    if not row:
        return None
    tfa_active = int(row["tfa_active"] or 0)
    return {
        "username": row["username"],
        "tfa_active": tfa_active,
        "tfa_active_int": tfa_active,
        "active": int(row["active"]),
        "active_int": int(row["active"]),
        "created": row["created"],
    }


def admin_add(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["admin", "add", _mask(data)]
    if ctx.role != "admin":
        ctx.denied(log_)
        return False
    username = (data.get("username") or "").strip().lower()
    active = to_int(data.get("active"))
    if not _USERNAME_OK(username) or username == "API":
        ctx.err(log_, ["username_invalid", username])
        return False
    if ctx.db.count("SELECT username FROM admin WHERE username = %s", (username,)) or ctx.db.count(
        "SELECT username FROM domain_admins WHERE username = %s", (username,)
    ):
        ctx.err(log_, ["object_exists", htmlspecialchars(username)])
        return False
    if not password_check(ctx, data.get("password"), data.get("password2")):
        return False
    ctx.db.exec(
        "INSERT INTO admin (username, password, superadmin, active) VALUES (%s, %s, 1, %s)",
        (username, hash_password(data["password"]), active),
    )
    ctx.ok(log_, ["admin_added", htmlspecialchars(username)])
    return True


def admin_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["admin", "edit", _mask(data)]
    if ctx.role != "admin":
        ctx.denied(log_)
        return False
    for username in as_list(data.get("username")):
        is_now = admin_details(ctx, username)
        if not is_now:
            ctx.denied(log_)
            continue
        active = to_int(data["active"]) if "active" in data else is_now["active"]
        username_new = data.get("username_new") or is_now["username"]
        password, password2 = data.get("password"), data.get("password2")
        if active == 0:
            left = sum((admin_details(ctx, a) or {}).get("active", 0) for a in admin_get(ctx))
            if left == 1:
                ctx.warn(log_, "no_active_admin")
                continue
        if not _USERNAME_OK(username_new):
            ctx.err(log_, ["username_invalid", username_new])
            continue
        if username_new != username and admin_details(ctx, username_new):
            ctx.err(log_, ["username_invalid", username_new])
            continue
        if password:
            if not password_check(ctx, password, password2):
                return False
            ctx.db.exec(
                "UPDATE admin SET username = %s, active = %s, password = %s WHERE username = %s",
                (username_new, active, hash_password(password), username),
            )
        else:
            ctx.db.exec("UPDATE admin SET username = %s, active = %s WHERE username = %s", (username_new, active, username))
        if data.get("disable_tfa"):
            ctx.db.exec("UPDATE tfa SET active = 0 WHERE username = %s", (username,))
        else:
            ctx.db.exec("UPDATE tfa SET username = %s WHERE username = %s", (username_new, username))
        ctx.ok(log_, ["admin_modified", htmlspecialchars(username)])
    return True


def admin_delete(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["admin", "delete", data]
    if ctx.role != "admin":
        ctx.denied(log_)
        return False
    for username in as_list(data.get("username")):
        if ctx.username == username:
            ctx.warn(log_, "cannot_delete_self")
            continue
        if not admin_details(ctx, username):
            ctx.err(log_, ["username_invalid", username])
            continue
        for table in ("admin", "domain_admins", "tfa", "fido2"):
            ctx.db.exec(f"DELETE FROM {table} WHERE username = %s", (username,))
        ctx.ok(log_, ["admin_removed", htmlspecialchars(username)])
    return True


# ---------------------------------------------------------------------------
# domain_admin()
# ---------------------------------------------------------------------------
def domain_admin_get(ctx: Context) -> list[str]:
    if ctx.role != "admin":
        ctx.denied(["domain_admin", "get"])
        return []
    rows = ctx.db.all(
        "SELECT DISTINCT username FROM domain_admins WHERE username IN (SELECT username FROM admin WHERE superadmin != 1)"
    )
    return [r["username"] for r in rows]


def domain_admin_details(ctx: Context, username: str) -> dict[str, Any] | None:
    if ctx.role == "domainadmin" and username != ctx.username:
        return None
    if ctx.role != "admin" and ctx.role != "domainadmin":
        return None
    if not username or not _USERNAME_OK(username):
        return None
    row = ctx.db.one(
        """SELECT tfa.active AS tfa_active, domain_admins.username, domain_admins.created, domain_admins.active AS active
           FROM domain_admins LEFT OUTER JOIN tfa ON tfa.username = domain_admins.username
           WHERE domain_admins.username = %s""",
        (username,),
    )
    if not row:
        return None
    tfa_active = int(row["tfa_active"] or 0)
    out = {
        "username": row["username"],
        "tfa_active": tfa_active,
        "tfa_active_int": tfa_active,
        "active": int(row["active"]),
        "active_int": int(row["active"]),
        "created": row["created"],
        "selected_domains": [
            r["domain"] for r in ctx.db.all("SELECT domain FROM domain WHERE domain IN (SELECT domain FROM domain_admins WHERE username = %s)", (username,))
        ],
        "unselected_domains": [
            r["domain"]
            for r in ctx.db.all("SELECT domain FROM domain WHERE domain NOT IN (SELECT domain FROM domain_admins WHERE username = %s)", (username,))
        ],
    }
    return out


def domain_admin_add(ctx: Context, data: dict[str, Any]) -> bool:
    from .mailbox import domain_details

    log_ = ["domain_admin", "add", _mask(data)]
    if ctx.role != "admin":
        ctx.denied(log_)
        return False
    username = (data.get("username") or "").strip().lower()
    domains = as_list(data.get("domains"))
    active = to_int(data.get("active"))
    if not domains:
        ctx.err(log_, "domain_invalid")
        return False
    if not _USERNAME_OK(username) or username == "API":
        ctx.err(log_, ["username_invalid", username])
        return False
    for table in ("mailbox", "admin", "domain_admins"):
        if ctx.db.count(f"SELECT username FROM {table} WHERE username = %s", (username,)):
            ctx.err(log_, ["object_exists", htmlspecialchars(username)])
            return False
    if not password_check(ctx, data.get("password"), data.get("password2")):
        return False
    valid = 0
    for domain in domains:
        if not is_valid_domain_name(domain) or not domain_details(ctx, domain):
            ctx.err(log_, ["domain_invalid", htmlspecialchars(domain)])
            continue
        valid += 1
        ctx.db.exec(
            "INSERT INTO domain_admins (username, domain, created, active) VALUES (%s, %s, %s, %s)",
            (username, domain, datetime.now(), active),
        )
    if valid:
        ctx.db.exec(
            "INSERT INTO admin (username, password, superadmin, active) VALUES (%s, %s, 0, %s)",
            (username, hash_password(data["password"]), active),
        )
    ctx.db.exec("INSERT INTO da_acl (username) VALUES (%s) ON CONFLICT DO NOTHING", (username,))
    ctx.ok(log_, ["domain_admin_added", htmlspecialchars(username)])
    return True


def domain_admin_edit(ctx: Context, data: dict[str, Any]) -> bool:
    from .mailbox import domain_details

    log_ = ["domain_admin", "edit", _mask(data)]
    if ctx.role == "admin":
        for username in as_list(data.get("username")):
            is_now = domain_admin_details(ctx, username)
            if not is_now:
                ctx.denied(log_)
                continue
            active = to_int(data["active"]) if "active" in data else is_now["active"]
            domains = as_list(data.get("domains")) or is_now["selected_domains"]
            username_new = data.get("username_new") or is_now["username"]
            password, password2 = data.get("password"), data.get("password2")
            bad = False
            for domain in domains:
                if not is_valid_domain_name(domain) or not domain_details(ctx, domain):
                    ctx.err(log_, ["domain_invalid", htmlspecialchars(domain)])
                    bad = True
                    break
            if bad:
                continue
            if not _USERNAME_OK(username_new):
                ctx.err(log_, ["username_invalid", username_new])
                continue
            if username_new != username and domain_admin_details(ctx, username_new):
                ctx.err(log_, ["username_invalid", username_new])
                continue
            ctx.db.exec("DELETE FROM domain_admins WHERE username = %s", (username,))
            ctx.db.exec("UPDATE da_acl SET username = %s WHERE username = %s", (username_new, username))
            for domain in domains:
                ctx.db.exec(
                    "INSERT INTO domain_admins (username, domain, created, active) VALUES (%s, %s, %s, %s)",
                    (username_new, domain, datetime.now(), active),
                )
            if password:
                if not password_check(ctx, password, password2):
                    return False
                ctx.db.exec(
                    "UPDATE admin SET username = %s, active = %s, password = %s WHERE username = %s",
                    (username_new, active, hash_password(password), username),
                )
            else:
                ctx.db.exec("UPDATE admin SET username = %s, active = %s WHERE username = %s", (username_new, active, username))
            if data.get("disable_tfa"):
                ctx.db.exec("UPDATE tfa SET active = 0 WHERE username = %s", (username,))
            else:
                ctx.db.exec("UPDATE tfa SET username = %s WHERE username = %s", (username_new, username))
            ctx.ok(log_, ["domain_admin_modified", htmlspecialchars(username)])
        return True
    if ctx.role == "domainadmin":
        username = ctx.username
        row = ctx.db.one("SELECT password FROM admin WHERE username = %s", (username,))
        if not row or not verify_hash(row["password"], data.get("user_old_pass") or ""):
            ctx.denied(log_)
            return False
        if not password_check(ctx, data.get("user_new_pass"), data.get("user_new_pass2")):
            return False
        ctx.db.exec("UPDATE admin SET password = %s WHERE username = %s", (hash_password(data["user_new_pass"]), username))
        ctx.ok(log_, ["domain_admin_modified", htmlspecialchars(username)])
        return True
    ctx.denied(log_)
    return False


def domain_admin_delete(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["domain_admin", "delete", data]
    if ctx.role != "admin":
        ctx.denied(log_)
        return False
    for username in as_list(data.get("username")):
        if not domain_admin_details(ctx, username):
            ctx.err(log_, ["username_invalid", username])
            continue
        for table in ("domain_admins", "admin", "da_acl", "tfa", "fido2"):
            ctx.db.exec(f"DELETE FROM {table} WHERE username = %s", (username,))
        ctx.ok(log_, ["domain_admin_removed", htmlspecialchars(username)])
    return True


def domain_admin_sso_issue(ctx: Context, data: dict[str, Any]) -> dict | bool:
    if ctx.role != "admin":
        ctx.denied(["domain_admin_sso", "issue", data])
        return False
    username = data.get("username")
    if not ctx.db.count("SELECT username FROM domain_admins WHERE username = %s", (username,)):
        ctx.err(["domain_admin_sso", "issue", data], ["object_doesnt_exist", htmlspecialchars(username)])
        return False
    token = api_key_token()
    ctx.db.exec("INSERT INTO da_sso (username, token) VALUES (%s, %s)", (username, token))
    ctx.db.exec("DELETE FROM da_sso WHERE created < NOW() - INTERVAL '30 seconds'")
    return {"token": token}


def domain_admin_sso_check(ctx: Context, token: str) -> str | bool:
    token = "".join(ch for ch in (token or "") if ch.isalnum() or ch == "-")
    row = ctx.db.one(
        """SELECT t1.username FROM da_sso AS t1 JOIN admin AS t2 ON t1.username = t2.username
           WHERE t1.token = %s AND t1.created > NOW() - INTERVAL '30 seconds' AND t2.active = 1 AND t2.superadmin = 0""",
        (token,),
    )
    return row["username"] if row else False


# ---------------------------------------------------------------------------
# admin_api(): API keys
# ---------------------------------------------------------------------------
def admin_api(ctx: Context, access: str, action: str, data: dict[str, Any] | None = None) -> Any:
    data = data or {}
    if ctx.role != "admin":
        ctx.denied(["admin_api"])
        return False
    if access not in ("ro", "rw"):
        ctx.err(["admin_api"], "invalid access type")
        return False
    if action == "edit":
        active = 1 if data.get("active") not in (None, "", 0, "0", False) else 0
        skip_ip_check = 1 if data.get("skip_ip_check") not in (None, "", 0, "0", False) else 0
        allow_from: list[str] = []
        for val in split_list(data.get("allow_from")):
            if not valid_network(val):
                ctx.warn(["admin_api", data], ["ip_invalid", htmlspecialchars(val)])
                continue
            allow_from.append(val)
        allow_from_s = ",".join(dict.fromkeys(allow_from))
        if not allow_from_s and skip_ip_check == 0:
            ctx.err(["admin_api", data], "ip_list_empty")
            return False
        exists = ctx.db.count("SELECT api_key FROM api WHERE access = %s", (access,))
        if not exists:
            ctx.db.exec(
                "INSERT INTO api (api_key, skip_ip_check, active, allow_from, access) VALUES (%s, %s, %s, %s, %s)",
                (api_key_token(), skip_ip_check, active, allow_from_s, access),
            )
        elif skip_ip_check == 0:
            ctx.db.exec(
                "UPDATE api SET skip_ip_check = %s, active = %s, allow_from = %s WHERE access = %s",
                (skip_ip_check, active, allow_from_s, access),
            )
        else:
            ctx.db.exec("UPDATE api SET skip_ip_check = %s, active = %s WHERE access = %s", (skip_ip_check, active, access))
    elif action == "regen_key":
        ctx.db.exec("UPDATE api SET api_key = %s WHERE access = %s", (api_key_token(), access))
    elif action == "get":
        row = ctx.db.one("SELECT * FROM api WHERE access = %s", (access,))
        if row:
            row["allow_from"] = (row["allow_from"] or "").replace(",", "\n")
        return row or False
    ctx.ok(["admin_api", data], "admin_api_modified")
    return True


# ---------------------------------------------------------------------------
# app_passwd()
# ---------------------------------------------------------------------------
def _app_passwd_user(ctx: Context, data: dict[str, Any], log_: list) -> str | None:
    if data.get("username") and is_email(data["username"]):
        if not own_mailbox_access(ctx, data["username"]):
            ctx.denied(log_)
            return None
        return data["username"]
    return ctx.username


def app_passwd_get(ctx: Context, data: dict[str, Any] | None = None) -> list[dict]:
    data = data or {}
    username = _app_passwd_user(ctx, data, ["app_passwd", "get", data])
    if not username:
        return []
    return ctx.db.all("SELECT id, name FROM app_passwd WHERE mailbox = %s", (username,))


def app_passwd_details(ctx: Context, id_: Any) -> dict[str, Any] | None:
    row = ctx.db.one("SELECT * FROM app_passwd WHERE id = %s", (to_int(id_),))
    if not row:
        return None
    if not own_mailbox_access(ctx, row["mailbox"]):
        return None
    row["name"] = htmlspecialchars((row["name"] or "").strip())
    row.pop("password", None)
    return row


def _protocols(data: dict[str, Any]) -> dict[str, int]:
    protocols = as_list(data.get("protocols"))
    return {p: (1 if p in protocols else 0) for p in ("imap_access", "dav_access", "smtp_access", "eas_access", "pop3_access", "sieve_access")}


def app_passwd_add(ctx: Context, data: dict[str, Any]) -> bool:
    from .mailbox import mailbox_details

    log_ = ["app_passwd", "add", _mask(data)]
    if not ctx.has_acl("app_passwds"):
        ctx.denied(log_)
        return False
    username = _app_passwd_user(ctx, data, log_)
    if not username:
        return False
    app_name = htmlspecialchars((data.get("app_name") or "").strip())
    password, password2 = data.get("app_passwd"), data.get("app_passwd2")
    active = to_int(data.get("active"))
    prot = _protocols(data)
    details = mailbox_details(ctx, username) or {}
    domain = details.get("domain")
    if not domain:
        ctx.denied(log_)
        return False
    if not password_check(ctx, password, password2):
        return False
    if not app_name:
        ctx.err(log_, "app_name_empty")
        return False
    ctx.db.exec(
        """INSERT INTO app_passwd (name, mailbox, domain, password, imap_access, smtp_access, eas_access, dav_access, pop3_access, sieve_access, active)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (
            app_name, username, domain, hash_password(password),
            prot["imap_access"], prot["smtp_access"], prot["eas_access"], prot["dav_access"], prot["pop3_access"], prot["sieve_access"], active,
        ),
    )
    ctx.ok(log_, "app_passwd_added")
    return True


def app_passwd_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["app_passwd", "edit", _mask(data)]
    if not ctx.has_acl("app_passwds"):
        ctx.denied(log_)
        return False
    username = _app_passwd_user(ctx, data, log_)
    if not username:
        return False
    ids = as_list(data.get("id"))
    for id_ in ids:
        is_now = app_passwd_details(ctx, id_)
        if not is_now:
            ctx.err(log_, ["app_passwd_id_invalid", id_])
            continue
        app_name = htmlspecialchars((data.get("app_name") or is_now["name"]).strip())
        password, password2 = data.get("password"), data.get("password2")
        prot = _protocols(data) if "protocols" in data else {k: is_now[k] for k in ("imap_access", "dav_access", "smtp_access", "eas_access", "pop3_access", "sieve_access")}
        active = to_int(data["active"]) if "active" in data else is_now["active"]
        if password and password2:
            if not password_check(ctx, password, password2):
                continue
            ctx.db.exec("UPDATE app_passwd SET password = %s WHERE mailbox = %s AND id = %s", (hash_password(password), username, to_int(id_)))
        ctx.db.exec(
            """UPDATE app_passwd SET name = %s, mailbox = %s, imap_access = %s, smtp_access = %s, eas_access = %s, dav_access = %s,
               pop3_access = %s, sieve_access = %s, active = %s WHERE id = %s""",
            (
                app_name, username, prot["imap_access"], prot["smtp_access"], prot["eas_access"], prot["dav_access"],
                prot["pop3_access"], prot["sieve_access"], active, to_int(id_),
            ),
        )
        ctx.ok(log_, ["object_modified", htmlspecialchars(", ".join(str(i) for i in ids))])
    return True


def app_passwd_delete(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["app_passwd", "delete", data]
    for id_ in as_list(data.get("id")):
        row = ctx.db.one("SELECT mailbox FROM app_passwd WHERE id = %s", (to_int(id_),))
        if not row:
            ctx.err(log_, "app_passwd_id_invalid")
            return False
        if not own_mailbox_access(ctx, row["mailbox"]):
            ctx.denied(log_)
            return False
        ctx.db.exec("DELETE FROM app_passwd WHERE id = %s", (to_int(id_),))
        ctx.ok(log_, ["app_passwd_removed", htmlspecialchars(str(id_))])
    return True


# ---------------------------------------------------------------------------
# sasl log / last login (functions.inc.php last_login)
# ---------------------------------------------------------------------------
def last_login_get(ctx: Context, username: str, sasl_limit_days: int = 7, ui_offset: int = 1) -> dict[str, Any]:
    sasl: list[dict] = []
    if is_email(username) and own_mailbox_access(ctx, username):
        sasl = ctx.db.all(
            """SELECT real_rip, MAX(datetime) AS datetime, service, app_password, MAX(app_passwd.name) AS app_password_name
               FROM sasl_log LEFT OUTER JOIN app_passwd ON sasl_log.app_password = app_passwd.id
               WHERE username = %s AND datetime > NOW() - make_interval(hours => %s)
               GROUP BY real_rip, service, app_password ORDER BY datetime DESC""",
            (username, int(sasl_limit_days) * 24),
        )
        from ..validators import is_public_ip

        for row in sasl:
            if not is_public_ip(row["real_rip"]):
                row["real_rip"] = f"Web/EAS/Internal ({row['real_rip']})"
            else:
                try:
                    row["location"] = ctx.redis.hget("IP_SHORTCOUNTRY", row["real_rip"])
                except Exception:  # noqa: BLE001
                    row["location"] = None
    ui: dict | None = None
    if ctx.role == "admin" or username == ctx.username:
        ui = ctx.db.one(
            """SELECT remote, time FROM logs
               WHERE call::jsonb->>0 = 'check_login' AND call::jsonb->>1 = %s AND type = 'success'
               ORDER BY time DESC LIMIT 1 OFFSET %s""",
            (username, int(ui_offset)),
        )
    return {"ui": ui or {}, "sasl": sasl}


def last_login_reset(ctx: Context, username: str) -> bool:
    if is_email(username) and own_mailbox_access(ctx, username):
        ctx.db.exec("DELETE FROM sasl_log WHERE username = %s", (username,))
    if ctx.role == "admin" or username == ctx.username:
        ctx.db.exec(
            "DELETE FROM logs WHERE call::jsonb->>0 = 'check_login' AND call::jsonb->>1 = %s AND type = 'success'",
            (username,),
        )
    return True


def new_reset_token() -> str:
    return secrets.token_urlsafe(32)
