"""Domains, alias domains, mailboxes and aliases: port of functions.mailbox.inc.php (core objects).

Validation, quota accounting, ACL checks and side effects (Redis DOMAIN_MAP, ratelimits, DKIM,
SOGo static view, Dovecot maildir cleanup via dockerapi) follow the PHP implementation.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from ..config import settings
from ..security.acl import has_alias_object_access, own_domain_access, own_mailbox_access
from ..security.context import Context
from ..security.passwords import hash_password, verify_hash
from ..security.policy import password_check
from ..validators import (
    as_list,
    htmlspecialchars,
    idn_to_ascii,
    idn_to_utf8,
    is_email,
    is_valid_domain_name,
    split_list,
    to_int,
)
from .common import dkim_add, docker, ratelimit_edit, ratelimit_get

MB = 1048576
RESOURCE_KIND_RE = "location|thing|group"


def _mask(data: dict) -> dict:
    out = dict(data or {})
    for k in ("password", "password2", "user_old_pass", "user_new_pass", "user_new_pass2"):
        if k in out:
            out[k] = "*"
    return out


def _isset(data: dict, key: str) -> bool:
    return key in data and data[key] is not None


def _has_content(data: dict, key: str) -> bool:
    return _isset(data, key) and str(data[key]) != ""


def _goto_regex(username: str) -> str:
    return "(^|,)" + re.escape(username) + "($|,)"


# ---------------------------------------------------------------------------
# templates
# ---------------------------------------------------------------------------
def get_templates(ctx: Context, type_: str, id_: Any = None) -> Any:
    if ctx.role not in ("admin", "domainadmin") and not ctx.access_all_exception:
        return None
    if id_ is not None:
        row = ctx.db.one("SELECT * FROM templates WHERE id = %s AND type = %s", (to_int(id_), type_))
        return row or None
    rows = ctx.db.all("SELECT * FROM templates WHERE type = %s ORDER BY id", (type_,))
    return rows or None


# ---------------------------------------------------------------------------
# SOGo static view (update_sogo_static_view)
# ---------------------------------------------------------------------------
def update_sogo_static_view(ctx: Context, mailbox: str | None = None) -> None:
    if settings.skip_sogo:
        return
    import base64
    import hashlib
    import secrets

    exists = False
    if mailbox is not None:
        exists = ctx.db.count("SELECT username FROM mailbox WHERE username = %s AND active = 1", (mailbox,)) > 0
    # random password so that SOGo never accepts a direct login; auth goes through mailcow
    salt = secrets.token_bytes(16)
    random_hash = "{SSHA256}" + base64.b64encode(hashlib.sha256(secrets.token_bytes(24) + salt).digest() + salt).decode()
    where_extra = "AND mailbox.username = %(mailbox)s" if exists else ""
    query = f"""
        INSERT INTO _sogo_static_view (c_uid, domain, c_name, c_password, c_cn, mail, aliases, ad_aliases, ext_acl, kind, multiple_bookings)
        SELECT mailbox.username, mailbox.domain, mailbox.username, %(random_hash)s, mailbox.name, mailbox.username,
               COALESCE(string_agg(ga.aliases, ' ' ORDER BY ga.aliases), ''),
               COALESCE(MAX(gda.ad_alias), ''),
               COALESCE(MAX(external_acl.send_as_acl), ''),
               mailbox.kind, mailbox.multiple_bookings
        FROM mailbox
        LEFT OUTER JOIN grouped_mail_aliases ga ON ga.username ~ ('(^|,)' || regexp_replace(mailbox.username, '([.+?^$|()\\[\\]{{}}\\\\])', '\\\\\\1', 'g') || '($|,)')
        LEFT OUTER JOIN grouped_domain_alias_address gda ON gda.username = mailbox.username
        LEFT OUTER JOIN grouped_sender_acl_external external_acl ON external_acl.username = mailbox.username
        WHERE mailbox.active = 1 {where_extra}
        GROUP BY mailbox.username
        ON CONFLICT (c_uid) DO UPDATE SET
          domain = EXCLUDED.domain, c_name = EXCLUDED.c_name, c_password = EXCLUDED.c_password, c_cn = EXCLUDED.c_cn,
          mail = EXCLUDED.mail, aliases = EXCLUDED.aliases, ad_aliases = EXCLUDED.ad_aliases, ext_acl = EXCLUDED.ext_acl,
          kind = EXCLUDED.kind, multiple_bookings = EXCLUDED.multiple_bookings
    """
    ctx.db.exec(query, {"random_hash": random_hash, "mailbox": mailbox})
    ctx.db.exec("DELETE FROM _sogo_static_view WHERE c_uid NOT IN (SELECT username FROM mailbox WHERE active = 1)")


# ---------------------------------------------------------------------------
# domains
# ---------------------------------------------------------------------------
def get_domains(ctx: Context, tags: list[str] | None = None) -> list[str]:
    if ctx.role not in ("admin", "domainadmin"):
        return []
    if tags:
        rows = ctx.db.all(
            "SELECT DISTINCT domain FROM tags_domain WHERE " + " OR ".join(["tag_name LIKE %s"] * len(tags)),
            tuple(f"%{t}%" for t in tags),
        )
        return [r["domain"] for r in rows if ctx.role == "admin" or own_domain_access(ctx, r["domain"])]
    rows = ctx.db.all(
        """SELECT domain FROM domain
           WHERE domain IN (SELECT domain FROM domain_admins WHERE active = 1 AND username = %s) OR 'admin' = %s
           ORDER BY domain""",
        (ctx.username, ctx.role),
    )
    return [r["domain"] for r in rows]


def domain_details(ctx: Context, domain: str) -> dict[str, Any] | None:
    domain = idn_to_ascii((domain or "").strip().lower())
    if not own_domain_access(ctx, domain):
        return None
    row = ctx.db.one("SELECT target_domain FROM alias_domain WHERE alias_domain = %s", (domain,))
    if row:
        domain = row["target_domain"]
    row = ctx.db.one("SELECT * FROM domain WHERE domain = %s", (domain,))
    if not row:
        return None
    mb = ctx.db.one(
        "SELECT COUNT(username) AS count, COALESCE(SUM(quota), 0) AS in_use FROM mailbox WHERE (kind = '' OR kind IS NULL) AND domain = %s",
        (row["domain"],),
    )
    q = ctx.db.one(
        "SELECT SUM(bytes) AS bytes_total, SUM(messages) AS msgs_total FROM quota2 WHERE username IN (SELECT username FROM mailbox WHERE domain = %s)",
        (row["domain"],),
    )
    rl = ratelimit_get(ctx, "domain", domain)
    d: dict[str, Any] = {}
    d["max_new_mailbox_quota"] = min(int(row["quota"]) * MB - int(mb["in_use"]), int(row["maxquota"]) * MB)
    d["def_new_mailbox_quota"] = min(d["max_new_mailbox_quota"], int(row["defquota"]) * MB)
    d["quota_used_in_domain"] = int(mb["in_use"])
    d["bytes_total"] = int(q["bytes_total"] or 0)
    d["msgs_total"] = int(q["msgs_total"] or 0)
    d["mboxes_in_domain"] = int(mb["count"])
    d["mboxes_left"] = int(row["mailboxes"]) - int(mb["count"])
    d["domain_name"] = row["domain"]
    d["domain_h_name"] = idn_to_utf8(row["domain"])
    d["description"] = row["description"]
    d["max_num_aliases_for_domain"] = int(row["aliases"])
    d["max_num_mboxes_for_domain"] = int(row["mailboxes"])
    d["def_quota_for_mbox"] = int(row["defquota"]) * MB
    d["max_quota_for_mbox"] = int(row["maxquota"]) * MB
    d["max_quota_for_domain"] = int(row["quota"]) * MB
    d["relayhost"] = row["relayhost"]
    d["backupmx"] = d["backupmx_int"] = int(row["backupmx"])
    d["gal"] = d["gal_int"] = int(row["gal"])
    d["rl"] = rl
    d["active"] = d["active_int"] = int(row["active"])
    d["relay_all_recipients"] = d["relay_all_recipients_int"] = int(row["relay_all_recipients"])
    d["relay_unknown_only"] = d["relay_unknown_only_int"] = int(row["relay_unknown_only"])
    d["created"] = row["created"]
    d["modified"] = row["modified"]
    al = ctx.db.one(
        """SELECT COUNT(address) AS alias_count FROM alias
           WHERE (domain = %s OR domain IN (SELECT alias_domain FROM alias_domain WHERE target_domain = %s))
             AND address NOT IN (SELECT username FROM mailbox)""",
        (domain, domain),
    )
    d["aliases_in_domain"] = int(al["alias_count"] or 0)
    d["aliases_left"] = int(row["aliases"]) - d["aliases_in_domain"]
    if ctx.role == "admin":
        da = ctx.db.one("SELECT string_agg(username, ', ') AS domain_admins FROM domain_admins WHERE domain = %s", (domain,))
        d["domain_admins"] = da["domain_admins"] if da and da["domain_admins"] else "-"
    d["tags"] = [r["tag_name"] for r in ctx.db.all("SELECT tag_name FROM tags_domain WHERE domain = %s", (domain,))]
    return d


def _save_tags(ctx: Context, table: str, key_col: str, key: str, tags: list, log_: list) -> None:
    for index, tag in enumerate(tags or []):
        if not tag:
            continue
        if index > settings.tagging_limit:
            ctx.warn(log_, ["tag_limit_exceeded", f"limit {settings.tagging_limit}"])
            break
        ctx.db.exec(f"INSERT INTO {table} ({key_col}, tag_name) VALUES (%s, %s) ON CONFLICT DO NOTHING", (key, str(tag)))


def domain_add(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["mailbox", "add", "domain", _mask(data)]
    if ctx.role != "admin":
        ctx.denied(log_)
        return False
    tpl_attrs = None
    if data.get("template"):
        tpl = get_templates(ctx, "domain", data["template"])
        tpl_attrs = tpl["attributes"] if tpl else None
    if not tpl_attrs:
        tpls = get_templates(ctx, "domain") or []
        tpl_attrs = tpls[0]["attributes"] if tpls else {}
    domain = idn_to_ascii((data.get("domain") or "").strip().lower())
    description = data.get("description") or domain
    tags = as_list(data["tags"]) if _isset(data, "tags") else tpl_attrs.get("tags", [])
    aliases = to_int(data["aliases"]) if _isset(data, "aliases") else int(tpl_attrs.get("max_num_aliases_for_domain", 400))
    mailboxes = to_int(data["mailboxes"]) if _isset(data, "mailboxes") else int(tpl_attrs.get("max_num_mboxes_for_domain", 10))
    defquota = to_int(data["defquota"]) if _isset(data, "defquota") else int(tpl_attrs.get("def_quota_for_mbox", 3072 * MB)) // MB
    maxquota = to_int(data["maxquota"]) if _isset(data, "maxquota") else int(tpl_attrs.get("max_quota_for_mbox", 10240 * MB)) // MB
    quota = to_int(data["quota"]) if _isset(data, "quota") else int(tpl_attrs.get("max_quota_for_domain", 10240 * MB)) // MB
    restart_sogo = to_int(data.get("restart_sogo"))
    if defquota > maxquota:
        ctx.err(log_, "mailbox_defquota_exceeds_mailbox_maxquota")
        return False
    if maxquota > quota:
        ctx.err(log_, "mailbox_quota_exceeds_domain_quota")
        return False
    if not defquota:
        ctx.err(log_, "defquota_empty")
        return False
    if not maxquota:
        ctx.err(log_, "maxquota_empty")
        return False
    active = to_int(data["active"]) if _isset(data, "active") else int(tpl_attrs.get("active", 1))
    relay_all = to_int(data["relay_all_recipients"]) if _isset(data, "relay_all_recipients") else int(tpl_attrs.get("relay_all_recipients", 0))
    relay_unknown = to_int(data["relay_unknown_only"]) if _isset(data, "relay_unknown_only") else int(tpl_attrs.get("relay_unknown_only", 0))
    backupmx = to_int(data["backupmx"]) if _isset(data, "backupmx") else int(tpl_attrs.get("backupmx", 0))
    gal = to_int(data["gal"]) if _isset(data, "gal") else int(tpl_attrs.get("gal", 1))
    if relay_all == 1:
        backupmx = 1
    if relay_unknown == 1:
        backupmx = 1
        relay_all = 1
    if not is_valid_domain_name(domain):
        ctx.err(log_, "domain_invalid")
        return False
    if ctx.db.count("SELECT domain FROM domain WHERE domain = %s", (domain,)) or ctx.db.count(
        "SELECT alias_domain FROM alias_domain WHERE alias_domain = %s", (domain,)
    ):
        ctx.err(log_, ["domain_exists", htmlspecialchars(domain)])
        return False
    if domain == settings.mailcow_hostname:
        ctx.err(log_, "domain_cannot_match_hostname")
        return False
    ctx.db.exec("DELETE FROM sender_acl WHERE external = 1 AND send_as LIKE %s", ("%@" + domain,))
    ctx.db.exec(
        """INSERT INTO domain (domain, description, aliases, mailboxes, defquota, maxquota, quota, backupmx, gal, active, relay_unknown_only, relay_all_recipients)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (domain, description, aliases, mailboxes, defquota, maxquota, quota, backupmx, gal, active, relay_unknown, relay_all),
    )
    _save_tags(ctx, "tags_domain", "domain", domain, tags, log_)
    try:
        ctx.redis.hset("DOMAIN_MAP", domain, 1)
    except Exception as exc:  # noqa: BLE001
        ctx.err(log_, ["redis_error", str(exc)])
        return False
    rl_value = to_int(data["rl_value"]) if _isset(data, "rl_value") else to_int(tpl_attrs.get("rl_value"))
    rl_frame = data.get("rl_frame") or tpl_attrs.get("rl_frame")
    if rl_value and rl_frame:
        ratelimit_edit(ctx, "domain", {"rl_value": rl_value, "rl_frame": rl_frame, "object": domain})
    key_size = to_int(data["key_size"]) if _isset(data, "key_size") else to_int(tpl_attrs.get("key_size"))
    dkim_selector = data.get("dkim_selector") or tpl_attrs.get("dkim_selector")
    if key_size and dkim_selector:
        if ctx.redis.hget("DKIM_SELECTORS", domain):
            ctx.ok(log_, "domain_add_dkim_available")
        else:
            dkim_add(ctx, {"key_size": key_size, "dkim_selector": dkim_selector, "domains": domain})
    if restart_sogo:
        resp = docker(ctx, "post", "sogo-mailcow", "restart")
        try:
            ok = json.loads(resp).get("type") == "success"
        except Exception:  # noqa: BLE001
            ok = False
        if not ok:
            ctx.warn(log_, "domain_added_sogo_failed")
            return False
    ctx.ok(log_, ["domain_added", htmlspecialchars(domain)])
    return True


def domain_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["mailbox", "edit", "domain", _mask(data)]
    for domain in as_list(data.get("domain")):
        domain = idn_to_ascii(str(domain))
        if not is_valid_domain_name(domain):
            ctx.err(log_, "domain_invalid")
            continue
        is_now = domain_details(ctx, domain)
        if ctx.role == "domainadmin" and own_domain_access(ctx, domain):
            if not is_now:
                ctx.err(log_, "domain_invalid")
                continue
            gal = to_int(data["gal"]) if _isset(data, "gal") else is_now["gal"]
            description = data["description"] if data.get("description") and ctx.has_acl("domain_desc") else is_now["description"]
            tags = as_list(data.get("tags")) if isinstance(data.get("tags"), list) else []
            ctx.db.exec("UPDATE domain SET description = %s, gal = %s WHERE domain = %s", (description, gal, domain))
            _save_tags(ctx, "tags_domain", "domain", domain, tags, log_)
            ctx.ok(log_, ["domain_modified", htmlspecialchars(domain)])
        elif ctx.role == "admin":
            if not is_now:
                ctx.err(log_, "domain_invalid")
                continue
            active = to_int(data["active"]) if _isset(data, "active") else is_now["active"]
            backupmx = to_int(data["backupmx"]) if _isset(data, "backupmx") else is_now["backupmx"]
            gal = to_int(data["gal"]) if _isset(data, "gal") else is_now["gal"]
            relay_all = to_int(data["relay_all_recipients"]) if _isset(data, "relay_all_recipients") else is_now["relay_all_recipients"]
            relay_unknown = to_int(data["relay_unknown_only"]) if _isset(data, "relay_unknown_only") else is_now["relay_unknown_only"]
            relayhost = to_int(data["relayhost"]) if _isset(data, "relayhost") else to_int(is_now["relayhost"])
            aliases = to_int(data["aliases"]) if data.get("aliases") else is_now["max_num_aliases_for_domain"]
            mailboxes = to_int(data["mailboxes"]) if _has_content(data, "mailboxes") else is_now["max_num_mboxes_for_domain"]
            defquota = to_int(data["defquota"]) if _has_content(data, "defquota") else is_now["def_quota_for_mbox"] // MB
            maxquota = to_int(data["maxquota"]) if data.get("maxquota") else is_now["max_quota_for_mbox"] // MB
            quota = to_int(data["quota"]) if data.get("quota") else is_now["max_quota_for_domain"] // MB
            description = data["description"] if data.get("description") else is_now["description"]
            tags = as_list(data.get("tags")) if isinstance(data.get("tags"), list) else []
            if relay_all == 1:
                backupmx = 1
            if relay_unknown == 1:
                backupmx = 1
                relay_all = 1
            mbd = ctx.db.one(
                """SELECT COUNT(*) AS count, MAX(COALESCE(ROUND(quota/1048576.0), 0)) AS biggest_mailbox,
                          COALESCE(ROUND(SUM(quota)/1048576.0), 0) AS quota_all
                   FROM mailbox WHERE (kind = '' OR kind IS NULL) AND domain = %s""",
                (domain,),
            )
            ald = ctx.db.one("SELECT COUNT(*) AS count FROM alias WHERE domain = %s AND address NOT IN (SELECT username FROM mailbox)", (domain,))
            if defquota > maxquota:
                ctx.err(log_, "mailbox_defquota_exceeds_mailbox_maxquota")
                continue
            if not defquota:
                ctx.err(log_, "defquota_empty")
                continue
            if maxquota > quota:
                ctx.err(log_, "mailbox_quota_exceeds_domain_quota")
                continue
            if not maxquota:
                ctx.err(log_, "maxquota_empty")
                continue
            if int(mbd["biggest_mailbox"] or 0) > maxquota:
                ctx.err(log_, ["max_quota_in_use", int(mbd["biggest_mailbox"])])
                continue
            if int(mbd["quota_all"] or 0) > quota:
                ctx.err(log_, ["domain_quota_m_in_use", int(mbd["quota_all"])])
                continue
            if int(mbd["count"]) > mailboxes:
                ctx.err(log_, ["mailboxes_in_use", int(mbd["count"])])
                continue
            if int(ald["count"]) > aliases:
                ctx.err(log_, ["aliases_in_use", int(ald["count"])])
                continue
            ctx.db.exec(
                """UPDATE domain SET relay_all_recipients = %s, relay_unknown_only = %s, backupmx = %s, gal = %s, active = %s,
                   quota = %s, defquota = %s, maxquota = %s, relayhost = %s, mailboxes = %s, aliases = %s, description = %s
                   WHERE domain = %s""",
                (relay_all, relay_unknown, backupmx, gal, active, quota, defquota, maxquota, str(relayhost), mailboxes, aliases, description, domain),
            )
            _save_tags(ctx, "tags_domain", "domain", domain, tags, log_)
            ctx.ok(log_, ["domain_modified", htmlspecialchars(domain)])
        else:
            ctx.denied(log_)
    return True


def domain_delete(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["mailbox", "delete", "domain", data]
    if ctx.role != "admin":
        ctx.denied(log_)
        return False
    for domain in as_list(data.get("domain")):
        if not is_valid_domain_name(domain):
            ctx.err(log_, "domain_invalid")
            continue
        domain = idn_to_ascii(domain.strip().lower())
        if ctx.db.count("SELECT username FROM mailbox WHERE domain = %s", (domain,)):
            ctx.err(log_, ["domain_not_empty", domain])
            continue
        resp = docker(ctx, "post", "dovecot-mailcow", "exec", {"cmd": "maildir", "task": "cleanup", "maildir": domain})
        try:
            gc = json.loads(resp)
        except Exception:  # noqa: BLE001
            gc = {"type": "error", "msg": str(resp)}
        if gc.get("type") != "success":
            ctx.warn(log_, f"Could not move mail storage to garbage collector: {gc.get('msg')}")
        ctx.db.exec("DELETE FROM domain WHERE domain = %s", (domain,))
        ctx.db.exec("DELETE FROM domain_admins WHERE domain = %s", (domain,))
        ctx.db.exec("DELETE FROM alias WHERE domain = %s", (domain,))
        ctx.db.exec("DELETE FROM alias_domain WHERE target_domain = %s", (domain,))
        ctx.db.exec("DELETE FROM mailbox WHERE domain = %s", (domain,))
        like = "%@" + domain
        ctx.db.exec("DELETE FROM sender_acl WHERE logged_in_as LIKE %s", (like,))
        ctx.db.exec("DELETE FROM quota2 WHERE username LIKE %s", (like,))
        ctx.db.exec("DELETE FROM pushover WHERE username LIKE %s", (like,))
        ctx.db.exec("DELETE FROM quota2replica WHERE username LIKE %s", (like,))
        ctx.db.exec("DELETE FROM spamalias WHERE address LIKE %s", (like,))
        ctx.db.exec("DELETE FROM filterconf WHERE object = %s", (domain,))
        ctx.db.exec("DELETE FROM bcc_maps WHERE local_dest = %s", (domain,))
        ctx.db.exec("DELETE FROM admin WHERE superadmin = 0 AND username NOT IN (SELECT username FROM domain_admins)")
        ctx.db.exec("DELETE FROM da_acl WHERE username NOT IN (SELECT username FROM domain_admins)")
        try:
            ctx.redis.hdel("DOMAIN_MAP", domain)
            ctx.redis.hdel("RL_VALUE", domain)
        except Exception as exc:  # noqa: BLE001
            ctx.err(log_, ["redis_error", str(exc)])
            continue
        ctx.ok(log_, ["domain_removed", htmlspecialchars(domain)])
    return True


# ---------------------------------------------------------------------------
# alias domains
# ---------------------------------------------------------------------------
def get_alias_domains(ctx: Context, domain: str | None = None) -> list[str]:
    if domain is not None:
        if not own_domain_access(ctx, domain):
            return []
        rows = ctx.db.all("SELECT alias_domain FROM alias_domain WHERE target_domain = %s ORDER BY alias_domain", (domain,))
    else:
        rows = ctx.db.all(
            """SELECT alias_domain FROM alias_domain
               WHERE target_domain IN (SELECT domain FROM domain_admins WHERE active = 1 AND username = %s) OR 'admin' = %s
               ORDER BY alias_domain""",
            (ctx.username, ctx.role),
        )
    return [r["alias_domain"] for r in rows]


def alias_domain_details(ctx: Context, alias_domain: str) -> dict[str, Any] | None:
    row = ctx.db.one("SELECT alias_domain, target_domain, active, created, modified FROM alias_domain WHERE alias_domain = %s", (alias_domain,))
    if not row:
        return None
    if not own_domain_access(ctx, row["target_domain"]):
        return None
    parent = ctx.db.one("SELECT backupmx FROM domain WHERE domain = %s", (row["target_domain"],))
    return {
        "alias_domain": row["alias_domain"],
        "parent_is_backupmx": int(parent["backupmx"]) if parent else 0,
        "target_domain": row["target_domain"],
        "active": int(row["active"]),
        "active_int": int(row["active"]),
        "rl": ratelimit_get(ctx, "domain", alias_domain),
        "created": row["created"],
        "modified": row["modified"],
    }


def alias_domain_add(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["mailbox", "add", "alias_domain", data]
    active = to_int(data.get("active"))
    alias_domains = split_list(data.get("alias_domain"))
    target_domain = idn_to_ascii((data.get("target_domain") or "").strip().lower())
    if not ctx.has_acl("alias_domains"):
        ctx.denied(log_)
        return False
    if not is_valid_domain_name(target_domain):
        ctx.err(log_, "target_domain_invalid")
        return False
    if not own_domain_access(ctx, target_domain):
        ctx.denied(log_)
        return False
    for alias_domain in alias_domains:
        alias_domain = idn_to_ascii(alias_domain.strip().lower())
        if not is_valid_domain_name(alias_domain):
            ctx.err(log_, ["alias_domain_invalid", htmlspecialchars(alias_domain)])
            continue
        if alias_domain == target_domain:
            ctx.err(log_, ["aliasd_targetd_identical", htmlspecialchars(target_domain)])
            continue
        if not ctx.db.count("SELECT domain FROM domain WHERE domain = %s", (target_domain,)):
            ctx.err(log_, ["targetd_not_found", htmlspecialchars(target_domain)])
            continue
        if ctx.db.count("SELECT domain FROM domain WHERE domain = %s AND backupmx = 1", (target_domain,)):
            ctx.err(log_, ["targetd_relay_domain", htmlspecialchars(target_domain)])
            continue
        if ctx.db.count(
            "SELECT alias_domain FROM alias_domain WHERE alias_domain = %s UNION SELECT domain FROM domain WHERE domain = %s",
            (alias_domain, alias_domain),
        ):
            ctx.err(log_, ["alias_domain_invalid", alias_domain])
            continue
        ctx.db.exec("DELETE FROM sender_acl WHERE external = 1 AND send_as LIKE %s", ("%@" + alias_domain,))
        ctx.db.exec(
            "INSERT INTO alias_domain (alias_domain, target_domain, active) VALUES (%s, %s, %s)", (alias_domain, target_domain, active)
        )
        try:
            ctx.redis.hset("DOMAIN_MAP", alias_domain, 1)
        except Exception as exc:  # noqa: BLE001
            ctx.err(log_, ["redis_error", str(exc)])
            return False
        if to_int(data.get("rl_value")):
            ratelimit_edit(ctx, "domain", {"rl_value": data["rl_value"], "rl_frame": data.get("rl_frame"), "object": alias_domain})
        if data.get("key_size") and data.get("dkim_selector"):
            if ctx.redis.hget("DKIM_SELECTORS", alias_domain):
                ctx.ok(log_, "domain_add_dkim_available")
            else:
                dkim_add(ctx, {"key_size": data["key_size"], "dkim_selector": data["dkim_selector"], "domains": alias_domain})
        ctx.ok(log_, ["aliasd_added", htmlspecialchars(alias_domain)])
    return True


def alias_domain_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["mailbox", "edit", "alias_domain", data]
    for alias_domain in as_list(data.get("alias_domain")):
        alias_domain = idn_to_ascii(str(alias_domain).strip().lower())
        is_now = alias_domain_details(ctx, alias_domain)
        if not is_now:
            ctx.err(log_, ["alias_domain_invalid", htmlspecialchars(alias_domain)])
            continue
        active = to_int(data["active"]) if _isset(data, "active") else is_now["active"]
        target_domain = idn_to_ascii(data["target_domain"].strip().lower()) if data.get("target_domain") else is_now["target_domain"]
        if not is_valid_domain_name(target_domain):
            ctx.err(log_, ["target_domain_invalid", htmlspecialchars(target_domain)])
            continue
        if not own_domain_access(ctx, target_domain):
            ctx.denied(log_)
            continue
        if not domain_details(ctx, target_domain) or alias_domain_details(ctx, target_domain):
            ctx.err(log_, ["target_domain_invalid", htmlspecialchars(target_domain)])
            continue
        ctx.db.exec("UPDATE alias_domain SET target_domain = %s, active = %s WHERE alias_domain = %s", (target_domain, active, alias_domain))
        ctx.ok(log_, ["aliasd_modified", htmlspecialchars(alias_domain)])
    return True


def alias_domain_delete(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["mailbox", "delete", "alias_domain", data]
    for alias_domain in as_list(data.get("alias_domain")):
        if not is_valid_domain_name(alias_domain):
            ctx.err(log_, "domain_invalid")
            continue
        row = ctx.db.one("SELECT target_domain FROM alias_domain WHERE alias_domain = %s", (alias_domain,))
        if not row or not own_domain_access(ctx, row["target_domain"]):
            ctx.denied(log_)
            continue
        ctx.db.exec("DELETE FROM alias_domain WHERE alias_domain = %s", (alias_domain,))
        ctx.db.exec("DELETE FROM alias WHERE domain = %s", (alias_domain,))
        ctx.db.exec("DELETE FROM spamalias WHERE address LIKE %s", ("%@" + alias_domain,))
        ctx.db.exec("DELETE FROM bcc_maps WHERE local_dest = %s", (alias_domain,))
        try:
            ctx.redis.hdel("DOMAIN_MAP", alias_domain)
            ctx.redis.hdel("RL_VALUE", alias_domain)
        except Exception as exc:  # noqa: BLE001
            ctx.err(log_, ["redis_error", str(exc)])
            continue
        ctx.ok(log_, ["alias_domain_removed", htmlspecialchars(alias_domain)])
    return True


# ---------------------------------------------------------------------------
# mailboxes
# ---------------------------------------------------------------------------
def get_mailboxes(ctx: Context, domain: str | None = None, tags: list[str] | None = None) -> list[str]:
    if tags and domain is not None:
        rows = ctx.db.all(
            "SELECT DISTINCT username FROM tags_mailbox WHERE username LIKE %s AND (" + " OR ".join(["tag_name LIKE %s"] * len(tags)) + ")",
            (f"%{domain}%", *[f"%{t}%" for t in tags]),
        )
        return [r["username"] for r in rows if own_domain_access(ctx, r["username"].split("@")[-1])]
    if domain is not None and own_domain_access(ctx, domain):
        rows = ctx.db.all("SELECT username FROM mailbox WHERE (kind = '' OR kind IS NULL) AND domain = %s ORDER BY username", (domain,))
        return [r["username"] for r in rows]
    rows = ctx.db.all(
        """SELECT username FROM mailbox WHERE (kind = '' OR kind IS NULL)
           AND (domain IN (SELECT domain FROM domain_admins WHERE active = 1 AND username = %s) OR 'admin' = %s)
           ORDER BY username""",
        (ctx.username, ctx.role),
    )
    return [r["username"] for r in rows]


def mailbox_details(ctx: Context, username: str, reduced: bool = False) -> dict[str, Any] | None:
    if not own_mailbox_access(ctx, username):
        return None
    quota_table = "quota2" if settings.master else "quota2replica"
    row = ctx.db.one(
        f"""SELECT domain.backupmx, mailbox.username, mailbox.name, mailbox.active, mailbox.domain, mailbox.local_part,
                   mailbox.quota, mailbox.created, mailbox.modified, mailbox.authsource, {quota_table}.bytes, attributes,
                   custom_attributes, {quota_table}.messages
            FROM mailbox
            JOIN domain ON domain.domain = mailbox.domain
            LEFT JOIN {quota_table} ON mailbox.username = {quota_table}.username
            WHERE (mailbox.kind = '' OR mailbox.kind IS NULL) AND mailbox.username = %s""",
        (username,),
    )
    if not row:
        return None
    attrs = row["attributes"] or {}
    m: dict[str, Any] = {
        "username": row["username"],
        "active": int(row["active"]),
        "active_int": int(row["active"]),
        "domain": row["domain"],
        "name": row["name"],
        "local_part": row["local_part"],
        "quota": int(row["quota"]),
        "messages": int(row["messages"] or 0),
        "attributes": attrs,
        "custom_attributes": row["custom_attributes"] or {},
        "quota_used": int(row["bytes"] or 0),
        "created": row["created"],
        "modified": row["modified"],
        "authsource": row["authsource"] or "mailcow",
    }
    m["percent_in_use"] = "- " if int(row["quota"]) == 0 else round(m["quota_used"] / int(row["quota"]) * 100)
    if m["percent_in_use"] == "- ":
        m["percent_class"] = "info"
    elif m["percent_in_use"] >= 90:
        m["percent_class"] = "danger"
    elif m["percent_in_use"] >= 75:
        m["percent_class"] = "warning"
    else:
        m["percent_class"] = "success"
    last = {"imap": 0, "smtp": 0, "pop3": 0, "SSO": 0}
    for r in ctx.db.all("SELECT MAX(datetime) AS datetime, service FROM sasl_log WHERE username = %s GROUP BY service", (username,)):
        if r["service"] in last and settings.show_last_login:
            last[r["service"]] = int(r["datetime"].timestamp())
    m["last_imap_login"], m["last_smtp_login"], m["last_pop3_login"], m["last_sso_login"] = last["imap"], last["smtp"], last["pop3"], last["SSO"]
    if not reduced:
        rl = ratelimit_get(ctx, "mailbox", username)
        dq = ctx.db.one("SELECT maxquota, quota FROM domain WHERE domain = %s", (row["domain"],))
        po = ctx.db.one("SELECT COUNT(active) AS pushover_active FROM pushover WHERE username = %s AND active = 1", (username,))
        mu = ctx.db.one(
            "SELECT COALESCE(SUM(quota), 0) AS in_use FROM mailbox WHERE (kind = '' OR kind IS NULL) AND domain = %s AND username != %s",
            (row["domain"], username),
        )
        sa = ctx.db.one("SELECT COUNT(address) AS sa_count FROM spamalias WHERE goto = %s AND validity >= %s", (username, int(time.time())))
        m["max_new_quota"] = min(int(dq["quota"]) * MB - int(mu["in_use"]), int(dq["maxquota"]) * MB)
        m["spam_aliases"] = int(sa["sa_count"] or 0)
        m["pushover_active"] = 1 if int(po["pushover_active"] or 0) == 1 else 0
        if rl:
            m["rl"], m["rl_scope"] = rl, "mailbox"
        else:
            m["rl"], m["rl_scope"] = ratelimit_get(ctx, "domain", row["domain"]), "domain"
        m["is_relayed"] = int(row["backupmx"])
    m["tags"] = [r["tag_name"] for r in ctx.db.all("SELECT tag_name FROM tags_mailbox WHERE username = %s", (username,))]
    return m


def _protocol_access(data: dict[str, Any]) -> None:
    if _isset(data, "protocol_access"):
        pa = as_list(data["protocol_access"])
        for p in ("imap", "pop3", "smtp", "sieve"):
            data[f"{p}_access"] = 1 if p in pa else 0


def mailbox_add(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["mailbox", "add", "mailbox", _mask(data)]
    local_part = (data.get("local_part") or "").strip().lower()
    domain = idn_to_ascii((data.get("domain") or "").strip().lower())
    username = f"{local_part}@{domain}"
    if not is_email(username) or not local_part:
        ctx.err(log_, "mailbox_invalid")
        return False
    authsource = "mailcow"  # external identity providers are not supported in this port
    tpl_attrs = None
    if data.get("template"):
        tpl = get_templates(ctx, "mailbox", data["template"])
        tpl_attrs = tpl["attributes"] if tpl else None
    if not tpl_attrs:
        tpls = get_templates(ctx, "mailbox") or []
        tpl_attrs = tpls[0]["attributes"] if tpls else {}
    defaults = {**settings.mailbox_default_attributes, **tpl_attrs}
    password, password2 = data.get("password"), data.get("password2")
    name = (data.get("name") or "").rstrip(">").lstrip("<") or local_part
    tags = as_list(data["tags"]) if _isset(data, "tags") else defaults.get("tags", [])
    quota_m = to_int(data["quota"]) if _isset(data, "quota") else int(defaults.get("quota", 0)) // MB
    if not ctx.has_acl("unlimited_quota") and quota_m == 0:
        ctx.err(log_, "unlimited_quota_acl")
        return False
    _protocol_access(data)

    def pick(key: str, default_key: str | None = None) -> int:
        if _isset(data, key):
            return to_int(data[key])
        return to_int(defaults.get(default_key or key, 0))

    active = pick("active")
    force_pw_update = pick("force_pw_update")
    tls_in, tls_out = pick("tls_enforce_in"), pick("tls_enforce_out")
    sogo_access = pick("sogo_access")
    imap_access, pop3_access, smtp_access, sieve_access = pick("imap_access"), pick("pop3_access"), pick("smtp_access"), pick("sieve_access")
    relayhost = to_int(data.get("relayhost"))
    q_notif = str(data["quarantine_notification"]) if _isset(data, "quarantine_notification") else str(defaults.get("quarantine_notification"))
    q_cat = str(data["quarantine_category"]) if _isset(data, "quarantine_category") else str(defaults.get("quarantine_category"))
    attribute_hash = data.get("attribute_hash") or ""
    quota_b = quota_m * MB
    attrs = {
        "force_pw_update": str(force_pw_update),
        "tls_enforce_in": str(tls_in),
        "tls_enforce_out": str(tls_out),
        "sogo_access": str(sogo_access),
        "imap_access": str(imap_access),
        "pop3_access": str(pop3_access),
        "smtp_access": str(smtp_access),
        "sieve_access": str(sieve_access),
        "relayhost": str(relayhost),
        "passwd_update": time.strftime("%Y-%m-%d %H:%M:%S"),
        "mailbox_format": str(defaults.get("mailbox_format", "maildir:")),
        "quarantine_notification": q_notif,
        "quarantine_category": q_cat,
        "attribute_hash": attribute_hash,
    }
    if not is_valid_domain_name(domain):
        ctx.err(log_, "domain_invalid")
        return False
    if not own_domain_access(ctx, domain):
        ctx.denied(log_)
        return False
    dd = ctx.db.one("SELECT mailboxes, maxquota, quota FROM domain WHERE domain = %s", (domain,))
    md = ctx.db.one(
        "SELECT COUNT(*) AS count, COALESCE(ROUND(SUM(quota)/1048576.0), 0) AS quota FROM mailbox WHERE (kind = '' OR kind IS NULL) AND domain = %s",
        (domain,),
    )
    if ctx.db.count("SELECT local_part FROM mailbox WHERE local_part = %s AND domain = %s", (local_part, domain)):
        ctx.err(log_, ["object_exists", htmlspecialchars(username)])
        return False
    if ctx.db.count("SELECT address FROM alias WHERE address = %s", (username,)):
        ctx.err(log_, ["is_alias", htmlspecialchars(username)])
        return False
    if ctx.db.count("SELECT address FROM spamalias WHERE address = %s", (username,)):
        ctx.err(log_, ["is_spam_alias", htmlspecialchars(username)])
        return False
    if not dd:
        ctx.err(log_, ["domain_not_found", htmlspecialchars(domain)])
        return False
    if not password_check(ctx, password, password2):
        return False
    password_hashed = hash_password(password)
    if int(md["count"]) >= int(dd["mailboxes"]):
        ctx.err(log_, ["max_mailbox_exceeded", int(md["count"]), int(dd["mailboxes"])])
        return False
    if quota_m > int(dd["maxquota"]):
        ctx.err(log_, ["mailbox_quota_exceeded", int(dd["maxquota"])])
        return False
    if int(md["quota"]) + quota_m > int(dd["quota"]):
        ctx.err(log_, ["mailbox_quota_left_exceeded", int(dd["quota"]) - int(md["quota"])])
        return False
    ctx.db.exec(
        """INSERT INTO mailbox (username, password, name, quota, local_part, domain, attributes, authsource, active)
           VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)""",
        (username, password_hashed, name, quota_b, local_part, domain, json.dumps(attrs), authsource, active),
    )
    _save_tags(ctx, "tags_mailbox", "username", username, tags, log_)
    for t in ("quota2", "quota2replica"):
        ctx.db.exec(
            f"INSERT INTO {t} (username, bytes, messages) VALUES (%s, 0, 0) ON CONFLICT (username) DO UPDATE SET bytes = 0, messages = 0",
            (username,),
        )
    ctx.db.exec("INSERT INTO alias (address, goto, domain, active) VALUES (%s, %s, %s, %s)", (username, username, domain, active))
    acl_fields = [
        "spam_alias", "tls_policy", "spam_score", "spam_policy", "delimiter_action", "syncjobs", "eas_reset", "sogo_profile_reset",
        "pushover", "quarantine", "quarantine_attachments", "quarantine_notification", "quarantine_category", "app_passwds", "pw_reset",
    ]
    if _isset(data, "acl"):
        acl_list = as_list(data["acl"])
        acl_vals = {f: (1 if f in acl_list else 0) for f in acl_fields}
    else:
        acl_vals = {f: to_int(defaults.get(f"acl_{f}", 1 if f != "syncjobs" and f != "sogo_profile_reset" else 0)) for f in acl_fields}
    cols = ", ".join(["username"] + acl_fields)
    marks = ", ".join(["%s"] * (len(acl_fields) + 1))
    ctx.db.exec(f"INSERT INTO user_acl ({cols}) VALUES ({marks})", (username, *[acl_vals[f] for f in acl_fields]))
    rl_frame = data.get("rl_frame") or defaults.get("rl_frame")
    rl_value = data.get("rl_value") if _isset(data, "rl_value") else defaults.get("rl_value")
    if rl_frame and rl_value:
        ratelimit_edit(ctx, "mailbox", {"object": username, "rl_frame": rl_frame, "rl_value": rl_value})
    try:
        update_sogo_static_view(ctx, username)
    except Exception as exc:  # noqa: BLE001
        ctx.err(log_, str(exc))
    ctx.ok(log_, ["mailbox_added", htmlspecialchars(username)])
    return True


def sender_acl_handles(ctx: Context, username: str) -> dict[str, Any] | None:
    if ctx.role not in ("admin", "domainadmin"):
        return None
    d: dict[str, Any] = {
        "sender_acl_domains": {"ro": [], "rw": [], "selectable": []},
        "sender_acl_addresses": {"ro": [], "rw": [], "selectable": []},
        "fixed_sender_aliases": [],
        "external_sender_aliases": [],
    }
    for r in ctx.db.all("SELECT address FROM alias WHERE goto ~ %s AND address NOT LIKE '@%%'", (_goto_regex(username),)):
        d["fixed_sender_aliases"].append(r["address"])
    for r in ctx.db.all(
        """SELECT local_part || '@' || alias_domain.alias_domain AS alias_domain_alias FROM mailbox, alias_domain
           WHERE alias_domain.target_domain = mailbox.domain AND mailbox.username = %s""",
        (username,),
    ):
        if r["alias_domain_alias"]:
            d["fixed_sender_aliases"].append(r["alias_domain_alias"])
    for r in ctx.db.all("SELECT send_as FROM sender_acl WHERE logged_in_as = %s AND external = 1", (username,)):
        d["external_sender_aliases"].append(r["send_as"])
    for r in ctx.db.all(
        "SELECT REPLACE(send_as, '@', '') AS send_as FROM sender_acl WHERE logged_in_as = %s AND external = 0 AND (send_as LIKE '@%%' OR send_as = '*')",
        (username,),
    ):
        v = r["send_as"]
        if is_valid_domain_name(v):
            (d["sender_acl_domains"]["rw"] if own_domain_access(ctx, v) else d["sender_acl_domains"]["ro"]).append(v)
        elif v == "*":
            (d["sender_acl_domains"]["rw"] if ctx.role == "admin" else d["sender_acl_domains"]["ro"]).append(v)
    for r in ctx.db.all(
        "SELECT send_as FROM sender_acl WHERE logged_in_as = %s AND external = 0 AND send_as NOT LIKE '@%%' AND send_as != '*'", (username,)
    ):
        v = r["send_as"]
        if is_email(v):
            (d["sender_acl_addresses"]["rw"] if has_alias_object_access(ctx, ctx.username, ctx.role, v) else d["sender_acl_addresses"]["ro"]).append(v)
    for r in ctx.db.all(
        """SELECT domain FROM domain WHERE domain NOT IN (
             SELECT REPLACE(send_as, '@', '') FROM sender_acl WHERE logged_in_as = %s AND external = 0 AND send_as LIKE '@%%')
           UNION SELECT '*' FROM domain WHERE '*' NOT IN (SELECT send_as FROM sender_acl WHERE logged_in_as = %s AND external = 0)""",
        (username, username),
    ):
        v = r["domain"]
        if is_valid_domain_name(v) and own_domain_access(ctx, v):
            d["sender_acl_domains"]["selectable"].append(v)
        elif v == "*" and ctx.role == "admin":
            d["sender_acl_domains"]["selectable"].append(v)
    for r in ctx.db.all(
        """SELECT address FROM alias WHERE goto != %s AND address NOT IN (
             SELECT send_as FROM sender_acl WHERE logged_in_as = %s AND external = 0 AND send_as NOT LIKE '@%%')""",
        (username, username),
    ):
        v = r["address"]
        if v in d["fixed_sender_aliases"]:
            continue
        if is_email(v) and has_alias_object_access(ctx, ctx.username, ctx.role, v):
            d["sender_acl_addresses"]["selectable"].append(v)
    return d


def _apply_sender_acl(ctx: Context, username: str, data: dict[str, Any], log_: list) -> None:
    if _isset(data, "extended_sender_acl"):
        if not ctx.has_acl("extend_sender_acl"):
            ctx.err(log_, "extended_sender_acl_denied")
        else:
            known = set(get_domains(ctx)) | set(get_alias_domains(ctx))
            extra: list[str] = []
            for item in split_list(data["extended_sender_acl"]):
                item = item.lstrip("@")
                if not is_email(item) and not is_valid_domain_name(item):
                    ctx.err(log_, ["extra_acl_invalid", htmlspecialchars(item)])
                    continue
                if is_email(item):
                    dom = idn_to_ascii(item.split("@")[-1])
                    if dom in known:
                        ctx.err(log_, ["extra_acl_invalid_domain", dom])
                        continue
                    extra.append(item)
                else:
                    if item in known:
                        ctx.err(log_, ["extra_acl_invalid_domain", item])
                        continue
                    extra.append("@" + item)
            ctx.db.exec("DELETE FROM sender_acl WHERE external = 1 AND logged_in_as = %s", (username,))
            for item in dict.fromkeys(extra):
                ctx.db.exec("INSERT INTO sender_acl (send_as, logged_in_as, external) VALUES (%s, %s, 1)", (item, username))
    if _isset(data, "sender_acl"):
        handles = sender_acl_handles(ctx, username) or {}
        admin_set = list((handles.get("sender_acl_domains") or {}).get("ro", [])) + list((handles.get("sender_acl_addresses") or {}).get("ro", []))
        wanted = as_list(data["sender_acl"])
        if "*" in wanted:
            da_set = ["*"]
        elif wanted == ["default"]:
            da_set = []
        else:
            da_set = [w for w in wanted if w != "default"]
        if da_set or admin_set:
            known = set(get_domains(ctx)) | set(get_alias_domains(ctx))
            valid: list[str] = []
            for val in da_set:
                if not is_email(val) and not is_valid_domain_name(val.lstrip("@")) and val != "*":
                    ctx.err(log_, ["sender_acl_invalid", val])
                    continue
                dom = val.lstrip("@")
                if is_valid_domain_name(dom):
                    if known and dom not in known:
                        ctx.err(log_, ["sender_acl_invalid", val])
                        continue
                    if not own_domain_access(ctx, dom):
                        ctx.err(log_, ["sender_acl_invalid", val])
                        continue
                if val == "*" and ctx.role != "admin":
                    ctx.err(log_, ["sender_acl_invalid", val])
                    continue
                if is_email(val) and not has_alias_object_access(ctx, ctx.username, ctx.role, val):
                    ctx.err(log_, ["sender_acl_invalid", val])
                    continue
                valid.append(val)
            merged = valid + admin_set
            if "*" in merged:
                merged = ["*"]
            ctx.db.exec("DELETE FROM sender_acl WHERE external = 0 AND logged_in_as = %s", (username,))
            fixed = handles.get("fixed_sender_aliases", [])
            for item in merged:
                dom = item.lstrip("@")
                if is_valid_domain_name(dom):
                    item = "@" + dom
                if item in fixed:
                    continue
                ctx.db.exec("INSERT INTO sender_acl (send_as, logged_in_as) VALUES (%s, %s)", (item, username))
        else:
            ctx.db.exec("DELETE FROM sender_acl WHERE external = 0 AND logged_in_as = %s", (username,))


def mailbox_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["mailbox", "edit", "mailbox", _mask(data)]
    for username in as_list(data.get("username")):
        if not is_email(username):
            ctx.err(log_, ["username_invalid", username])
            continue
        is_now = mailbox_details(ctx, username)
        _protocol_access(data)
        if not is_now:
            ctx.denied(log_)
            continue
        attrs = is_now["attributes"]
        active = to_int(data["active"]) if _isset(data, "active") else is_now["active"]
        force_pw_update = to_int(data["force_pw_update"]) if _isset(data, "force_pw_update") else to_int(attrs.get("force_pw_update"))
        sogo_access = to_int(data["sogo_access"]) if _isset(data, "sogo_access") and ctx.has_acl("sogo_access") else to_int(attrs.get("sogo_access"))
        prot = {}
        for p in ("imap", "pop3", "smtp", "sieve"):
            prot[p] = to_int(data[f"{p}_access"]) if _isset(data, f"{p}_access") and ctx.has_acl("protocol_access") else to_int(attrs.get(f"{p}_access"))
        relayhost = to_int(data["relayhost"]) if _isset(data, "relayhost") and ctx.has_acl("mailbox_relayhost") else to_int(attrs.get("relayhost"))
        quota_m = to_int(data["quota"]) if _has_content(data, "quota") else is_now["quota"] // MB
        name = data["name"].rstrip(">").lstrip("<") if data.get("name") else is_now["name"]
        domain = is_now["domain"]
        quota_b = quota_m * MB
        password, password2 = data.get("password") or None, data.get("password2") or None
        tags = as_list(data.get("tags")) if isinstance(data.get("tags"), list) else []
        attribute_hash = data.get("attribute_hash") or ""
        authsource = is_now["authsource"]
        recovery_email = data["pw_recovery_email"] if _isset(data, "pw_recovery_email") else attrs.get("recovery_email")
        if not ctx.has_acl("unlimited_quota") and quota_m == 0 and is_now["quota"] != 0:
            ctx.err(log_, "unlimited_quota_acl")
            return False
        if not own_domain_access(ctx, domain):
            ctx.denied(log_)
            continue
        dd = domain_details(ctx, domain) or {}
        if quota_m > is_now["max_new_quota"] // MB:
            ctx.err(log_, ["mailbox_quota_left_exceeded", is_now["max_new_quota"] // MB])
            continue
        if quota_m > dd.get("max_quota_for_mbox", 0) // MB:
            ctx.err(log_, ["mailbox_quota_exceeded", dd.get("max_quota_for_mbox", 0) // MB])
            continue
        _apply_sender_acl(ctx, username, data, log_)
        if password:
            if not password_check(ctx, password, password2):
                continue
            ctx.db.exec(
                "UPDATE mailbox SET password = %s, attributes = jsonb_set(attributes, '{passwd_update}', to_jsonb(NOW()::text)) "
                "WHERE username = %s AND authsource = 'mailcow'",
                (hash_password(password), username),
            )
        ctx.db.exec("UPDATE alias SET active = %s WHERE address = %s", (active, username))
        new_attrs = {
            "force_pw_update": str(force_pw_update),
            "sogo_access": str(sogo_access),
            "imap_access": str(prot["imap"]),
            "sieve_access": str(prot["sieve"]),
            "pop3_access": str(prot["pop3"]),
            "relayhost": str(relayhost),
            "smtp_access": str(prot["smtp"]),
            "recovery_email": recovery_email or "",
            "attribute_hash": attribute_hash,
        }
        ctx.db.exec(
            "UPDATE mailbox SET active = %s, name = %s, quota = %s, authsource = %s, attributes = COALESCE(attributes, '{}'::jsonb) || %s::jsonb WHERE username = %s",
            (active, name, quota_b, authsource, json.dumps(new_attrs), username),
        )
        _save_tags(ctx, "tags_mailbox", "username", username, tags, log_)
        ctx.ok(log_, ["mailbox_modified", username])
        try:
            update_sogo_static_view(ctx, username)
        except Exception as exc:  # noqa: BLE001
            ctx.err(log_, str(exc))
    return True


def mailbox_delete(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["mailbox", "delete", "mailbox", data]
    for username in as_list(data.get("username")):
        if not is_email(username):
            ctx.denied(log_)
            continue
        if not own_mailbox_access(ctx, username):
            ctx.denied(log_)
            continue
        details = mailbox_details(ctx, username)
        if details and details.get("domain") and details.get("local_part"):
            fields = {"cmd": "maildir", "task": "cleanup", "maildir": f"{details['domain']}/{details['local_part']}"}
            if settings.clustermode == "replication":
                docker(ctx, "broadcast", "dovecot-mailcow", "exec", fields)
            else:
                resp = docker(ctx, "post", "dovecot-mailcow", "exec", fields)
                try:
                    gc = json.loads(resp)
                except Exception:  # noqa: BLE001
                    gc = {"type": "error", "msg": str(resp)}
                if gc.get("type") != "success":
                    ctx.warn(log_, f"Could not move maildir to garbage collector: {gc.get('msg')}")
        else:
            ctx.warn(log_, "Could not move maildir to garbage collector: variables local_part and/or domain empty")
        for q in (
            "DELETE FROM alias WHERE goto = %s",
            "DELETE FROM pushover WHERE username = %s",
            "DELETE FROM quarantine WHERE rcpt = %s",
            "DELETE FROM quota2 WHERE username = %s",
            "DELETE FROM quota2replica WHERE username = %s",
            "DELETE FROM mailbox WHERE username = %s",
            "DELETE FROM user_acl WHERE username = %s",
            "DELETE FROM spamalias WHERE goto = %s",
            "DELETE FROM imapsync WHERE user2 = %s",
            "DELETE FROM filterconf WHERE object = %s",
            "DELETE FROM sogo_user_profile WHERE c_uid = %s",
            "DELETE FROM sogo_cache_folder WHERE c_uid = %s",
            "DELETE FROM sogo_store WHERE c_folder_id IN (SELECT c_folder_id FROM sogo_folder_info WHERE c_path2 = %s)",
            "DELETE FROM sogo_quick_contact WHERE c_folder_id IN (SELECT c_folder_id FROM sogo_folder_info WHERE c_path2 = %s)",
            "DELETE FROM sogo_quick_appointment WHERE c_folder_id IN (SELECT c_folder_id FROM sogo_folder_info WHERE c_path2 = %s)",
            "DELETE FROM sogo_folder_info WHERE c_path2 = %s",
            "DELETE FROM bcc_maps WHERE local_dest = %s",
            "DELETE FROM oauth_access_tokens WHERE user_id = %s",
            "DELETE FROM oauth_refresh_tokens WHERE user_id = %s",
            "DELETE FROM oauth_authorization_codes WHERE user_id = %s",
            "DELETE FROM tfa WHERE username = %s",
            "DELETE FROM fido2 WHERE username = %s",
        ):
            ctx.db.exec(q, (username,))
        ctx.db.exec("DELETE FROM sender_acl WHERE logged_in_as = %s OR send_as = %s", (username, username))
        ctx.db.exec("DELETE FROM sogo_acl WHERE c_object LIKE %s OR c_uid = %s", ("%/" + username.replace("%", "\\%") + "/%", username))
        for r in ctx.db.all("SELECT address, goto FROM alias WHERE goto ~ %s", (_goto_regex(username),)):
            gotos = [g for g in r["goto"].split(",") if g != username]
            ctx.db.exec("UPDATE alias SET goto = %s WHERE address = %s", (",".join(gotos), r["address"]))
        try:
            ctx.redis.hdel("RL_VALUE", username)
        except Exception as exc:  # noqa: BLE001
            ctx.err(log_, ["redis_error", str(exc)])
            continue
        try:
            update_sogo_static_view(ctx, username)
        except Exception as exc:  # noqa: BLE001
            ctx.err(log_, str(exc))
        ctx.ok(log_, ["mailbox_removed", htmlspecialchars(username)])
    return True


# ---------------------------------------------------------------------------
# mailbox user settings
# ---------------------------------------------------------------------------
def _attr_target(ctx: Context, username: str | None) -> str | None:
    if username and is_email(username):
        if not own_mailbox_access(ctx, username):
            return None
        return username
    return ctx.username


def _mailbox_attrs(ctx: Context, username: str) -> dict[str, Any]:
    row = ctx.db.one("SELECT attributes FROM mailbox WHERE username = %s", (username,))
    return (row or {}).get("attributes") or {}


def tls_policy_get(ctx: Context, username: str | None) -> dict[str, Any] | None:
    target = _attr_target(ctx, username)
    if not target:
        return None
    attrs = _mailbox_attrs(ctx, target)
    return {"tls_enforce_in": attrs.get("tls_enforce_in"), "tls_enforce_out": attrs.get("tls_enforce_out")}


def tls_policy_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["mailbox", "edit", "tls_policy", data]
    if not ctx.has_acl("tls_policy"):
        ctx.denied(log_)
        return False
    for username in as_list(data.get("username")):
        if not own_mailbox_access(ctx, username):
            ctx.denied(log_)
            continue
        is_now = tls_policy_get(ctx, username)
        if not is_now:
            ctx.denied(log_)
            continue
        tls_in = to_int(data["tls_enforce_in"]) if _isset(data, "tls_enforce_in") else to_int(is_now["tls_enforce_in"])
        tls_out = to_int(data["tls_enforce_out"]) if _isset(data, "tls_enforce_out") else to_int(is_now["tls_enforce_out"])
        ctx.db.exec(
            "UPDATE mailbox SET attributes = attributes || %s::jsonb WHERE username = %s",
            (json.dumps({"tls_enforce_in": str(tls_in), "tls_enforce_out": str(tls_out)}), username),
        )
        ctx.ok(log_, ["mailbox_modified", username])
    return True


def quarantine_setting_get(ctx: Context, key: str, username: str | None) -> Any:
    target = _attr_target(ctx, username)
    if not target:
        return None
    return _mailbox_attrs(ctx, target).get(key)


def quarantine_setting_edit(ctx: Context, key: str, data: dict[str, Any]) -> bool:
    allowed = {"quarantine_notification": ("never", "hourly", "daily", "weekly"), "quarantine_category": ("add_header", "reject", "all")}
    log_ = ["mailbox", "edit", key, data]
    if not ctx.has_acl(key):
        ctx.denied(log_)
        return False
    for username in as_list(data.get("username")):
        if not own_mailbox_access(ctx, username):
            ctx.denied(log_)
            continue
        value = data.get(key) or quarantine_setting_get(ctx, key, username)
        if value not in allowed[key]:
            ctx.denied(log_)
            continue
        ctx.db.exec("UPDATE mailbox SET attributes = attributes || %s::jsonb WHERE username = %s", (json.dumps({key: value}), username))
        ctx.ok(log_, ["mailbox_modified", username])
    return True


def spam_score_get(ctx: Context, username: str | None) -> str | None:
    target = _attr_target(ctx, username)
    if not target:
        return None
    default = "5, 15"
    try:
        import httpx

        transport = httpx.HTTPTransport(uds="/var/lib/rspamd/rspamd.sock")
        with httpx.Client(transport=transport, timeout=5) as client:
            actions = client.get("http://rspamd/actions").json()
        reject = next((a["value"] for a in actions if a.get("action") == "reject"), None)
        add_header = next((a["value"] for a in actions if a.get("action") == "add header"), None)
        if reject and add_header:
            default = f"{add_header}, {reject}"
        else:
            ctx.warn(["mailbox", "get", "spam_score"], "Could not determine servers default spam score, assuming default")
    except Exception:  # noqa: BLE001
        ctx.warn(["mailbox", "get", "spam_score"], "Could not determine servers default spam score, assuming default")
    rows = {
        r["option"]: r["value"]
        for r in ctx.db.all("SELECT option, value FROM filterconf WHERE object = %s AND option IN ('lowspamlevel', 'highspamlevel')", (target,))
    }
    if not rows:
        return default
    return f"{rows.get('lowspamlevel')}, {rows.get('highspamlevel')}"


def spam_score_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["mailbox", "edit", "spam_score", data]
    if not ctx.has_acl("spam_score"):
        ctx.denied(log_)
        return False
    for username in as_list(data.get("username")):
        if not own_mailbox_access(ctx, username):
            ctx.denied(log_)
            continue
        value = str(data.get("spam_score") or "")
        if value == "default":
            ctx.db.exec("DELETE FROM filterconf WHERE object = %s AND option IN ('lowspamlevel', 'highspamlevel')", (username,))
            ctx.ok(log_, ["mailbox_modified", username])
            continue
        parts = [p.strip() for p in value.split(",")]
        try:
            low, high = float(parts[0]), float(parts[1])
        except (IndexError, ValueError):
            ctx.err(log_, 'Invalid spam score, format must be "1,2" where first is low and second is high spam value.')
            continue
        if low == high:
            high += 0.1
        ctx.db.exec("DELETE FROM filterconf WHERE object = %s AND option IN ('lowspamlevel', 'highspamlevel')", (username,))
        ctx.db.exec("INSERT INTO filterconf (object, option, value) VALUES (%s, 'highspamlevel', %s)", (username, f"{high:g}"))
        ctx.db.exec("INSERT INTO filterconf (object, option, value) VALUES (%s, 'lowspamlevel', %s)", (username, f"{low:g}"))
        ctx.ok(log_, ["mailbox_modified", username])
    return True


def edit_user_account(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["edit_user_account", _mask(data)]
    username = ctx.username
    if not username or not is_email(username) or ctx.role != "user":
        ctx.denied(log_)
        return False
    old, new, new2 = data.get("user_old_pass"), data.get("user_new_pass"), data.get("user_new_pass2")
    if old and new and new2:
        row = ctx.db.one(
            "SELECT password FROM mailbox WHERE kind !~ %s AND username = %s AND authsource = 'mailcow'", (RESOURCE_KIND_RE, username)
        )
        if not row or not verify_hash(row["password"], old):
            ctx.denied(log_)
            return False
        if not password_check(ctx, new, new2):
            return False
        ctx.db.exec(
            "UPDATE mailbox SET password = %s, attributes = attributes || %s::jsonb WHERE username = %s AND authsource = 'mailcow'",
            (hash_password(new), json.dumps({"force_pw_update": "0", "passwd_update": time.strftime("%Y-%m-%d %H:%M:%S")}), username),
        )
        update_sogo_static_view(ctx)
    elif _isset(data, "pw_recovery_email"):
        if not ctx.has_acl("pw_reset"):
            ctx.denied(log_)
            return False
        rec = data["pw_recovery_email"] if is_email(data["pw_recovery_email"]) else ""
        ctx.db.exec(
            "UPDATE mailbox SET attributes = attributes || %s::jsonb WHERE username = %s AND authsource = 'mailcow'",
            (json.dumps({"recovery_email": rec}), username),
        )
    ctx.ok(log_, ["mailbox_modified", htmlspecialchars(username)])
    return True


def user_get_alias_details(ctx: Context, username: str | None) -> dict[str, Any] | None:
    if ctx.role == "user":
        username = ctx.username
    if not username or not is_email(username):
        return None
    if not own_mailbox_access(ctx, username):
        return None
    d: dict[str, Any] = {"address": username, "direct_aliases": {}, "shared_aliases": {}, "alias_domains": []}
    for r in ctx.db.all(
        "SELECT address, public_comment FROM alias WHERE goto ~ %s AND address NOT LIKE '@%%' AND goto != %s AND address != %s",
        (_goto_regex(username), username, username),
    ):
        d["shared_aliases"][r["address"]] = {"public_comment": htmlspecialchars(r["public_comment"])}
    for r in ctx.db.all("SELECT address, public_comment FROM alias WHERE goto = %s AND address NOT LIKE '@%%' AND address != %s", (username, username)):
        d["direct_aliases"][r["address"]] = {"public_comment": htmlspecialchars(r["public_comment"])}
    for r in ctx.db.all(
        """SELECT local_part || '@' || alias_domain AS ad_alias, alias_domain FROM mailbox
           LEFT OUTER JOIN alias_domain ON target_domain = domain WHERE username = %s""",
        (username,),
    ):
        if r["ad_alias"]:
            d["direct_aliases"][r["ad_alias"]] = {"public_comment": "Alias domain"}
            d["alias_domains"].append(r["alias_domain"])
    r = ctx.db.one("SELECT COALESCE(string_agg(send_as, ', '), '') AS send_as FROM sender_acl WHERE logged_in_as = %s AND send_as NOT LIKE '@%%'", (username,))
    d["aliases_also_send_as"] = r["send_as"] if r else ""
    r = ctx.db.one(
        """SELECT concat_ws(', ', COALESCE(string_agg(DISTINCT send_as, ', '), ''), string_agg(DISTINCT '@' || alias_domain, ', ')) AS send_as
           FROM sender_acl LEFT JOIN alias_domain ON alias_domain.target_domain = ltrim(send_as, '@')
           WHERE logged_in_as = %s AND send_as LIKE '@%%'""",
        (username,),
    )
    d["aliases_send_as_all"] = r["send_as"] if r else ""
    r = ctx.db.one("SELECT COALESCE(string_agg(address, ', '), '') AS address FROM alias WHERE goto ~ %s AND address LIKE '@%%'", (_goto_regex(username),))
    d["is_catch_all"] = r["address"] if r else ""
    return d


# ---------------------------------------------------------------------------
# aliases
# ---------------------------------------------------------------------------
def get_aliases(ctx: Context, domain: str, by_address: bool = False) -> list[Any]:
    if not own_domain_access(ctx, domain):
        return []
    rows = ctx.db.all("SELECT id, address FROM alias WHERE address != goto AND domain = %s ORDER BY address", (domain,))
    return [r["address"] if by_address else r["id"] for r in rows]


def alias_details(ctx: Context, ident: Any) -> dict[str, Any] | None:
    id_ = to_int(ident, -1) if str(ident).isdigit() else -1
    row = ctx.db.one(
        """SELECT id, domain, goto, address, public_comment, private_comment, active, sogo_visible, created, modified
           FROM alias WHERE (id = %s OR address = %s) AND address != goto""",
        (id_, str(ident)),
    )
    if not row:
        return None
    if not own_domain_access(ctx, row["domain"]):
        return None
    ad = ctx.db.one("SELECT target_domain FROM alias_domain WHERE alias_domain = %s", (row["domain"],))
    return {
        "in_primary_domain": ad["target_domain"] if ad and ad.get("target_domain") else "",
        "id": row["id"],
        "domain": row["domain"],
        "public_comment": row["public_comment"],
        "private_comment": row["private_comment"],
        "goto": row["goto"],
        "address": row["address"],
        "is_catch_all": 0 if is_email(row["address"]) else 1,
        "active": int(row["active"]),
        "active_int": int(row["active"]),
        "sogo_visible": int(row["sogo_visible"]),
        "sogo_visible_int": int(row["sogo_visible"]),
        "created": row["created"],
        "modified": row["modified"],
    }


def alias_add(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["mailbox", "add", "alias", data]
    addresses = split_list(data.get("address"))
    gotos = split_list(data.get("goto"))
    active = to_int(data.get("active"))
    sogo_visible = to_int(data.get("sogo_visible"))
    goto_null, goto_spam, goto_ham = to_int(data.get("goto_null")), to_int(data.get("goto_spam")), to_int(data.get("goto_ham"))
    private_comment = data.get("private_comment") or ""
    public_comment = data.get("public_comment") or ""
    if len(private_comment) > 160 or len(public_comment) > 160:
        ctx.err(log_, "comment_too_long")
        return False
    if not addresses:
        ctx.err(log_, "alias_empty")
        return False
    if not gotos and goto_null + goto_spam + goto_ham == 0:
        ctx.err(log_, "goto_empty")
        return False
    if goto_null == 1:
        goto = "null@localhost"
    elif goto_spam == 1:
        goto = "spam@localhost"
    elif goto_ham == 1:
        goto = "ham@localhost"
    else:
        cleaned: list[str] = []
        for g in gotos:
            if "@" not in g:
                ctx.err(log_, ["goto_invalid", htmlspecialchars(g)])
                continue
            local, _, dom = g.rpartition("@")
            g = f"{local}@{idn_to_ascii(dom)}"
            if ctx.db.count("SELECT username FROM mailbox WHERE kind ~ %s AND username = %s", (RESOURCE_KIND_RE, g)):
                ctx.err(log_, ["goto_invalid", htmlspecialchars(g)])
                continue
            if not is_email(g):
                ctx.err(log_, ["goto_invalid", htmlspecialchars(g)])
                continue
            cleaned.append(g)
        cleaned = list(dict.fromkeys(cleaned))
        if not cleaned:
            return False
        gotos = cleaned
        goto = ",".join(cleaned)
    for address in addresses:
        if address in gotos:
            continue
        if "@" not in address:
            ctx.err(log_, ["alias_invalid", address])
            continue
        local_part, _, dom = address.rpartition("@")
        domain = idn_to_ascii(dom)
        address = f"{local_part}@{domain}"
        dd = domain_details(ctx, domain)
        if dd and dd["aliases_left"] == 0:
            ctx.err(log_, "max_alias_exceeded")
            return False
        if ctx.db.count(
            """SELECT address FROM alias WHERE address = %s OR address IN (
                 SELECT username FROM mailbox, alias_domain
                 WHERE alias_domain.alias_domain = %s AND mailbox.username = %s || '@' || alias_domain.target_domain)""",
            (address, domain, local_part),
        ):
            ctx.err(log_, ["is_alias_or_mailbox", htmlspecialchars(address)])
            continue
        if not ctx.db.count(
            "SELECT domain FROM domain WHERE domain = %s OR domain = (SELECT target_domain FROM alias_domain WHERE alias_domain = %s)",
            (domain, domain),
        ):
            ctx.err(log_, ["domain_not_found", htmlspecialchars(domain)])
            continue
        if ctx.db.count("SELECT address FROM spamalias WHERE address = %s", (address,)):
            ctx.err(log_, ["is_spam_alias", htmlspecialchars(address)])
            continue
        if not is_email(address) and local_part:
            ctx.err(log_, ["alias_invalid", address])
            continue
        if not own_domain_access(ctx, domain):
            ctx.denied(log_)
            continue
        stored = address if is_email(address) else "@" + domain
        new_id = ctx.db.insert_returning_id(
            """INSERT INTO alias (address, public_comment, private_comment, goto, domain, sogo_visible, active)
               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (stored, public_comment, private_comment, goto, domain, sogo_visible, active),
        )
        ctx.ok(log_, ["alias_added", address, new_id])
    return True


def alias_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["mailbox", "edit", "alias", data]
    for ident in as_list(data.get("id")):
        is_now = alias_details(ctx, ident)
        if not is_now:
            ctx.err(log_, ["alias_invalid", str(ident)])
            continue
        active = to_int(data["active"]) if _isset(data, "active") else is_now["active"]
        sogo_visible = to_int(data["sogo_visible"]) if _isset(data, "sogo_visible") else is_now["sogo_visible"]
        goto_null, goto_spam, goto_ham = to_int(data.get("goto_null")), to_int(data.get("goto_spam")), to_int(data.get("goto_ham"))
        public_comment = data["public_comment"] if _isset(data, "public_comment") else is_now["public_comment"]
        private_comment = data["private_comment"] if _isset(data, "private_comment") else is_now["private_comment"]
        goto = data["goto"] if data.get("goto") else is_now["goto"]
        address = data["address"] if data.get("address") else is_now["address"]
        if data.get("expand_alias") in (True, 1, "1"):
            if not ctx.db.count("SELECT address FROM alias WHERE address = %s AND domain NOT IN (SELECT alias_domain FROM alias_domain)", (address,)):
                ctx.warn(log_, ["is_not_primary_alias", htmlspecialchars(address)])
                continue
            missing = ctx.db.one(
                """SELECT alias.goto, string_agg(split_part(alias.address, '@', 1) || '@' || alias_domain.alias_domain, ',') AS missing_alias
                   FROM alias JOIN alias_domain ON alias_domain.target_domain = alias.domain
                   WHERE split_part(alias.address, '@', 1) || '@' || alias_domain.alias_domain NOT IN (SELECT address FROM alias WHERE address != goto)
                     AND alias.address NOT IN (SELECT address FROM alias WHERE address = goto)
                     AND address = %s
                   GROUP BY alias.goto""",
                (address,),
            )
            if missing and missing.get("missing_alias"):
                alias_add(ctx, {"address": missing["missing_alias"], "goto": missing["goto"], "sogo_visible": 1, "active": 1})
            ctx.ok(log_, ["alias_modified", htmlspecialchars(address)])
            continue
        local_part, _, dom = address.rpartition("@")
        domain = idn_to_ascii(dom)
        if is_now["address"] != address:
            address = f"{local_part}@{domain}"
            if not own_domain_access(ctx, domain):
                ctx.denied(log_)
                continue
            if not is_email(address) and local_part:
                ctx.err(log_, ["alias_invalid", address])
                continue
            if is_now["address"].lower() != address.lower():
                if ctx.db.count(
                    """SELECT address FROM alias WHERE address = %s OR address IN (
                         SELECT username FROM mailbox, alias_domain
                         WHERE alias_domain.alias_domain = %s AND mailbox.username = %s || '@' || alias_domain.target_domain)""",
                    (address, domain, local_part),
                ):
                    ctx.err(log_, ["is_alias_or_mailbox", htmlspecialchars(address)])
                    continue
            if not ctx.db.count(
                "SELECT domain FROM domain WHERE domain = %s OR domain = (SELECT target_domain FROM alias_domain WHERE alias_domain = %s)",
                (domain, domain),
            ):
                ctx.err(log_, ["domain_not_found", htmlspecialchars(domain)])
                continue
            if ctx.db.count("SELECT address FROM spamalias WHERE address = %s", (address,)):
                ctx.err(log_, ["is_spam_alias", htmlspecialchars(address)])
                continue
        if goto_null == 1:
            goto = "null@localhost"
        elif goto_spam == 1:
            goto = "spam@localhost"
        elif goto_ham == 1:
            goto = "ham@localhost"
        else:
            cleaned = []
            for g in split_list(goto):
                if not is_email(g):
                    ctx.err(log_, ["goto_invalid", g])
                    continue
                if g == address:
                    ctx.err(log_, "alias_goto_identical")
                    continue
                ctx.db.exec("DELETE FROM sender_acl WHERE logged_in_as = %s AND send_as = %s", (g, address))
                cleaned.append(g)
            goto = ",".join(dict.fromkeys(cleaned))
        if goto:
            ctx.db.exec(
                """UPDATE alias SET address = %s, public_comment = %s, private_comment = %s, domain = %s, goto = %s, sogo_visible = %s, active = %s
                   WHERE id = %s""",
                (address, public_comment, private_comment, domain, goto, sogo_visible, active, is_now["id"]),
            )
        ctx.ok(log_, ["alias_modified", htmlspecialchars(address)])
    return True


def alias_delete(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["mailbox", "delete", "alias", data]
    for ident in as_list(data.get("id")):
        a = alias_details(ctx, ident)
        if not a:
            ctx.denied(log_)
            continue
        ctx.db.exec("DELETE FROM alias WHERE id = %s", (a["id"],))
        ctx.db.exec("DELETE FROM sender_acl WHERE send_as = %s", (a["address"],))
        ctx.ok(log_, ["alias_removed", htmlspecialchars(a["address"])])
    return True
