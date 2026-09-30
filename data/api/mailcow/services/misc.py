"""Smaller admin objects: relayhosts, transports, bcc maps, recipient maps, TLS policy maps,
rspamd settings maps, forwarding hosts, quarantine listing, logs, rspamd custom maps, quota notification, UI customisation.

Ports of functions.transports.inc.php, functions.address_rewriting.inc.php, functions.tls_policy_maps.inc.php,
functions.rspamd.inc.php, functions.fwdhost.inc.php, functions.quarantine.inc.php (list/delete), get_logs().
"""
from __future__ import annotations

import json
import os
import re
import socket
from typing import Any

from ..config import settings
from ..security.acl import has_alias_object_access, own_domain_access, own_mailbox_access
from ..security.context import Context
from ..validators import as_list, htmlspecialchars, is_email, is_valid_domain_name, split_list, to_int, valid_hostname, valid_network


def _admin(ctx: Context, log_: list) -> bool:
    if ctx.role != "admin":
        ctx.denied(log_)
        return False
    return True


# ---------------------------------------------------------------------------
# relayhosts
# ---------------------------------------------------------------------------
def relayhost_get(ctx: Context, id_: Any = None) -> Any:
    if ctx.role != "admin":
        return None
    if id_ is None:
        return ctx.db.all("SELECT id, hostname, username, active FROM relayhosts ORDER BY id")
    row = ctx.db.one("SELECT * FROM relayhosts WHERE id = %s", (to_int(id_),))
    if row:
        row["used_by_domains"] = ", ".join(r["domain"] for r in ctx.db.all("SELECT domain FROM domain WHERE relayhost = %s", (str(row["id"]),)))
        row["used_by_mailboxes"] = ", ".join(
            r["username"] for r in ctx.db.all("SELECT username FROM mailbox WHERE attributes->>'relayhost' = %s", (str(row["id"]),))
        )
    return row


def relayhost_add(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["relayhost", "add", {**data, "password": "*"}]
    if not _admin(ctx, log_):
        return False
    hostname = (data.get("hostname") or "").strip()
    if not hostname:
        ctx.err(log_, "relayhost_invalid")
        return False
    ctx.db.exec(
        "INSERT INTO relayhosts (hostname, username, password, active) VALUES (%s, %s, %s, %s)",
        (hostname, data.get("username") or "", data.get("password") or "", to_int(data.get("active"))),
    )
    ctx.ok(log_, ["relayhost_added", htmlspecialchars(hostname)])
    return True


def relayhost_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["relayhost", "edit", {**data, "password": "*"}]
    if not _admin(ctx, log_):
        return False
    for id_ in as_list(data.get("id")):
        is_now = ctx.db.one("SELECT * FROM relayhosts WHERE id = %s", (to_int(id_),))
        if not is_now:
            ctx.err(log_, "relayhost_invalid")
            continue
        ctx.db.exec(
            "UPDATE relayhosts SET hostname = %s, username = %s, password = %s, active = %s WHERE id = %s",
            (
                data.get("hostname") or is_now["hostname"],
                data["username"] if "username" in data else is_now["username"],
                data["password"] if "password" in data else is_now["password"],
                to_int(data["active"]) if "active" in data else is_now["active"],
                to_int(id_),
            ),
        )
        ctx.ok(log_, ["object_modified", htmlspecialchars(str(id_))])
    return True


def relayhost_delete(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["relayhost", "delete", data]
    if not _admin(ctx, log_):
        return False
    for id_ in as_list(data.get("id")):
        ctx.db.exec("DELETE FROM relayhosts WHERE id = %s", (to_int(id_),))
        ctx.db.exec("UPDATE domain SET relayhost = '0' WHERE relayhost = %s", (str(to_int(id_)),))
        ctx.db.exec("UPDATE mailbox SET attributes = attributes || '{\"relayhost\": \"0\"}'::jsonb WHERE attributes->>'relayhost' = %s", (str(to_int(id_)),))
        ctx.ok(log_, ["relayhost_removed", htmlspecialchars(str(id_))])
    return True


# ---------------------------------------------------------------------------
# transports
# ---------------------------------------------------------------------------
def transport_get(ctx: Context, id_: Any = None) -> Any:
    if ctx.role != "admin":
        return None
    if id_ is None:
        return ctx.db.all("SELECT id, destination, nexthop, username, is_mx_based, active FROM transports ORDER BY id")
    return ctx.db.one("SELECT * FROM transports WHERE id = %s", (to_int(id_),))


def _valid_transport_dest(dest: str) -> bool:
    d = dest.lstrip(".")
    return is_valid_domain_name(d) or is_email(dest) or bool(re.match(r"^[\w.\-]+$", d)) or dest == "*"


def transport_add(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["transport", "add", {**data, "password": "*"}]
    if not _admin(ctx, log_):
        return False
    destination = (data.get("destination") or "").strip()
    nexthop = (data.get("nexthop") or "").strip()
    if not destination or not nexthop or not _valid_transport_dest(destination):
        ctx.err(log_, "transport_dest_invalid")
        return False
    if ctx.db.count("SELECT id FROM transports WHERE destination = %s", (destination,)):
        ctx.err(log_, ["transport_dest_exists", htmlspecialchars(destination)])
        return False
    ctx.db.exec(
        "INSERT INTO transports (destination, nexthop, username, password, is_mx_based, active) VALUES (%s, %s, %s, %s, %s, %s)",
        (destination, nexthop, data.get("username") or "", data.get("password") or "", to_int(data.get("is_mx_based")), to_int(data.get("active"))),
    )
    ctx.ok(log_, ["relayhost_added", htmlspecialchars(destination)])
    return True


def transport_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["transport", "edit", {**data, "password": "*"}]
    if not _admin(ctx, log_):
        return False
    for id_ in as_list(data.get("id")):
        is_now = ctx.db.one("SELECT * FROM transports WHERE id = %s", (to_int(id_),))
        if not is_now:
            ctx.err(log_, "transport_dest_invalid")
            continue
        ctx.db.exec(
            "UPDATE transports SET destination = %s, nexthop = %s, username = %s, password = %s, is_mx_based = %s, active = %s WHERE id = %s",
            (
                data.get("destination") or is_now["destination"],
                data.get("nexthop") or is_now["nexthop"],
                data["username"] if "username" in data else is_now["username"],
                data["password"] if "password" in data else is_now["password"],
                to_int(data["is_mx_based"]) if "is_mx_based" in data else is_now["is_mx_based"],
                to_int(data["active"]) if "active" in data else is_now["active"],
                to_int(id_),
            ),
        )
        ctx.ok(log_, ["object_modified", htmlspecialchars(str(id_))])
    return True


def transport_delete(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["transport", "delete", data]
    if not _admin(ctx, log_):
        return False
    for id_ in as_list(data.get("id")):
        ctx.db.exec("DELETE FROM transports WHERE id = %s", (to_int(id_),))
        ctx.ok(log_, ["relayhost_removed", htmlspecialchars(str(id_))])
    return True


# ---------------------------------------------------------------------------
# bcc maps / recipient maps (address rewriting)
# ---------------------------------------------------------------------------
def bcc_get(ctx: Context, id_: Any = None) -> Any:
    if id_ is None:
        rows = ctx.db.all("SELECT id, local_dest, bcc_dest, domain, type, active FROM bcc_maps ORDER BY id")
        return [r for r in rows if own_domain_access(ctx, r["domain"])]
    row = ctx.db.one("SELECT * FROM bcc_maps WHERE id = %s", (to_int(id_),))
    return row if row and own_domain_access(ctx, row["domain"]) else None


def bcc_add(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["bcc", "add", data]
    if not ctx.has_acl("bcc_maps"):
        ctx.denied(log_)
        return False
    local_dest = (data.get("local_dest") or "").strip().lower()
    bcc_dest = (data.get("bcc_dest") or "").strip().lower()
    type_ = data.get("type")
    active = to_int(data.get("active"))
    if type_ not in ("sender", "rcpt"):
        ctx.err(log_, "bcc_map_type_invalid")
        return False
    if local_dest.startswith("@"):
        local_dest = local_dest[1:]
    if is_valid_domain_name(local_dest):
        domain = local_dest
        local_dest_sane = "@" + local_dest
    elif is_email(local_dest):
        domain = local_dest.split("@")[-1]
        local_dest_sane = local_dest
    else:
        ctx.err(log_, "bcc_map_dest_invalid")
        return False
    if not own_domain_access(ctx, domain):
        ctx.denied(log_)
        return False
    if not is_email(bcc_dest):
        ctx.err(log_, "bcc_dest_format")
        return False
    if ctx.db.count("SELECT id FROM bcc_maps WHERE local_dest = %s AND type = %s", (local_dest_sane, type_)):
        ctx.err(log_, ["bcc_exists", htmlspecialchars(local_dest_sane), type_])
        return False
    ctx.db.exec(
        "INSERT INTO bcc_maps (local_dest, bcc_dest, domain, active, type) VALUES (%s, %s, %s, %s, %s)",
        (local_dest_sane, bcc_dest, domain, active, type_),
    )
    ctx.ok(log_, ["bcc_saved", htmlspecialchars(local_dest_sane)])
    return True


def bcc_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["bcc", "edit", data]
    if not ctx.has_acl("bcc_maps"):
        ctx.denied(log_)
        return False
    for id_ in as_list(data.get("id")):
        is_now = bcc_get(ctx, id_)
        if not is_now:
            ctx.denied(log_)
            continue
        bcc_dest = (data.get("bcc_dest") or is_now["bcc_dest"]).strip().lower()
        type_ = data.get("type") or is_now["type"]
        active = to_int(data["active"]) if "active" in data else is_now["active"]
        if not is_email(bcc_dest):
            ctx.err(log_, "bcc_dest_format")
            continue
        if type_ not in ("sender", "rcpt"):
            ctx.err(log_, "bcc_map_type_invalid")
            continue
        ctx.db.exec("UPDATE bcc_maps SET bcc_dest = %s, active = %s, type = %s WHERE id = %s", (bcc_dest, active, type_, to_int(id_)))
        ctx.ok(log_, ["bcc_edited", htmlspecialchars(is_now["local_dest"])])
    return True


def bcc_delete(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["bcc", "delete", data]
    for id_ in as_list(data.get("id")):
        is_now = bcc_get(ctx, id_)
        if not is_now:
            ctx.denied(log_)
            continue
        ctx.db.exec("DELETE FROM bcc_maps WHERE id = %s", (to_int(id_),))
        ctx.ok(log_, ["bcc_deleted", str(id_)])
    return True


def recipient_map_get(ctx: Context, id_: Any = None) -> Any:
    if ctx.role != "admin":
        return None
    if id_ is None:
        return ctx.db.all("SELECT * FROM recipient_maps ORDER BY id")
    return ctx.db.one("SELECT * FROM recipient_maps WHERE id = %s", (to_int(id_),))


def recipient_map_add(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["recipient_map", "add", data]
    if not _admin(ctx, log_):
        return False
    old_dest = (data.get("recipient_map_old") or "").strip().lower()
    new_dest = (data.get("recipient_map_new") or "").strip().lower()
    active = to_int(data.get("active"))
    if old_dest.startswith("@"):
        old_dest = old_dest[1:]
    if is_valid_domain_name(old_dest):
        old_dest_sane = "@" + old_dest
    elif is_email(old_dest):
        old_dest_sane = old_dest
    else:
        ctx.err(log_, ["recipient_map_entry_invalid", htmlspecialchars(old_dest)])
        return False
    if not is_email(new_dest):
        ctx.err(log_, ["recipient_map_entry_invalid", htmlspecialchars(new_dest)])
        return False
    if ctx.db.count("SELECT id FROM recipient_maps WHERE old_dest = %s", (old_dest_sane,)):
        ctx.err(log_, ["recipient_map_entry_exists", htmlspecialchars(old_dest_sane)])
        return False
    ctx.db.exec("INSERT INTO recipient_maps (old_dest, new_dest, active) VALUES (%s, %s, %s)", (old_dest_sane, new_dest, active))
    ctx.ok(log_, ["recipient_map_entry_saved", htmlspecialchars(old_dest_sane)])
    return True


def recipient_map_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["recipient_map", "edit", data]
    if not _admin(ctx, log_):
        return False
    for id_ in as_list(data.get("id")):
        is_now = recipient_map_get(ctx, id_)
        if not is_now:
            ctx.err(log_, ["recipient_map_entry_invalid", str(id_)])
            continue
        new_dest = (data.get("recipient_map_new") or is_now["new_dest"]).strip().lower()
        active = to_int(data["active"]) if "active" in data else is_now["active"]
        if not is_email(new_dest):
            ctx.err(log_, ["recipient_map_entry_invalid", htmlspecialchars(new_dest)])
            continue
        ctx.db.exec("UPDATE recipient_maps SET new_dest = %s, active = %s WHERE id = %s", (new_dest, active, to_int(id_)))
        ctx.ok(log_, ["recipient_map_entry_saved", htmlspecialchars(is_now["old_dest"])])
    return True


def recipient_map_delete(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["recipient_map", "delete", data]
    if not _admin(ctx, log_):
        return False
    for id_ in as_list(data.get("id")):
        ctx.db.exec("DELETE FROM recipient_maps WHERE id = %s", (to_int(id_),))
        ctx.ok(log_, ["recipient_map_entry_deleted", str(id_)])
    return True


# ---------------------------------------------------------------------------
# TLS policy maps
# ---------------------------------------------------------------------------
TLS_POLICIES = ("none", "may", "encrypt", "dane", "dane-only", "fingerprint", "verify", "secure")


def tls_policy_map_get(ctx: Context, id_: Any = None) -> Any:
    if ctx.role != "admin":
        return None
    if id_ is None:
        return ctx.db.all("SELECT * FROM tls_policy_override ORDER BY id")
    return ctx.db.one("SELECT * FROM tls_policy_override WHERE id = %s", (to_int(id_),))


def tls_policy_map_add(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["tls_policy_maps", "add", data]
    if not _admin(ctx, log_):
        return False
    dest = (data.get("dest") or "").strip().lower()
    policy = (data.get("policy") or "").strip().lower()
    parameters = (data.get("parameters") or "").strip()
    active = to_int(data.get("active"))
    if not dest or not (is_valid_domain_name(dest.lstrip(".[").rstrip("]")) or is_email(dest) or re.match(r"^\[?[\w.:\-]+\]?(:\d+)?$", dest)):
        ctx.err(log_, ["tls_policy_map_dest_invalid", htmlspecialchars(dest)])
        return False
    if policy not in TLS_POLICIES:
        ctx.err(log_, ["tls_policy_map_policy_invalid", htmlspecialchars(policy)])
        return False
    if parameters and not re.match(r"^[\w=,.:\-\s]+$", parameters):
        ctx.err(log_, ["tls_policy_map_parameter_invalid", htmlspecialchars(parameters)])
        return False
    if ctx.db.count("SELECT id FROM tls_policy_override WHERE dest = %s", (dest,)):
        ctx.err(log_, ["tls_policy_map_entry_exists", htmlspecialchars(dest)])
        return False
    ctx.db.exec(
        "INSERT INTO tls_policy_override (dest, policy, parameters, active) VALUES (%s, %s, %s, %s)", (dest, policy, parameters, active)
    )
    ctx.ok(log_, ["tls_policy_map_entry_saved", htmlspecialchars(dest)])
    return True


def tls_policy_map_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["tls_policy_maps", "edit", data]
    if not _admin(ctx, log_):
        return False
    for id_ in as_list(data.get("id")):
        is_now = tls_policy_map_get(ctx, id_)
        if not is_now:
            ctx.err(log_, ["tls_policy_map_entry_invalid", str(id_)])
            continue
        policy = (data.get("policy") or is_now["policy"]).strip().lower()
        parameters = data["parameters"].strip() if "parameters" in data else (is_now["parameters"] or "")
        active = to_int(data["active"]) if "active" in data else is_now["active"]
        if policy not in TLS_POLICIES:
            ctx.err(log_, ["tls_policy_map_policy_invalid", htmlspecialchars(policy)])
            continue
        ctx.db.exec("UPDATE tls_policy_override SET policy = %s, parameters = %s, active = %s WHERE id = %s", (policy, parameters, active, to_int(id_)))
        ctx.ok(log_, ["tls_policy_map_entry_saved", htmlspecialchars(is_now["dest"])])
    return True


def tls_policy_map_delete(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["tls_policy_maps", "delete", data]
    if not _admin(ctx, log_):
        return False
    for id_ in as_list(data.get("id")):
        ctx.db.exec("DELETE FROM tls_policy_override WHERE id = %s", (to_int(id_),))
        ctx.ok(log_, ["tls_policy_map_entry_deleted", str(id_)])
    return True


# ---------------------------------------------------------------------------
# rspamd settings maps (settingsmap) and custom regex maps
# ---------------------------------------------------------------------------
def rsetting_get(ctx: Context, id_: Any = None) -> Any:
    if ctx.role != "admin":
        return None
    if id_ is None:
        return ctx.db.all("SELECT id, description, active FROM settingsmap ORDER BY id")
    return ctx.db.one("SELECT * FROM settingsmap WHERE id = %s", (to_int(id_),))


def rsetting_add(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["rsettings", "add", data]
    if not _admin(ctx, log_):
        return False
    desc = (data.get("desc") or data.get("description") or "").strip()
    content = (data.get("content") or "").strip()
    if not content:
        ctx.err(log_, "rsetting_content_empty")
        return False
    ctx.db.exec(
        "INSERT INTO settingsmap (description, content, active) VALUES (%s, %s, %s)", (desc or "No description", content, to_int(data.get("active")))
    )
    ctx.ok(log_, "rsetting_added")
    return True


def rsetting_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["rsettings", "edit", data]
    if not _admin(ctx, log_):
        return False
    for id_ in as_list(data.get("id")):
        is_now = rsetting_get(ctx, id_)
        if not is_now:
            ctx.err(log_, "rsetting_invalid")
            continue
        desc = (data.get("desc") or data.get("description") or is_now["description"]).strip()
        content = (data.get("content") or is_now["content"]).strip()
        active = to_int(data["active"]) if "active" in data else is_now["active"]
        ctx.db.exec("UPDATE settingsmap SET description = %s, content = %s, active = %s WHERE id = %s", (desc, content, active, to_int(id_)))
        ctx.ok(log_, ["object_modified", str(id_)])
    return True


def rsetting_delete(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["rsettings", "delete", data]
    if not _admin(ctx, log_):
        return False
    for id_ in as_list(data.get("id")):
        ctx.db.exec("DELETE FROM settingsmap WHERE id = %s", (to_int(id_),))
        ctx.ok(log_, ["object_removed", str(id_)])
    return True


def rspamd_map_get(ctx: Context, map_name: str) -> str | None:
    if ctx.role != "admin" or map_name not in settings.rspamd_maps["regex"].values():
        return None
    try:
        with open(os.path.join(settings.rspamd_custom_maps, map_name), "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def rspamd_map_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["rspamd", "edit", "regex", data]
    if not _admin(ctx, log_):
        return False
    map_name = data.get("map")
    if map_name not in settings.rspamd_maps["regex"].values():
        ctx.err(log_, "invalid_map_name")
        return False
    content = data.get("rspamd_map_data") or ""
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            re.compile(line.strip("/").rsplit("/", 1)[0] if line.startswith("/") else line)
        except re.error:
            ctx.err(log_, ["invalid_regex", htmlspecialchars(line)])
            return False
    with open(os.path.join(settings.rspamd_custom_maps, map_name), "w", encoding="utf-8") as fh:
        fh.write(content.rstrip("\n") + "\n")
    ctx.ok(log_, ["object_modified", htmlspecialchars(map_name)])
    return True


# ---------------------------------------------------------------------------
# forwarding hosts (Redis)
# ---------------------------------------------------------------------------
def fwdhost_get(ctx: Context) -> list[dict[str, Any]]:
    if ctx.role != "admin":
        return []
    out = []
    for host, source in (ctx.redis.hgetall("WHITELISTED_FWD_HOST") or {}).items():
        keep_spam = ctx.redis.hget("KEEP_SPAM", host)
        out.append({"host": host, "source": source, "keep_spam": "yes" if keep_spam == "1" else "no"})
    return out


def fwdhost_add(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["fwdhost", "add", data]
    if not _admin(ctx, log_):
        return False
    filter_spam = to_int(data.get("filter_spam"))
    for host in split_list(data.get("hostname")):
        hosts: list[str] = []
        if valid_network(host):
            hosts = [host]
        elif valid_hostname(host):
            try:
                for info in socket.getaddrinfo(host, None):
                    hosts.append(info[4][0])
            except socket.gaierror:
                pass
        if not hosts:
            ctx.err(log_, ["invalid_host", htmlspecialchars(host)])
            continue
        for h in dict.fromkeys(hosts):
            ctx.redis.hset("WHITELISTED_FWD_HOST", h, host)
            if filter_spam == 0:
                ctx.redis.hset("KEEP_SPAM", h, 1)
            else:
                ctx.redis.hdel("KEEP_SPAM", h)
        ctx.ok(log_, ["forwarding_host_added", htmlspecialchars(", ".join(hosts))])
    return True


def fwdhost_delete(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["fwdhost", "delete", data]
    if not _admin(ctx, log_):
        return False
    for host in as_list(data.get("forwardinghost")):
        ctx.redis.hdel("WHITELISTED_FWD_HOST", host)
        ctx.redis.hdel("KEEP_SPAM", host)
        ctx.ok(log_, ["forwarding_host_removed", htmlspecialchars(host)])
    return True


# ---------------------------------------------------------------------------
# quarantine (listing / details / delete)
# ---------------------------------------------------------------------------
def quarantine_get(ctx: Context, scope: str = "all") -> list[dict[str, Any]]:
    if not ctx.role:
        return []
    if ctx.role == "admin":
        rows = ctx.db.all("SELECT id, qid, score, sender, rcpt, subject, action, created, notified FROM quarantine ORDER BY id DESC")
    else:
        rows = ctx.db.all("SELECT id, qid, score, sender, rcpt, subject, action, created, notified FROM quarantine ORDER BY id DESC")
        rows = [r for r in rows if own_mailbox_access(ctx, r["rcpt"])]
    for r in rows:
        r["subject"] = htmlspecialchars(r["subject"] or "")
        r["score"] = float(r["score"]) if r["score"] is not None else None
    return rows


def quarantine_details(ctx: Context, id_: Any) -> dict[str, Any] | None:
    row = ctx.db.one("SELECT * FROM quarantine WHERE id = %s", (to_int(id_),))
    if not row or not own_mailbox_access(ctx, row["rcpt"]):
        return None
    row["score"] = float(row["score"]) if row["score"] is not None else None
    row["subject"] = htmlspecialchars(row["subject"] or "")
    return row


def quarantine_delete(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["quarantine", "delete", data]
    if not ctx.has_acl("quarantine"):
        ctx.denied(log_)
        return False
    for id_ in as_list(data.get("id")):
        row = ctx.db.one("SELECT rcpt FROM quarantine WHERE id = %s", (to_int(id_),))
        if not row or not own_mailbox_access(ctx, row["rcpt"]):
            ctx.denied(log_)
            continue
        ctx.db.exec("DELETE FROM quarantine WHERE id = %s", (to_int(id_),))
        ctx.ok(log_, ["item_deleted", str(id_)])
    return True


def quarantine_settings_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["quarantine", "edit", "settings", data]
    if not _admin(ctx, log_):
        return False
    r = ctx.redis
    retention_size = to_int(data.get("retention_size"))
    max_size = to_int(data.get("max_size"))
    max_age = to_int(data.get("max_age"))
    try:
        max_score = float(data.get("max_score") or 9999.0)
    except ValueError:
        max_score = 9999.0
    release_format = data.get("release_format") or "raw"
    if release_format not in ("raw", "attachment"):
        release_format = "raw"
    exclude = [d for d in as_list(data.get("exclude_domains")) if is_valid_domain_name(d)]
    sender = (data.get("sender") or "").strip()
    if sender and not is_email(sender):
        ctx.err(log_, "quarantine_sender_invalid")
        return False
    bcc = (data.get("bcc") or "").strip()
    redirect = (data.get("redirect") or "").strip()
    if (bcc and not is_email(bcc)) or (redirect and not is_email(redirect)):
        ctx.err(log_, "bcc_or_redirect_invalid")
        return False
    if retention_size < 1 or max_size < 1 or max_age < 1:
        ctx.err(log_, "retention_size")
        return False
    r.set("Q_RETENTION_SIZE", retention_size)
    r.set("Q_MAX_SIZE", max_size)
    r.set("Q_MAX_AGE", max_age)
    r.set("Q_MAX_SCORE", max_score)
    r.set("Q_RELEASE_FORMAT", release_format)
    r.set("Q_EXCLUDE_DOMAINS", json.dumps(exclude))
    r.set("Q_SENDER", sender or "quarantine@localhost")
    r.set("Q_SUBJ", (data.get("subj") or "Spam Quarantine Notification").strip())
    r.set("Q_BCC", bcc)
    r.set("Q_REDIRECT", redirect)
    if data.get("html_tmpl"):
        r.set("Q_HTML", data["html_tmpl"])
    else:
        r.delete("Q_HTML")
    ctx.ok(log_, "saved_settings")
    return True


# ---------------------------------------------------------------------------
# logs (Redis lists filled by syslog-ng / dockerapi / netfilter)
# ---------------------------------------------------------------------------
LOG_KEYS = {
    "dovecot": "DOVECOT_MAILLOG",
    "postfix": "POSTFIX_MAILLOG",
    "sogo": "SOGO_LOG",
    "netfilter": "NETFILTER_LOG",
    "autodiscover": "AUTODISCOVER_LOG",
    "acme": "ACME_LOG",
    "api": "API_LOG",
    "rspamd-history": "RSPAMD_HISTORY",
    "watchdog": "WATCHDOG_LOG",
    "ratelimited": "RL_LOG",
    "cron": "CRON_LOG",
}


def get_logs(ctx: Context, application: str, lines: int | str | None = None, offset: int = 0) -> Any:
    if ctx.role != "admin":
        return None
    lines = settings.log_lines if lines in (None, "", 0) else lines
    if application == "ui":
        return ctx.db.all("SELECT * FROM logs ORDER BY id DESC LIMIT %s OFFSET %s", (int(lines), int(offset)))
    if application == "sasl":
        return ctx.db.all("SELECT * FROM sasl_log ORDER BY datetime DESC LIMIT %s OFFSET %s", (int(lines), int(offset)))
    key = LOG_KEYS.get(application)
    if not key:
        return None
    items = ctx.redis.lrange(key, int(offset), int(offset) + int(lines) - 1) or []
    out = []
    for item in items:
        try:
            out.append(json.loads(item))
        except ValueError:
            out.append({"message": item})
    return out


def acl_alias_check(ctx: Context, address: str) -> bool:
    return has_alias_object_access(ctx, ctx.username, ctx.role, address)


# ---------------------------------------------------------------------------
# quarantine: hash links (qhandler) and release (port of quarantine('release'/'hash_details'))
# ---------------------------------------------------------------------------
def quarantine_hash_details(ctx: Context, qhash: str) -> dict[str, Any] | None:
    qhash = (qhash or "").strip()
    if not re.fullmatch(r"[a-f0-9]{64}", qhash):
        return None
    row = ctx.db.one(
        "SELECT id, qid, subject, score, sender, rcpt, action, created, notified FROM quarantine WHERE encode(sha256((id::text || qid)::bytea), 'hex') = %s",
        (qhash,),
    )
    if row:
        row["score"] = float(row["score"]) if row["score"] is not None else None
        row["subject"] = htmlspecialchars(row["subject"] or "")
    return row


def _quarantine_id_by_hash(ctx: Context, qhash: str) -> int | None:
    qhash = (qhash or "").strip()
    if not re.fullmatch(r"[a-f0-9]{64}", qhash):
        return None
    row = ctx.db.one(
        """SELECT quarantine.id FROM quarantine LEFT OUTER JOIN user_acl ON user_acl.username = rcpt
           WHERE encode(sha256((quarantine.id::text || qid)::bytea), 'hex') = %s
             AND user_acl.quarantine = 1
             AND user_acl.username IN (SELECT username FROM mailbox)""",
        (qhash,),
    )
    return int(row["id"]) if row else None


def _smtp_reinject(host: str, sender: str, rcpt: str, msg: str) -> str | None:
    """Talk plain SMTP to the Postfix quarantine re-injection listener (port 590). Returns an error string or None."""
    import smtplib

    try:
        with smtplib.SMTP(host, 590, timeout=15) as smtp:
            smtp.helo("quarantine")
            smtp.sendmail(sender, [rcpt], msg.encode("utf-8", errors="replace"))
    except Exception as exc:  # noqa: BLE001
        return str(exc)
    return None


def quarantine_release(ctx: Context, ids: list | None = None, qhash: str | None = None) -> bool:
    """Release quarantined items to the recipient. Access via ACL (UI) or via hash link (notification mail)."""
    import html as _html
    from email.message import EmailMessage

    targets: list[int] = []
    if qhash is not None:
        rid = _quarantine_id_by_hash(ctx, qhash)
        if rid is None:
            ctx.denied(["quarantine", "release", qhash])
            return False
        targets = [rid]
    else:
        if not ctx.has_acl("quarantine"):
            ctx.denied(["quarantine", "release", ids])
            return False
        for id_ in as_list(ids):
            row = ctx.db.one("SELECT rcpt FROM quarantine WHERE id = %s", (to_int(id_),))
            if not row or not own_mailbox_access(ctx, row["rcpt"]):
                ctx.denied(["quarantine", "release", id_])
                continue
            targets.append(to_int(id_))
    release_format = ctx.redis.get("Q_RELEASE_FORMAT") or "raw"
    for rid in targets:
        row = ctx.db.one("SELECT msg, qid, sender, rcpt FROM quarantine WHERE id = %s", (rid,))
        if not row:
            continue
        sender = row["sender"] or "sender-unknown@rspamd"
        raw = _html.unescape(row["msg"] or "")
        if release_format == "attachment":
            em = EmailMessage()
            em["From"] = sender
            em["To"] = row["rcpt"]
            em["Subject"] = f"Quarantined mail released: {row['qid']}"
            em.set_content("The attached message was released from the quarantine.")
            em.add_attachment(raw.encode("utf-8", errors="replace"), maintype="message", subtype="rfc822", filename=f"{row['qid']}.eml")
            payload = em.as_string()
        else:
            payload = re.sub(r"^X-Spam-Flag: (.*)", r"X-Pre-Release-Spam-Flag \1", raw, flags=re.MULTILINE)
        err = _smtp_reinject("postfix", sender, row["rcpt"], payload)
        if err:
            ctx.warn(["quarantine", "release", rid], ["release_send_failed", err])
            return False
        ctx.db.exec("DELETE FROM quarantine WHERE id = %s", (rid,))
        ctx.ok(["quarantine", "release", rid], ["item_released", qhash or str(rid)])
    return True


def quarantine_delete_by_hash(ctx: Context, qhash: str) -> bool:
    rid = _quarantine_id_by_hash(ctx, qhash)
    if rid is None:
        ctx.denied(["quarantine", "delete", qhash])
        return False
    ctx.db.exec("DELETE FROM quarantine WHERE id = %s", (rid,))
    ctx.ok(["quarantine", "delete", qhash], ["item_deleted", qhash])
    return True
