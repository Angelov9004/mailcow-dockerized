"""Internal HTTP endpoints consumed by other containers (never exposed to the public internet by nginx).

  * POST /internal/auth              Dovecot passwd-verify.lua  (was mailcowauth.php, nginx :9082)
  * GET  /internal/dynmaps/*         rspamd lua + settings map  (was dynmaps/*.php, nginx :8081)
  * POST /internal/meta_exporter/*   rspamd metadata_exporter   (was meta_exporter/*.php, nginx :9081)
  * GET  /sogo-auth                  nginx auth_request for SOGo SSO (was sogo-auth.php)
"""
from __future__ import annotations

import base64
import email.header
import html
import ipaddress
import json
import logging
import re
import time
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse

from ..config import settings
from ..security.auth import apppass_login, check_login, set_sasl_log, user_login
from ..security.context import Context
from ..validators import is_email, parse_email, strip_plus_tag
from .deps import get_ctx
from ..services.mailbox import user_get_alias_details

log = logging.getLogger("mailcow.internal")
router = APIRouter()


def _sogo_sso_pass() -> str:
    try:
        with open(settings.sogo_sso_pass_file, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Dovecot authentication backend
# ---------------------------------------------------------------------------
@router.post("/internal/auth")
async def dovecot_auth(request: Request, ctx: Context = Depends(get_ctx)) -> Response:
    try:
        post = await request.json()
    except Exception:  # noqa: BLE001
        post = None
    if not isinstance(post, dict) or not all(k in post for k in ("username", "password", "real_rip")):
        log.error("MAILCOWAUTH: Bad Request")
        return JSONResponse({"success": False}, status_code=400)
    username, password, real_rip, service = str(post["username"]), str(post["password"]), str(post["real_rip"]), str(post.get("service") or "")
    ctx.real_ip = real_rip
    result: Any = False
    if real_rip == settings.sogo_ip:
        # SOGo auth request: check the SSO password first
        sso = _sogo_sso_pass()
        if sso and sso == password:
            log.info("MAILCOWAUTH: SOGo SSO auth for user %s", username)
            set_sasl_log(ctx, username, real_rip, "SOGO")
            result = True
    if result is False:
        result = apppass_login(ctx, username, password, {service: True}, is_internal=True)
        if result:
            log.info("MAILCOWAUTH: App auth for user %s", username)
            set_sasl_log(ctx, username, real_rip, service)
    if result is False:
        result = user_login(ctx, username, password, is_internal=True)
        if result:
            log.info("MAILCOWAUTH: User auth for user %s", username)
            set_sasl_log(ctx, username, real_rip, service)
    if result:
        return JSONResponse({"success": True}, status_code=200)
    log.warning("MAILCOWAUTH: Login failed for user %s", username)
    return JSONResponse({"success": False}, status_code=401)


# ---------------------------------------------------------------------------
# rspamd dynmaps
# ---------------------------------------------------------------------------
def _resolve_final_mailboxes(ctx: Context, rcpt: str, tag: str) -> list[str]:
    """Shared alias expansion used by aliasexp.php and pipe.php."""
    parsed = parse_email(rcpt)
    if not parsed:
        return []
    local, domain = parsed
    if not ctx.redis.hget("DOMAIN_MAP", domain):
        return []
    finals: list[str] = []
    row = ctx.db.one("SELECT goto FROM alias WHERE address = %s AND active = 1", (rcpt,))
    gotos = row["goto"] if row else None
    if not gotos:
        row = ctx.db.one("SELECT goto FROM alias WHERE address = %s AND active = 1", ("@" + domain,))
        gotos = row["goto"] if row else None
    if not gotos:
        row = ctx.db.one("SELECT target_domain FROM alias_domain WHERE alias_domain = %s AND active = 1", (domain,))
        if row:
            gotos = f"{local}@{row['target_domain']}"
    queue = [g for g in (gotos or "").split(",") if g]
    loop = 0
    while queue and loop <= 20:
        branch: list[str] = []
        for goto in queue:
            mb = ctx.db.one("SELECT username FROM mailbox WHERE username = %s AND (active = 1 OR active = 2)", (goto,))
            if mb:
                if mb["username"] not in finals:
                    finals.append(mb["username"])
                continue
            pg = parse_email(goto)
            if not pg or not ctx.redis.hget("DOMAIN_MAP", pg[1]):
                log.info("%s: %s is not a mailcow handled mailbox or alias address", tag, goto)
                continue
            row = ctx.db.one("SELECT goto FROM alias WHERE address = %s AND active = 1", (goto,))
            if row and row["goto"]:
                branch.extend(row["goto"].split(","))
            else:
                row = ctx.db.one("SELECT target_domain FROM alias_domain WHERE alias_domain = %s AND active = 1", (pg[1],))
                if row:
                    branch.append(f"{pg[0]}@{row['target_domain']}")
        queue = list(dict.fromkeys(branch))
        loop += 1
    return finals


@router.get("/internal/dynmaps/aliasexp", response_class=PlainTextResponse)
def dyn_aliasexp(request: Request, ctx: Context = Depends(get_ctx)) -> str:
    rcpt = strip_plus_tag(request.headers.get("rcpt", ""))
    finals = _resolve_final_mailboxes(ctx, rcpt, "ALIAS EXPANDER")
    if len(finals) == 1:
        log.info("ALIASEXP: direct alias %s expanded to %s", rcpt, finals[0])
        return finals[0].strip()
    return ""


@router.get("/internal/dynmaps/bcc")
def dyn_bcc(request: Request, ctx: Context = Depends(get_ctx)) -> Response:
    rcpt = strip_plus_tag(request.headers.get("rcpt", ""))
    sender = strip_plus_tag(request.headers.get("from", ""))
    if rcpt:
        row = ctx.db.one("SELECT bcc_dest FROM bcc_maps WHERE type = 'rcpt' AND local_dest = %s AND active = 1", (rcpt,))
        if row and is_email(row["bcc_dest"]):
            log.info("BCC MAP: returning %s for %s", row["bcc_dest"], rcpt)
            return PlainTextResponse(row["bcc_dest"].strip(), status_code=201)
    if sender:
        row = ctx.db.one("SELECT bcc_dest FROM bcc_maps WHERE type = 'sender' AND local_dest = %s AND active = 1", (sender,))
        if row and is_email(row["bcc_dest"]):
            log.info("BCC MAP: returning %s for %s", row["bcc_dest"], sender)
            return PlainTextResponse(row["bcc_dest"].strip(), status_code=201)
    return PlainTextResponse("", status_code=200)


@router.get("/internal/dynmaps/footer")
def dyn_footer(request: Request, ctx: Context = Depends(get_ctx)) -> Response:
    domain = request.headers.get("domain", "")
    username = request.headers.get("username", "")
    sender = request.headers.get("from", "")
    empty = {"html": "", "plain": "", "skip_replies": 0, "vars": {}}
    ad = ctx.db.one("SELECT target_domain FROM alias_domain WHERE alias_domain = %s", (domain,))
    target = ad["target_domain"] if ad else domain
    footer = ctx.db.one(
        "SELECT plain, html, mbox_exclude, alias_domain_exclude, skip_replies FROM domain_wide_footer WHERE domain = %s", (target,)
    )
    if footer and (sender in (footer["mbox_exclude"] or []) or domain in (footer["alias_domain_exclude"] or [])):
        footer = None
    if not footer:
        return JSONResponse(empty)
    row = ctx.db.one("SELECT custom_attributes FROM mailbox WHERE username = %s", (username,))
    out = {
        "plain": footer["plain"],
        "html": footer["html"],
        "mbox_exclude": footer["mbox_exclude"],
        "alias_domain_exclude": footer["alias_domain_exclude"],
        "skip_replies": int(footer["skip_replies"]),
        "vars": (row or {}).get("custom_attributes") or {},
    }
    return JSONResponse(out)


def _in_net(addr: str, net: str) -> bool:
    try:
        a = ipaddress.ip_address(addr)
        n = ipaddress.ip_network(net, strict=False)
        return a.version == n.version and a in n
    except ValueError:
        return False


@router.get("/internal/dynmaps/forwardinghosts", response_class=PlainTextResponse)
def dyn_forwardinghosts(request: Request, ctx: Context = Depends(get_ctx)) -> str:
    host = request.query_params.get("host")
    try:
        hosts = ctx.redis.hgetall("WHITELISTED_FWD_HOST") or {}
    except Exception:  # noqa: BLE001
        return "200 DUNNO" if host else "240.240.240.240\n"
    if host:
        for net in hosts:
            if _in_net(host, net):
                return "200 PERMIT"
        return "200 DUNNO"
    return "240.240.240.240\n" + "".join(f"{h}\n" for h in hosts)


def _rspamd_regex(local: str, domain: str) -> str:
    return "/^" + local.replace("/", "\\/") + "[+].*" + domain.replace("/", "\\/") + "$/i"


def _ucl_rcpts(ctx: Context, obj: str, type_: str) -> list[str]:
    rcpt: list[str] = []
    if type_ == "mailbox":
        for r in ctx.db.all("SELECT address FROM alias WHERE goto = %s AND address NOT LIKE '@%%'", (obj,)):
            p = parse_email(r["address"])
            if p and p[0] and p[1]:
                rcpt.append(_rspamd_regex(p[0], "@" + p[1]))
            rcpt.append(r["address"].replace("/", "\\/"))
        for r in ctx.db.all(
            """SELECT local_part || '@' || alias_domain.alias_domain AS alias FROM mailbox
               LEFT OUTER JOIN alias_domain ON mailbox.domain = alias_domain.target_domain WHERE mailbox.username = %s""",
            (obj,),
        ):
            if r["alias"] and "@" in r["alias"]:
                p = parse_email(r["alias"])
                if p and p[0] and p[1]:
                    rcpt.append(_rspamd_regex(p[0], "@" + p[1]))
                rcpt.append(r["alias"].replace("/", "\\/"))
    else:
        rcpt.append(f"/.*@{obj}/i")
        for r in ctx.db.all("SELECT alias_domain FROM alias_domain WHERE target_domain = %s", (obj,)):
            rcpt.append(f"/.*@{r['alias_domain']}/i")
    return rcpt


def _normalize_email(e: str) -> str:
    e = e.lower().replace("/", "\\/")
    if e.endswith("@gmail.com"):
        local, dom = e.split("@", 1)
        e = local.replace(".", "") + "@" + dom
    if e.endswith("@googlemail.com"):
        local, _ = e.split("@", 1)
        e = local.replace(".", "") + "@gmail.com"
    if "+" in e:
        local, dom = e.split("@", 1)
        e = local.split("+")[0] + "@" + dom
    return e


def _wl_regex(value: str) -> str:
    return "/" + "^" + re.escape(value).replace("\\*", ".*") + "$" + "/i"


@router.get("/internal/dynmaps/settings", response_class=PlainTextResponse)
def dyn_settings(request: Request, ctx: Context = Depends(get_ctx)) -> Response:
    """rspamd settings map: per-user scores, white/blacklists, SOGo contacts, traps, custom settings."""
    try:
        ctx.db.one("SELECT 1 FROM filterconf LIMIT 1")
    except Exception:  # noqa: BLE001
        return PlainTextResponse("settings { }")
    # Last-Modified support: newest change in the relevant tables
    row = ctx.db.one(
        """SELECT GREATEST(
             COALESCE((SELECT EXTRACT(EPOCH FROM MAX(GREATEST(created, COALESCE(modified, created)))) FROM filterconf), 1),
             COALESCE((SELECT EXTRACT(EPOCH FROM MAX(GREATEST(created, COALESCE(modified, created)))) FROM settingsmap), 1),
             COALESCE((SELECT EXTRACT(EPOCH FROM MAX(GREATEST(created, COALESCE(modified, created)))) FROM alias), 1),
             COALESCE((SELECT MAX(c_lastmodified) FROM sogo_folder_info f JOIN sogo_store s ON s.c_folder_id = f.c_folder_id), 1)
           ) AS t"""
    )
    db_update_time = int(row["t"] or 1572048000)
    last_mod = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(db_update_time))
    ims = request.headers.get("if-modified-since")
    if ims == last_mod:
        return Response(status_code=304, headers={"Last-Modified": last_mod})

    out: list[str] = []
    out.append(
        """settings {
  watchdog {
    priority = 10;
    rcpt_mime = "/null@localhost/i";
    from_mime = "/watchdog@localhost/i";
    apply "default" {
      symbols_disabled = ["HISTORY_SAVE", "ARC", "ARC_SIGNED", "DKIM", "DKIM_SIGNED", "CLAM_VIRUS"];
      want_spam = yes;
      actions {
        reject = 9999.0;
        greylist = 9998.0;
        "add header" = 9997.0;
      }

    }
  }"""
    )

    def sane(s: str) -> str:
        return re.sub(r"[^a-zA-Z0-9]+", "", s)

    def rcpt_lines(obj: str) -> str:
        t = "domain" if "@" not in obj else "mailbox"
        return "".join(f"    rcpt = {json.dumps(r)};\n" for r in _ucl_rcpts(ctx, obj, t))

    # custom scores
    for r in ctx.db.all("SELECT DISTINCT object FROM filterconf WHERE option IN ('highspamlevel', 'lowspamlevel')"):
        obj = r["object"]
        scores = {x["option"]: x["value"] for x in ctx.db.all("SELECT option, value FROM filterconf WHERE option IN ('highspamlevel','lowspamlevel') AND object = %s", (obj,))}
        try:
            high = float(scores.get("highspamlevel", 15))
            low = float(scores.get("lowspamlevel", 5))
        except ValueError:
            continue
        out.append(
            f"  score_{sane(obj)} {{\n    priority = 4;\n{rcpt_lines(obj)}    apply \"default\" {{\n      actions {{\n"
            f"        reject = {high:g};\n        greylist = {low - 1:g};\n        \"add header\" = {low:g};\n      }}\n    }}\n  }}"
        )
    # SOGo contacts whitelist
    for r in ctx.db.all(
        """SELECT sogo_folder_info.c_path2 AS username, string_agg(sogo_quick_contact.c_mail, ',') AS contacts FROM sogo_folder_info
           INNER JOIN sogo_quick_contact ON sogo_quick_contact.c_folder_id = sogo_folder_info.c_folder_id GROUP BY c_path2"""
    ):
        contacts = [_normalize_email(c) for c in (r["contacts"] or "").split(",") if is_email(c)]
        if not contacts or not r["username"]:
            continue
        froms = "".join(f"    from = {json.dumps(c)};\n" for c in contacts)
        out.append(
            f"  whitelist_sogo_{sane(r['username'])} {{\n{froms}    priority = 4;\n{''.join(f'    rcpt = {json.dumps(x)};' + chr(10) for x in _ucl_rcpts(ctx, r['username'], 'mailbox'))}"
            f"    apply \"default\" {{\n      SOGO_CONTACT = -99.0;\n    }}\n    symbols [\n      \"SOGO_CONTACT\"\n    ]\n  }}"
        )
    # white/blacklists
    for option, name, symbol, score in (("whitelist_from", "whitelist", "MAILCOW_WHITE", -999.0), ("blacklist_from", "blacklist", "MAILCOW_BLACK", 999.0)):
        for r in ctx.db.all("SELECT DISTINCT object FROM filterconf WHERE option = %s", (option,)):
            obj = r["object"]
            items = [x["value"] for x in ctx.db.all("SELECT value FROM filterconf WHERE object = %s AND option = %s", (obj, option))]
            prio = 6 if is_email(obj.strip()) else 5
            for hdr, suffix in (("from", ""), ("from_mime", "_mime" if name == "whitelist" else "_header")):
                lines = "".join(f'    {hdr} = "{_wl_regex(v)}";\n' for v in items)
                out.append(
                    f"  {name}{suffix}_{sane(obj)} {{\n{lines}    priority = {prio};\n{rcpt_lines(obj)}"
                    f"    apply \"default\" {{\n      {symbol} = {score};\n    }}\n    symbols [\n      \"{symbol}\"\n    ]\n  }}"
                )
    # traps
    for trap, sym in (("ham@localhost", "HAM_TRAP"), ("spam@localhost", "SPAM_TRAP")):
        out.append(
            f"  {sym.lower()} {{\n{''.join(f'    rcpt = {json.dumps(x)};' + chr(10) for x in _ucl_rcpts(ctx, trap, 'mailbox'))}    priority = 9;\n"
            f"    apply \"default\" {{\n      symbols_enabled = [\"HISTORY_SAVE\"];\n    }}\n    symbols [\n      \"{sym}\"\n    ]\n  }}"
        )
    # additional settings
    for r in ctx.db.all("SELECT id, content FROM settingsmap WHERE active = 1"):
        body = "".join(f"    {line}\n" for line in re.split(r"\r\n|\r|\n", r["content"] or ""))
        out.append(f"  additional_settings_{int(r['id'])} {{\n{body}  }}")
    out.append("}")
    return PlainTextResponse("\n".join(out), headers={"Last-Modified": last_mod})


# ---------------------------------------------------------------------------
# rspamd metadata exporter
# ---------------------------------------------------------------------------
def _decode_mime_header(value: str) -> str:
    try:
        return str(email.header.make_header(email.header.decode_header(value)))
    except Exception:  # noqa: BLE001
        return value


@router.post("/internal/meta_exporter/pipe")
async def meta_pipe(request: Request, ctx: Context = Depends(get_ctx)) -> Response:
    """Quarantine intake."""
    raw = await request.body()
    h = request.headers
    qid = h.get("x-rspamd-qid", "")
    fuzzy = h.get("x-rspamd-fuzzy", "[]")
    subject = _decode_mime_header(h.get("x-rspamd-subject", ""))
    score = h.get("x-rspamd-score")
    rcpts = h.get("x-rspamd-rcpt", "[]")
    user = h.get("x-rspamd-user", "") or "unknown"
    ip = h.get("x-rspamd-ip", "")
    action = h.get("x-rspamd-action", "unknown")
    sender = h.get("x-rspamd-from", "") or "empty-env-from@localhost"
    symbols = h.get("x-rspamd-symbols", "[]")
    if fuzzy == "unknown":
        fuzzy = "[]"
    try:
        max_size = int(ctx.redis.get("Q_MAX_SIZE") or 0)
        if max_size * 1048576 < len(raw):
            log.warning("QUARANTINE: Message too large: %d b exceeds %d b", len(raw), max_size * 1048576)
            return PlainTextResponse("", status_code=505)
        exclude = json.loads(ctx.redis.get("Q_EXCLUDE_DOMAINS") or "[]")
        retention = int(ctx.redis.get("Q_RETENTION_SIZE") or 0)
    except Exception as exc:  # noqa: BLE001
        log.error("QUARANTINE: %s", exc)
        return PlainTextResponse("", status_code=504)
    try:
        rcpt_list = json.loads(rcpts)
    except ValueError:
        rcpt_list = []
    finals: list[str] = []
    for rcpt in rcpt_list:
        rcpt = strip_plus_tag(rcpt)
        p = parse_email(rcpt)
        if not p or not ctx.redis.hget("DOMAIN_MAP", p[1]):
            continue
        if p[1] in exclude:
            log.info("QUARANTINE: Skipped domain %s", p[1])
            continue
        for f in _resolve_final_mailboxes(ctx, rcpt, "RCPT RESOLVER"):
            if f not in finals:
                finals.append(f)
    msg_text = html.escape(raw.decode("utf-8", errors="replace"), quote=False)
    try:
        score_val = float(score) if score not in (None, "") else None
    except ValueError:
        score_val = None
    for rcpt_final in finals:
        log.info("QUARANTINE: quarantine pipe: processing quarantine message for rcpt %s", rcpt_final)
        try:
            ctx.db.exec(
                """INSERT INTO quarantine (qid, subject, score, sender, rcpt, symbols, username, ip, msg, action, fuzzy_hashes)
                   VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s::jsonb)""",
                (qid, subject[:500], score_val, sender[:255], rcpt_final, symbols, user[:255], ip[:50], msg_text, action[:20], fuzzy),
            )
            ctx.db.exec(
                """DELETE FROM quarantine WHERE rcpt = %s AND id NOT IN (
                     SELECT id FROM quarantine WHERE rcpt = %s ORDER BY id DESC LIMIT %s)""",
                (rcpt_final, rcpt_final, retention),
            )
        except Exception as exc:  # noqa: BLE001
            log.error("QUARANTINE: %s", exc)
            return PlainTextResponse("", status_code=503)
    return PlainTextResponse("")


@router.post("/internal/meta_exporter/pipe_rl")
async def meta_pipe_rl(request: Request, ctx: Context = Depends(get_ctx)) -> Response:
    try:
        d = await request.json()
    except Exception:  # noqa: BLE001
        return PlainTextResponse("")
    data: dict[str, Any] = {
        "time": int(time.time()),
        "rcpt": ", ".join(d.get("rcpt") or []),
        "from": d.get("from"),
        "user": d.get("user"),
    }
    rl_info = ""
    for s in d.get("symbols") or []:
        if s.get("name") == "RATELIMITED":
            rl_info = "".join(s.get("options") or [])
            break
    data["rl_info"] = rl_info
    m = re.match(r"(.+)\((.+)\)", rl_info, re.IGNORECASE)
    data["rl_name"], data["rl_hash"] = (m.group(1), m.group(2)) if m else ("err", "err")
    data["qid"] = d.get("qid")
    data["ip"] = d.get("ip")
    data["message_id"] = d.get("message_id")
    data["header_subject"] = " ".join(d.get("header_subject") or [])
    data["header_from"] = ", ".join(d.get("header_from") or [])
    ctx.redis.lpush("RL_LOG", json.dumps(data))
    return PlainTextResponse("")


@router.post("/internal/meta_exporter/pushover")
async def meta_pushover(request: Request, ctx: Context = Depends(get_ctx)) -> Response:
    """Pushover notifications for new mail (port of meta_exporter/pushover.php)."""
    import httpx

    try:
        d = await request.json()
    except Exception:  # noqa: BLE001
        return PlainTextResponse("")
    rcpts = d.get("rcpt") or []
    sender = (d.get("from") or "").lower()
    header_from = ", ".join(d.get("header_from") or [])
    subject = " ".join(d.get("header_subject") or [])
    priority_hdr = ""
    for s in d.get("symbols") or []:
        pass
    finals: list[str] = []
    for rcpt in rcpts:
        rcpt = strip_plus_tag(rcpt)
        for f in _resolve_final_mailboxes(ctx, rcpt, "PUSHOVER"):
            if f not in finals:
                finals.append(f)
    for rcpt_final in finals:
        row = ctx.db.one("SELECT * FROM pushover WHERE username = %s AND active = 1", (rcpt_final,))
        if not row:
            continue
        attrs = row.get("attributes") or {}
        senders = [s.strip().lower() for s in (row.get("senders") or "").split(",") if s.strip()]
        senders_regex = (row.get("senders_regex") or "").strip()
        matched = not senders and not senders_regex
        if senders and sender in senders:
            matched = True
        if senders_regex:
            try:
                if re.search(senders_regex.strip("/"), sender, re.IGNORECASE):
                    matched = True
            except re.error:
                pass
        if not matched:
            continue
        title = (row.get("title") or "Mail") if row.get("title") else "Mail"
        text = row.get("text") or "From {SENDER}"
        repl = {"{SUBJECT}": subject, "{SENDER}": sender, "{SENDER_NAME}": header_from, "{TO}": rcpt_final, "{PRIORITY}": priority_hdr}
        for k, v in repl.items():
            title = title.replace(k, v)
            text = text.replace(k, v)
        try:
            httpx.post(
                "https://api.pushover.net/1/messages.json",
                data={"token": row["token"], "user": row["key"], "title": title, "message": text, "sound": attrs.get("sound", "pushover")},
                timeout=10,
            )
        except Exception as exc:  # noqa: BLE001
            log.error("PUSHOVER: %s", exc)
    return PlainTextResponse("")


# ---------------------------------------------------------------------------
# SOGo SSO (nginx auth_request)
# ---------------------------------------------------------------------------
SESSION_VAR_USER_ALLOWED = "sogo-sso-user-allowed"


@router.get("/sogo-auth")
def sogo_auth(request: Request, ctx: Context = Depends(get_ctx)) -> Response:
    auth = request.headers.get("authorization", "")
    original_uri = request.headers.get("x-original-uri", "")
    empty_headers = {"X-User": "", "X-Auth": "", "X-Auth-Type": ""}

    if auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8", errors="replace")
            username, password = decoded.split(":", 1)
        except Exception:  # noqa: BLE001
            return PlainTextResponse("Invalid login", status_code=401)
        is_dav = re.match(r"^(/SOGo|)/dav.*", original_uri) is not None
        is_eas = re.match(r"^(/SOGo|)/Microsoft-Server-ActiveSync.*", original_uri) is not None
        result = check_login(ctx, username, password, {"dav": is_dav, "eas": is_eas})
        if result == "user":
            return Response(
                status_code=200,
                headers={
                    "X-User": username,
                    "X-Auth": "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode(),
                    "X-Auth-Type": "Basic",
                },
            )
        return PlainTextResponse("Invalid login", status_code=401)

    login = request.query_params.get("login")
    if login is not None:
        login = html.unescape(login)
        is_dual = bool((ctx.session.get("dual-login") or {}).get("username"))
        allow_admin = settings.allow_admin_email_login
        if ctx.role and ((str(ctx.acl.get("login_as")) == "1" and allow_admin) or (not is_dual and login == ctx.username)):
            if is_email(login) and user_get_alias_details(ctx, login):
                allowed = list(ctx.session.get(SESSION_VAR_USER_ALLOWED) or [])
                if login not in allowed:
                    allowed.append(login)
                ctx.session[SESSION_VAR_USER_ALLOWED] = allowed
                if str(ctx.acl.get("login_as")) == "1" and allow_admin and not is_dual and ctx.role != "user":
                    ctx.session["dual-login"] = {"username": ctx.username, "role": ctx.role}
                    ctx.session["mailcow_cc_username"] = login
                    ctx.session["mailcow_cc_role"] = "user"
                ctx.db.exec(
                    """INSERT INTO sasl_log (service, app_password, username, real_rip, datetime) VALUES ('SSO', 0, %s, %s, NOW())
                       ON CONFLICT (service, real_rip, username) DO UPDATE SET datetime = NOW()""",
                    (login, ctx.real_ip),
                )
                return RedirectResponse(f"/SOGo/so/{login}", status_code=302)
        return RedirectResponse("/", status_code=302)

    if original_uri.lower().startswith("/sogo/so/"):
        parts = original_uri.split("/")
        requested = parts[3] if len(parts) > 3 else ""
        allowed = ctx.session.get(SESSION_VAR_USER_ALLOWED) or []
        for candidate in (requested, ctx.username or "", (ctx.session.get("dual-login") or {}).get("username", "")):
            if candidate and is_email(candidate) and candidate in allowed:
                password = _sogo_sso_pass()
                return Response(
                    status_code=200,
                    headers={
                        "X-User": candidate,
                        "X-Auth": "Basic " + base64.b64encode(f"{candidate}:{password}".encode()).decode(),
                        "X-Auth-Type": "Basic",
                    },
                )
    return Response(status_code=200, headers=empty_headers)
