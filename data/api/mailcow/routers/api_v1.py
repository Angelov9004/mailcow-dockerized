"""REST API v1 - compatible with the mailcow API layout:

  GET  /api/v1/get/<category>[/<object>[/<extra>]]
  POST /api/v1/add/<category>      JSON object
  POST /api/v1/edit/<category>     JSON {"items": [...], "attr": {...}}  (or a flat object)
  POST /api/v1/delete/<category>   JSON list of ids / names

Authentication: API key (X-API-Key header, ro/rw + IP ACL) or a browser session (cookie + X-CSRF-Token).
Every write returns the list of log messages that the PHP API returned as well.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from ..security import tfa as tfa_svc
from ..security.acl import acl_edit, acl_get
from ..security.context import Context, check_csrf, require_login, require_rw
from ..security.policy import password_complexity_edit, password_complexity_get
from ..services import admins, fail2ban, mailbox, misc
from ..services.common import dkim_add, dkim_blind, dkim_delete, dkim_details, dkim_duplicate, dkim_import, docker, quarantine_settings_get, ratelimit_delete_hash, ratelimit_edit, ratelimit_get
from ..validators import as_list, is_email, to_int
from .deps import get_ctx

log = logging.getLogger("mailcow.api")
router = APIRouter(prefix="/api/v1")


def _messages(ctx: Context) -> list[dict]:
    return [m.as_dict() for m in ctx.messages]


def _json_default(o: Any) -> Any:
    import datetime
    import decimal

    if isinstance(o, (datetime.datetime, datetime.date)):
        return o.isoformat(sep=" ")
    if isinstance(o, decimal.Decimal):
        return float(o)
    if isinstance(o, (bytes, bytearray)):
        return o.decode("utf-8", errors="replace")
    return str(o)


def respond(data: Any, status: int = 200, headers: dict | None = None) -> JSONResponse:
    return JSONResponse(content=json.loads(json.dumps(data, default=_json_default)), status_code=status, headers=headers)


async def _body(request: Request) -> Any:
    raw = await request.body()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except ValueError:
        # accept form posts from the UI as well
        form = await request.form()
        out: dict[str, Any] = {}
        for k, v in form.multi_items():
            key = k[:-2] if k.endswith("[]") else k
            if key in out:
                out[key] = as_list(out[key]) + [v]
            else:
                out[key] = [v] if k.endswith("[]") else v
        return out


def _write_guard(ctx: Context, request: Request, body: Any) -> None:
    require_login(ctx)
    require_rw(ctx)
    if not ctx.is_api:
        token = request.headers.get("x-csrf-token")
        if token is None and isinstance(body, dict):
            token = body.get("csrf_token")
        if not check_csrf(ctx, token):
            raise HTTPException(status_code=403, detail={"type": "error", "msg": "session_token"})


def _edit_payload(body: Any) -> tuple[list, dict]:
    """PHP: items + attr, else the flat object."""
    if isinstance(body, dict) and "attr" in body:
        items = as_list(body.get("items"))
        attr = dict(body.get("attr") or {})
        return items, attr
    return as_list(body.get("items")) if isinstance(body, dict) else [], dict(body) if isinstance(body, dict) else {}


# ---------------------------------------------------------------------------
# GET
# ---------------------------------------------------------------------------
def _get_domain(ctx: Context, obj: str | None, extra: str | None) -> Any:
    if obj in (None, "all"):
        tags = as_list(extra.split(",")) if extra else None
        out = []
        for d in mailbox.get_domains(ctx, tags):
            details = mailbox.domain_details(ctx, d)
            if details:
                out.append(details)
        return out
    return mailbox.domain_details(ctx, obj) or {}


def _get_mailbox(ctx: Context, obj: str | None, extra: str | None) -> Any:
    reduced = extra == "reduced"
    if obj in (None, "all"):
        out = []
        for m in mailbox.get_mailboxes(ctx):
            d = mailbox.mailbox_details(ctx, m, reduced=reduced)
            if d:
                out.append(d)
        return out
    if is_email(obj):
        return mailbox.mailbox_details(ctx, obj, reduced=reduced) or {}
    # object is a domain
    out = []
    for m in mailbox.get_mailboxes(ctx, obj):
        d = mailbox.mailbox_details(ctx, m, reduced=reduced)
        if d:
            out.append(d)
    return out


def _get_alias(ctx: Context, obj: str | None, extra: str | None) -> Any:
    if obj in (None, "all"):
        out = []
        for d in mailbox.get_domains(ctx) + mailbox.get_alias_domains(ctx):
            for a in mailbox.get_aliases(ctx, d):
                det = mailbox.alias_details(ctx, a)
                if det:
                    out.append(det)
        return out
    if str(obj).isdigit() or "@" in obj:
        return mailbox.alias_details(ctx, obj) or {}
    out = []
    for a in mailbox.get_aliases(ctx, obj):
        det = mailbox.alias_details(ctx, a)
        if det:
            out.append(det)
    return out


def _get_alias_domain(ctx: Context, obj: str | None, extra: str | None) -> Any:
    if obj in (None, "all"):
        return [d for d in (mailbox.alias_domain_details(ctx, a) for a in mailbox.get_alias_domains(ctx)) if d]
    det = mailbox.alias_domain_details(ctx, obj)
    if det:
        return det
    return [d for d in (mailbox.alias_domain_details(ctx, a) for a in mailbox.get_alias_domains(ctx, obj)) if d]


def _get_logs(ctx: Context, obj: str | None, extra: str | None) -> Any:
    if not obj:
        return {}
    lines, offset = None, 0
    if extra:
        parts = extra.split("/")
        if parts[0].isdigit():
            lines = int(parts[0])
        if len(parts) > 1 and parts[1].isdigit():
            offset = int(parts[1])
    return misc.get_logs(ctx, obj, lines, offset) or []


def _get_status(ctx: Context, obj: str | None, extra: str | None) -> Any:
    if ctx.role != "admin":
        return {}
    if obj == "containers":
        containers = docker(ctx, "containers")
        out = {}
        if isinstance(containers, dict):
            for name, c in containers.items():
                out[name] = {
                    "type": "info",
                    "container": name,
                    "state": c.get("State", {}).get("Status"),
                    "started_at": c.get("State", {}).get("StartedAt"),
                    "image": c.get("Config", {}).get("Image"),
                }
        return out
    if obj == "version":
        import os as _os

        from .. import __version__

        info = {"version": __version__}
        path = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "..", "app_info.json")
        try:
            with open(path, "r", encoding="utf-8") as fh:
                info.update(json.load(fh))
        except (OSError, ValueError):
            pass
        return info
    if obj == "vmail":
        return docker(ctx, "post", "dovecot-mailcow", "exec", {"cmd": "system", "task": "df", "dir": "/var/vmail"})
    if obj == "host":
        return docker(ctx, "host_stats")
    return {}


GET_HANDLERS: dict[str, Callable[[Context, str | None, str | None], Any]] = {
    "domain": _get_domain,
    "mailbox": _get_mailbox,
    "alias": _get_alias,
    "alias-domain": _get_alias_domain,
    "admin": lambda ctx, o, e: (
        [d for d in (admins.admin_details(ctx, a) for a in admins.admin_get(ctx)) if d] if o in (None, "all") else admins.admin_details(ctx, o) or {}
    ),
    "domain-admin": lambda ctx, o, e: (
        [d for d in (admins.domain_admin_details(ctx, a) for a in admins.domain_admin_get(ctx)) if d]
        if o in (None, "all")
        else admins.domain_admin_details(ctx, o) or {}
    ),
    "app-passwd": lambda ctx, o, e: (
        [admins.app_passwd_details(ctx, r["id"]) for r in admins.app_passwd_get(ctx, {"username": e} if e else None)]
        if o in (None, "all")
        else admins.app_passwd_details(ctx, o) or {}
    ),
    "user-acl": lambda ctx, o, e: acl_get(ctx, "user", o or ctx.username or "") or {},
    "da-acl": lambda ctx, o, e: acl_get(ctx, "domainadmin", o or ctx.username or "") or {},
    "dkim": lambda ctx, o, e: dkim_details(ctx, o or "") if o else {},
    "dkim_blind": lambda ctx, o, e: dkim_blind(ctx),
    "fail2ban": lambda ctx, o, e: fail2ban.fail2ban_get(ctx) or {},
    "passwordpolicy": lambda ctx, o, e: password_complexity_get(ctx),
    "rl-domain": lambda ctx, o, e: (
        [{"domain": d, **(ratelimit_get(ctx, "domain", d) or {})} for d in mailbox.get_domains(ctx) if ratelimit_get(ctx, "domain", d)]
        if o in (None, "all")
        else ratelimit_get(ctx, "domain", o) or {}
    ),
    "rl-mbox": lambda ctx, o, e: (
        [{"mailbox": m, **(ratelimit_get(ctx, "mailbox", m) or {})} for m in mailbox.get_mailboxes(ctx) if ratelimit_get(ctx, "mailbox", m)]
        if o in (None, "all")
        else ratelimit_get(ctx, "mailbox", o) or {}
    ),
    "relayhost": lambda ctx, o, e: (misc.relayhost_get(ctx) if o in (None, "all") else misc.relayhost_get(ctx, o)) or {},
    "transport": lambda ctx, o, e: (misc.transport_get(ctx) if o in (None, "all") else misc.transport_get(ctx, o)) or {},
    "bcc": lambda ctx, o, e: (misc.bcc_get(ctx) if o in (None, "all") else misc.bcc_get(ctx, o)) or {},
    "recipient_map": lambda ctx, o, e: (misc.recipient_map_get(ctx) if o in (None, "all") else misc.recipient_map_get(ctx, o)) or {},
    "tls-policy-map": lambda ctx, o, e: (misc.tls_policy_map_get(ctx) if o in (None, "all") else misc.tls_policy_map_get(ctx, o)) or {},
    "rsetting": lambda ctx, o, e: (misc.rsetting_get(ctx) if o in (None, "all") else misc.rsetting_get(ctx, o)) or {},
    "rspamd-map": lambda ctx, o, e: {"map": o, "content": misc.rspamd_map_get(ctx, o or "")} if o else {"maps": ctx and __import__("mailcow.config", fromlist=["settings"]).settings.rspamd_maps},
    "fwdhost": lambda ctx, o, e: misc.fwdhost_get(ctx),
    "quarantine": lambda ctx, o, e: misc.quarantine_get(ctx) if o in (None, "all") else misc.quarantine_details(ctx, o) or {},
    "quarantine_settings": lambda ctx, o, e: quarantine_settings_get(ctx) if ctx.role == "admin" else {},
    "tls-policy": lambda ctx, o, e: mailbox.tls_policy_get(ctx, o) or {},
    "quarantine_notification": lambda ctx, o, e: {"quarantine_notification": mailbox.quarantine_setting_get(ctx, "quarantine_notification", o)},
    "quarantine_category": lambda ctx, o, e: {"quarantine_category": mailbox.quarantine_setting_get(ctx, "quarantine_category", o)},
    "spam-score": lambda ctx, o, e: {"spam_score": mailbox.spam_score_get(ctx, o)},
    "last-login": lambda ctx, o, e: admins.last_login_get(ctx, o or ctx.username or "", to_int(e, 7) if e else 7),
    "reset-last-login": lambda ctx, o, e: {"reset": admins.last_login_reset(ctx, o or ctx.username or "")},
    "logs": _get_logs,
    "status": _get_status,
    "template": lambda ctx, o, e: (mailbox.get_templates(ctx, o or "domain") if e in (None, "all") else mailbox.get_templates(ctx, o or "domain", e)) or [],
    "sender_acl": lambda ctx, o, e: mailbox.sender_acl_handles(ctx, o or "") or {},
    "user_alias_details": lambda ctx, o, e: mailbox.user_get_alias_details(ctx, o) or {},
    "tfa": lambda ctx, o, e: tfa_svc.get_tfa(ctx, ctx.username, to_int(o) if o else None) or {},
    "webauthn-tfa-registration": lambda ctx, o, e: tfa_svc.webauthn_registration_options(ctx) or {},
    "webauthn-tfa-get-args": lambda ctx, o, e: tfa_svc.webauthn_authentication_options(ctx) or {},
    "totp-secret": lambda ctx, o, e: (lambda s: {"secret": s, "uri": tfa_svc.totp_provisioning_uri(s, ctx.username or "")})(tfa_svc.totp_new_secret()),
}


@router.get("/get/{category}")
@router.get("/get/{category}/{obj}")
@router.get("/get/{category}/{obj}/{extra:path}")
def api_get(category: str, obj: str | None = None, extra: str | None = None, ctx: Context = Depends(get_ctx)) -> Any:
    if category == "fail2ban" and obj == "banlist":
        res = fail2ban.fail2ban_banlist(ctx, "get", extra)
        if res is None:
            raise HTTPException(status_code=404)
        return PlainTextResponse(res)
    if category == "webauthn-tfa-get-args":
        # allowed while a login is pending
        if not ctx.session.get("pending_mailcow_cc_username") and not ctx.role:
            raise HTTPException(status_code=401, detail={"type": "error", "msg": "authentication failed"})
    else:
        require_login(ctx)
    handler = GET_HANDLERS.get(category)
    if handler is None:
        raise HTTPException(status_code=404, detail={"type": "error", "msg": f"unknown category {category}"})
    try:
        data = handler(ctx, obj, extra)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        log.exception("api get %s failed", category)
        ctx.err(["api", "get", category], ["mysql_error", str(exc)])
        raise HTTPException(status_code=500, detail={"type": "error", "msg": str(exc)}) from exc
    if data is None or data == {} or data == []:
        # the PHP API returned {} for "nothing found"
        return respond({})
    return respond(data)


# ---------------------------------------------------------------------------
# ADD / EDIT / DELETE
# ---------------------------------------------------------------------------
def _edit_many(fn: Callable[[Context, dict], Any], key: str) -> Callable[[Context, list, dict], Any]:
    def inner(ctx: Context, items: list, attr: dict) -> Any:
        data = dict(attr)
        if items:
            data[key] = items
        return fn(ctx, data)

    return inner


ADD_HANDLERS: dict[str, Callable[[Context, dict], Any]] = {
    "domain": mailbox.domain_add,
    "mailbox": mailbox.mailbox_add,
    "alias": mailbox.alias_add,
    "alias-domain": mailbox.alias_domain_add,
    "admin": admins.admin_add,
    "domain-admin": admins.domain_admin_add,
    "app-passwd": admins.app_passwd_add,
    "dkim": dkim_add,
    "dkim_duplicate": dkim_duplicate,
    "dkim_import": dkim_import,
    "relayhost": misc.relayhost_add,
    "transport": misc.transport_add,
    "bcc": misc.bcc_add,
    "recipient_map": misc.recipient_map_add,
    "tls-policy-map": misc.tls_policy_map_add,
    "rsetting": misc.rsetting_add,
    "fwdhost": misc.fwdhost_add,
    "tfa": tfa_svc.set_tfa,
    "sso": lambda ctx, d: admins.domain_admin_sso_issue(ctx, d),
}

EDIT_HANDLERS: dict[str, Callable[[Context, list, dict], Any]] = {
    "domain": _edit_many(mailbox.domain_edit, "domain"),
    "mailbox": _edit_many(mailbox.mailbox_edit, "username"),
    "alias": _edit_many(mailbox.alias_edit, "id"),
    "alias-domain": _edit_many(mailbox.alias_domain_edit, "alias_domain"),
    "admin": _edit_many(admins.admin_edit, "username"),
    "domain-admin": _edit_many(admins.domain_admin_edit, "username"),
    "app-passwd": _edit_many(admins.app_passwd_edit, "id"),
    "user-acl": lambda ctx, items, attr: acl_edit(ctx, "user", {**attr, "username": items or attr.get("username")}),
    "da-acl": lambda ctx, items, attr: acl_edit(ctx, "domainadmin", {**attr, "username": items or attr.get("username")}),
    "fail2ban": lambda ctx, items, attr: fail2ban.fail2ban_edit(ctx, {**attr, **({"network": items} if items else {})}),
    "passwordpolicy": lambda ctx, items, attr: password_complexity_edit(ctx, attr),
    "rl-domain": lambda ctx, items, attr: ratelimit_edit(ctx, "domain", {**attr, "object": items or attr.get("object")}),
    "rl-mbox": lambda ctx, items, attr: ratelimit_edit(ctx, "mailbox", {**attr, "object": items or attr.get("object")}),
    "relayhost": _edit_many(misc.relayhost_edit, "id"),
    "transport": _edit_many(misc.transport_edit, "id"),
    "bcc": _edit_many(misc.bcc_edit, "id"),
    "recipient_map": _edit_many(misc.recipient_map_edit, "id"),
    "tls-policy-map": _edit_many(misc.tls_policy_map_edit, "id"),
    "rsetting": _edit_many(misc.rsetting_edit, "id"),
    "rspamd-map": lambda ctx, items, attr: misc.rspamd_map_edit(ctx, attr),
    "quarantine_settings": lambda ctx, items, attr: misc.quarantine_settings_edit(ctx, attr),
    "qitem": lambda ctx, items, attr: misc.quarantine_release(ctx, ids=items) if attr.get("action") == "release" else misc.quarantine_delete(ctx, {"id": items}),
    "tls-policy": _edit_many(mailbox.tls_policy_edit, "username"),
    "quarantine_notification": _edit_many(lambda c, d: mailbox.quarantine_setting_edit(c, "quarantine_notification", d), "username"),
    "quarantine_category": _edit_many(lambda c, d: mailbox.quarantine_setting_edit(c, "quarantine_category", d), "username"),
    "spam-score": _edit_many(mailbox.spam_score_edit, "username"),
    "user": lambda ctx, items, attr: mailbox.edit_user_account(ctx, attr),
    "self": lambda ctx, items, attr: mailbox.edit_user_account(ctx, attr) if ctx.role == "user" else admins.domain_admin_edit(ctx, attr),
    "api": lambda ctx, items, attr: admins.admin_api(ctx, attr.get("access", "rw"), "regen_key" if attr.get("regen_key") else "edit", attr),
    "tfa": lambda ctx, items, attr: tfa_svc.unset_tfa_key(ctx, attr) if "unset_tfa_key" in attr else tfa_svc.set_tfa(ctx, attr),
}

DELETE_HANDLERS: dict[str, Callable[[Context, list, dict], Any]] = {
    "domain": lambda ctx, items, attr: mailbox.domain_delete(ctx, {"domain": items}),
    "mailbox": lambda ctx, items, attr: mailbox.mailbox_delete(ctx, {"username": items}),
    "alias": lambda ctx, items, attr: mailbox.alias_delete(ctx, {"id": items}),
    "alias-domain": lambda ctx, items, attr: mailbox.alias_domain_delete(ctx, {"alias_domain": items}),
    "admin": lambda ctx, items, attr: admins.admin_delete(ctx, {"username": items}),
    "domain-admin": lambda ctx, items, attr: admins.domain_admin_delete(ctx, {"username": items}),
    "app-passwd": lambda ctx, items, attr: admins.app_passwd_delete(ctx, {"id": items}),
    "dkim": lambda ctx, items, attr: dkim_delete(ctx, {"domains": items}),
    "relayhost": lambda ctx, items, attr: misc.relayhost_delete(ctx, {"id": items}),
    "transport": lambda ctx, items, attr: misc.transport_delete(ctx, {"id": items}),
    "bcc": lambda ctx, items, attr: misc.bcc_delete(ctx, {"id": items}),
    "recipient_map": lambda ctx, items, attr: misc.recipient_map_delete(ctx, {"id": items}),
    "tls-policy-map": lambda ctx, items, attr: misc.tls_policy_map_delete(ctx, {"id": items}),
    "rsetting": lambda ctx, items, attr: misc.rsetting_delete(ctx, {"id": items}),
    "fwdhost": lambda ctx, items, attr: misc.fwdhost_delete(ctx, {"forwardinghost": items}),
    "qitem": lambda ctx, items, attr: misc.quarantine_delete(ctx, {"id": items}),
    "qitem-release": lambda ctx, items, attr: misc.quarantine_release(ctx, ids=items),
    "rlhash": lambda ctx, items, attr: all(ratelimit_delete_hash(ctx, h) for h in items),
    "tfa": lambda ctx, items, attr: all(tfa_svc.unset_tfa_key(ctx, {"unset_tfa_key": i}) for i in items),
}


@router.post("/add/{category}")
async def api_add(category: str, request: Request, ctx: Context = Depends(get_ctx)) -> Any:
    body = await _body(request)
    _write_guard(ctx, request, body)
    handler = ADD_HANDLERS.get(category)
    if handler is None:
        raise HTTPException(status_code=404, detail={"type": "error", "msg": f"unknown category {category}"})
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail={"type": "error", "msg": "object expected"})
    body.pop("csrf_token", None)
    result = handler(ctx, body)
    out: list[Any] = _messages(ctx)
    if isinstance(result, dict):
        out.append({"type": "success", "log": ["api", "add", category], "msg": result})
    return _finish(ctx, out)


@router.post("/edit/{category}")
async def api_edit(category: str, request: Request, ctx: Context = Depends(get_ctx)) -> Any:
    body = await _body(request)
    _write_guard(ctx, request, body)
    handler = EDIT_HANDLERS.get(category)
    if handler is None:
        raise HTTPException(status_code=404, detail={"type": "error", "msg": f"unknown category {category}"})
    if isinstance(body, dict):
        body.pop("csrf_token", None)
    items, attr = _edit_payload(body)
    handler(ctx, items, attr)
    return _finish(ctx, _messages(ctx))


@router.post("/delete/{category}")
async def api_delete(category: str, request: Request, ctx: Context = Depends(get_ctx)) -> Any:
    body = await _body(request)
    _write_guard(ctx, request, body)
    handler = DELETE_HANDLERS.get(category)
    if handler is None:
        raise HTTPException(status_code=404, detail={"type": "error", "msg": f"unknown category {category}"})
    if isinstance(body, dict):
        body.pop("csrf_token", None)
        items = as_list(body.get("items") if "items" in body else body.get("id") or body.get("username") or body.get("domain") or body.get("alias_domain"))
        attr = body
    else:
        items, attr = as_list(body), {}
    handler(ctx, items, attr)
    return _finish(ctx, _messages(ctx))


def _finish(ctx: Context, out: list[Any]) -> JSONResponse:
    headers = {}
    if not ctx.is_api:
        headers["X-CSRF-Token"] = ctx.session.csrf_token
    return respond(out or [{"type": "success", "log": [], "msg": "ok"}], headers=headers)


# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------
@router.post("/status/container/{name}/{action}")
async def container_action(name: str, action: str, request: Request, ctx: Context = Depends(get_ctx)) -> Any:
    body = await _body(request)
    _write_guard(ctx, request, body)
    if ctx.role != "admin" or action not in ("restart", "stop", "start"):
        raise HTTPException(status_code=403)
    resp = docker(ctx, "post", name, action)
    try:
        return respond(json.loads(resp))
    except Exception:  # noqa: BLE001
        return respond({"type": "info", "msg": str(resp)})
