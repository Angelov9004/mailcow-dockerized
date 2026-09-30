"""Session endpoints for the web UI (login, TFA, logout, session info) and the mail client autoconfiguration."""
from __future__ import annotations

import logging
import os
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from ..config import settings
from ..security.acl import acl_to_session
from ..security.auth import check_login, set_user_loggedin_session
from ..security.context import Context, check_csrf
from ..security.tfa import verify_tfa_login
from ..services.admins import domain_admin_sso_check
from ..validators import is_email
from .api_v1 import _body, _messages, respond
from .deps import get_ctx

log = logging.getLogger("mailcow.ui")
router = APIRouter()

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")


def _session_info(ctx: Context) -> dict[str, Any]:
    return {
        "username": ctx.username,
        "role": ctx.role,
        "is_api": ctx.is_api,
        "csrf_token": None if ctx.is_api else ctx.session.csrf_token,
        "acl": ctx.acl,
        "dual_login": ctx.session.get("dual-login"),
        "pending_tfa": bool(ctx.session.get("pending_mailcow_cc_username")),
        "pending_tfa_methods": ctx.session.get("pending_tfa_methods"),
        "hostname": settings.mailcow_hostname,
        "skip_sogo": settings.skip_sogo,
        "allow_admin_email_login": settings.allow_admin_email_login,
        "demo_mode": settings.demo_mode,
    }


@router.get("/api/v1/session")
def session_info(ctx: Context = Depends(get_ctx)) -> Any:
    return respond(_session_info(ctx))


@router.post("/api/v1/login")
async def login(request: Request, ctx: Context = Depends(get_ctx)) -> Any:
    body = await _body(request)
    if not isinstance(body, dict):
        raise HTTPException(status_code=400)
    if ctx.role:
        return respond({"result": ctx.role, **_session_info(ctx)})
    username = str(body.get("username") or body.get("login_user") or "").strip()
    password = str(body.get("password") or body.get("pass_user") or "")
    if not username or not password:
        raise HTTPException(status_code=400, detail={"type": "error", "msg": "login_failed"})
    result = check_login(ctx, username, password)
    if result in ("admin", "domainadmin", "user"):
        if result == "user":
            username = username.lower()
        set_user_loggedin_session(ctx, username.strip().lower() if result != "user" else username, result)
        acl_to_session(ctx)
        return respond({"result": result, "messages": _messages(ctx), **_session_info(ctx)})
    if result == "pending":
        return respond({"result": "pending", "messages": _messages(ctx), **_session_info(ctx)})
    return respond({"result": False, "messages": _messages(ctx), **_session_info(ctx)}, status=401)


@router.post("/api/v1/login/tfa")
async def login_tfa(request: Request, ctx: Context = Depends(get_ctx)) -> Any:
    body = await _body(request)
    if not isinstance(body, dict):
        raise HTTPException(status_code=400)
    pending_user = ctx.session.get("pending_mailcow_cc_username")
    pending_role = ctx.session.get("pending_mailcow_cc_role")
    if not pending_user or not pending_role:
        raise HTTPException(status_code=401, detail={"type": "error", "msg": "no pending login"})
    if verify_tfa_login(ctx, pending_user, body):
        # webauthn sets username/role itself; keep whichever was resolved
        role = ctx.session.get("mailcow_cc_role") or pending_role
        user = ctx.session.get("mailcow_cc_username") or pending_user
        set_user_loggedin_session(ctx, user, role)
        acl_to_session(ctx)
        # Reactivate TFA if it was set to "deactivate TFA for next login"
        ctx.db.exec("UPDATE tfa SET active = 1 WHERE username = %s", (user,))
        return respond({"result": role, "messages": _messages(ctx), **_session_info(ctx)})
    return respond({"result": False, "messages": _messages(ctx), **_session_info(ctx)}, status=401)


@router.post("/api/v1/login/sso")
async def login_sso(request: Request, ctx: Context = Depends(get_ctx)) -> Any:
    """Domain admin single sign-on token issued by an admin (domain_admin_sso)."""
    body = await _body(request)
    token = (body or {}).get("token") if isinstance(body, dict) else None
    username = domain_admin_sso_check(ctx, str(token or ""))
    if not username:
        raise HTTPException(status_code=401, detail={"type": "error", "msg": "login_failed"})
    set_user_loggedin_session(ctx, username, "domainadmin")
    acl_to_session(ctx)
    ctx.ok(["domain_admin_sso", username, "*"], ["logged_in_as", username])
    return respond({"result": "domainadmin", **_session_info(ctx)})


@router.post("/api/v1/logout")
async def logout(request: Request, ctx: Context = Depends(get_ctx)) -> Any:
    body = await _body(request)
    token = request.headers.get("x-csrf-token") or (body.get("csrf_token") if isinstance(body, dict) else None)
    if ctx.role and not check_csrf(ctx, token):
        raise HTTPException(status_code=403, detail={"type": "error", "msg": "session_token"})
    dual = ctx.session.get("dual-login")
    if dual:
        # leave the "login as user" mode, back to the admin identity
        ctx.session["mailcow_cc_username"] = dual["username"]
        ctx.session["mailcow_cc_role"] = dual["role"]
        for k in ("sogo-sso-user-allowed", "sogo-sso-pass", "dual-login"):
            ctx.session.pop(k, None)
        acl_to_session(ctx)
        return respond({"result": "dual-logout", **_session_info(ctx)})
    ctx.session.destroy()
    return respond({"result": "logged-out"})


@router.post("/api/v1/login-as")
async def login_as(request: Request, ctx: Context = Depends(get_ctx)) -> Any:
    """Admin/domain admin impersonates a mailbox user in the UI (dual login)."""
    body = await _body(request)
    token = request.headers.get("x-csrf-token") or (body.get("csrf_token") if isinstance(body, dict) else None)
    if not ctx.role or not check_csrf(ctx, token):
        raise HTTPException(status_code=403)
    login = str((body or {}).get("username") or "")
    from ..security.acl import own_mailbox_access

    if ctx.role not in ("admin", "domainadmin") or str(ctx.acl.get("login_as")) != "1" or not is_email(login) or not own_mailbox_access(ctx, login):
        ctx.denied(["login_as", login])
        return respond({"result": False, "messages": _messages(ctx)}, status=403)
    if ctx.session.get("dual-login"):
        return respond({"result": False, "msg": "already in dual login"}, status=400)
    ctx.session["dual-login"] = {"username": ctx.username, "role": ctx.role}
    ctx.session["mailcow_cc_username"] = login
    ctx.session["mailcow_cc_role"] = "user"
    acl_to_session(ctx)
    ctx.ok(["login_as", login], ["logged_in_as", login])
    return respond({"result": "user", "messages": _messages(ctx), **_session_info(ctx)})


# ---------------------------------------------------------------------------
# autoconfig / autodiscover
# ---------------------------------------------------------------------------
def _autodiscover_config() -> dict[str, Any]:
    h = settings.mailcow_hostname
    port = settings.https_port
    return {
        "autodiscoverType": "imap" if settings.skip_sogo else "activesync",
        "useEASforOutlook": "no",
        "imap": {"server": h, "port": settings.imaps_port, "tlsport": settings.imap_port},
        "pop3": {"server": h, "port": settings.pops_port, "tlsport": settings.pop_port},
        "smtp": {"server": h, "port": settings.smtps_port, "tlsport": settings.submission_port},
        "activesync": {"url": f"https://{h}{'' if port == 443 else ':' + str(port)}/Microsoft-Server-ActiveSync"},
        "caldav": {"server": h, "port": port},
        "carddav": {"server": h, "port": port},
    }


@router.get("/autoconfig.xml")
@router.get("/mail/config-v1.1.xml")
@router.get("/Mail/Config-v1.1.xml")
@router.get("/.well-known/autoconfig/mail/config-v1.1.xml")
def autoconfig() -> Response:
    c = _autodiscover_config()
    xml = f"""<?xml version="1.0"?>
<clientConfig version="1.1">
    <emailProvider id="{settings.mailcow_hostname}">
      <domain>%EMAILDOMAIN%</domain>
      <displayName>A mailcow mail server</displayName>
      <displayShortName>mail server</displayShortName>
      <incomingServer type="imap">
         <hostname>{c['imap']['server']}</hostname>
         <port>{c['imap']['port']}</port>
         <socketType>SSL</socketType>
         <username>%EMAILADDRESS%</username>
         <authentication>password-cleartext</authentication>
      </incomingServer>
      <incomingServer type="imap">
         <hostname>{c['imap']['server']}</hostname>
         <port>{c['imap']['tlsport']}</port>
         <socketType>STARTTLS</socketType>
         <username>%EMAILADDRESS%</username>
         <authentication>password-cleartext</authentication>
      </incomingServer>
      <incomingServer type="pop3">
         <hostname>{c['pop3']['server']}</hostname>
         <port>{c['pop3']['port']}</port>
         <socketType>SSL</socketType>
         <username>%EMAILADDRESS%</username>
         <authentication>password-cleartext</authentication>
      </incomingServer>
      <incomingServer type="pop3">
         <hostname>{c['pop3']['server']}</hostname>
         <port>{c['pop3']['tlsport']}</port>
         <socketType>STARTTLS</socketType>
         <username>%EMAILADDRESS%</username>
         <authentication>password-cleartext</authentication>
      </incomingServer>
      <outgoingServer type="smtp">
         <hostname>{c['smtp']['server']}</hostname>
         <port>{c['smtp']['port']}</port>
         <socketType>SSL</socketType>
         <username>%EMAILADDRESS%</username>
         <authentication>password-cleartext</authentication>
      </outgoingServer>
      <outgoingServer type="smtp">
         <hostname>{c['smtp']['server']}</hostname>
         <port>{c['smtp']['tlsport']}</port>
         <socketType>STARTTLS</socketType>
         <username>%EMAILADDRESS%</username>
         <authentication>password-cleartext</authentication>
      </outgoingServer>
      <enable visiturl="https://{settings.mailcow_hostname}/admin">
         <instruction>Enable or disable protocols in the mailcow UI.</instruction>
      </enable>
    </emailProvider>
</clientConfig>
"""
    return Response(content=xml, media_type="application/xml")


@router.post("/autodiscover/autodiscover.xml")
@router.post("/Autodiscover/Autodiscover.xml")
async def autodiscover(request: Request, ctx: Context = Depends(get_ctx)) -> Response:
    """Outlook / EAS autodiscover. Requires HTTP basic auth like the PHP version."""
    import base64

    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("basic "):
        return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="mailcow"'})
    try:
        username, password = base64.b64decode(auth[6:]).decode("utf-8", errors="replace").split(":", 1)
    except Exception:  # noqa: BLE001
        return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="mailcow"'})
    login = check_login(ctx, username, password, {"eas": True, "dav": False})
    if login != "user":
        return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="mailcow"'})
    body = (await request.body()).decode("utf-8", errors="replace")
    m = re.search(r"<EMailAddress>(.*?)</EMailAddress>", body)
    email_addr = m.group(1) if m else username
    ua = request.headers.get("user-agent", "")
    c = _autodiscover_config()
    use_eas = c["autodiscoverType"] == "activesync" and ("outlook" not in ua.lower() or c["useEASforOutlook"] == "yes") and "emclient" not in ua.lower()
    if use_eas:
        xml = f"""<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006">
    <Culture>en:us</Culture>
    <User>
      <DisplayName>{email_addr}</DisplayName>
      <EMailAddress>{email_addr}</EMailAddress>
    </User>
    <Action>
      <Settings>
        <Server>
          <Type>MobileSync</Type>
          <Url>{c['activesync']['url']}</Url>
          <Name>{c['activesync']['url']}</Name>
        </Server>
      </Settings>
    </Action>
  </Response>
</Autodiscover>
"""
    else:
        xml = f"""<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <User>
      <DisplayName>{email_addr}</DisplayName>
    </User>
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type>
        <Server>{c['imap']['server']}</Server>
        <Port>{c['imap']['port']}</Port>
        <DomainRequired>off</DomainRequired>
        <LoginName>{email_addr}</LoginName>
        <SPA>off</SPA>
        <SSL>on</SSL>
        <AuthRequired>on</AuthRequired>
      </Protocol>
      <Protocol>
        <Type>SMTP</Type>
        <Server>{c['smtp']['server']}</Server>
        <Port>{c['smtp']['port']}</Port>
        <DomainRequired>off</DomainRequired>
        <LoginName>{email_addr}</LoginName>
        <SPA>off</SPA>
        <SSL>on</SSL>
        <AuthRequired>on</AuthRequired>
      </Protocol>
      <Protocol>
        <Type>CalDAV</Type>
        <Server>https://{c['caldav']['server']}:{c['caldav']['port']}/SOGo/dav/{email_addr}/Calendar</Server>
        <LoginName>{email_addr}</LoginName>
      </Protocol>
      <Protocol>
        <Type>CardDAV</Type>
        <Server>https://{c['carddav']['server']}:{c['carddav']['port']}/SOGo/dav/{email_addr}/Contacts</Server>
        <LoginName>{email_addr}</LoginName>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>
"""
    return Response(content=xml, media_type="application/xml")


@router.get("/autodiscover/autodiscover.json")
@router.get("/Autodiscover/Autodiscover.json")
def autodiscover_json(request: Request) -> Any:
    protocol = request.query_params.get("Protocol", "")
    if protocol.lower() == "activesync":
        return JSONResponse({"Protocol": "ActiveSync", "Url": _autodiscover_config()["activesync"]["url"]})
    if protocol.lower() == "autodiscoverv1":
        return JSONResponse({"Protocol": "AutodiscoverV1", "Url": f"https://{settings.mailcow_hostname}/Autodiscover/Autodiscover.xml"})
    return JSONResponse({"ErrorCode": "InvalidProtocol", "ErrorMessage": "The given protocol value is invalid."}, status_code=400)


# ---------------------------------------------------------------------------
# quarantine notification links (/qhandler/<action>/<hash>) - no login required, hash is the secret
# ---------------------------------------------------------------------------
@router.get("/qhandler/{action}/{qhash}")
def qhandler_get(action: str, qhash: str, ctx: Context = Depends(get_ctx)) -> Any:
    from ..services import misc as _misc

    item = _misc.quarantine_hash_details(ctx, qhash)
    if action not in ("show", "release", "delete") or not item:
        raise HTTPException(status_code=404)
    return respond({"action": action, "hash": qhash, "item": item, "csrf_token": ctx.session.csrf_token})


@router.post("/qhandler/{action}/{qhash}")
async def qhandler_post(action: str, qhash: str, request: Request, ctx: Context = Depends(get_ctx)) -> Any:
    from ..services import misc as _misc

    body = await _body(request)
    token = request.headers.get("x-csrf-token") or (body.get("csrf_token") if isinstance(body, dict) else None)
    if not check_csrf(ctx, token):
        raise HTTPException(status_code=403, detail={"type": "error", "msg": "session_token"})
    if action == "release":
        ok = _misc.quarantine_release(ctx, qhash=qhash)
    elif action == "delete":
        ok = _misc.quarantine_delete_by_hash(ctx, qhash)
    else:
        raise HTTPException(status_code=404)
    return respond({"result": ok, "messages": _messages(ctx)}, status=200 if ok else 403, headers={"X-CSRF-Token": ctx.session.csrf_token})


# ---------------------------------------------------------------------------
# static UI
# ---------------------------------------------------------------------------
@router.get("/", include_in_schema=False)
@router.get("/admin", include_in_schema=False)
@router.get("/domainadmin", include_in_schema=False)
@router.get("/user", include_in_schema=False)
@router.get("/mailbox", include_in_schema=False)
@router.get("/admin/{rest:path}", include_in_schema=False)
@router.get("/domainadmin/{rest:path}", include_in_schema=False)
@router.get("/user/{rest:path}", include_in_schema=False)
def spa(rest: str = "") -> Response:
    index = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(index):
        return PlainTextResponse("mailcow API is running; UI assets missing", status_code=200)
    return FileResponse(index, headers={"Cache-Control": "no-store"})


@router.get("/robots.txt", include_in_schema=False)
def robots() -> Response:
    return PlainTextResponse("User-agent: *\nDisallow: /\n")


@router.get("/healthz", include_in_schema=False)
def healthz(ctx: Context = Depends(get_ctx)) -> Any:
    ctx.db.one("SELECT 1")
    ctx.redis.ping()
    return respond({"status": "ok"})
