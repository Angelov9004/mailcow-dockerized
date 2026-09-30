"""Two-factor authentication: TOTP, WebAuthn and Yubico OTP.

Port of set_tfa(), get_tfa(), verify_tfa_login(), unset_tfa_key() from functions.inc.php.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
from typing import Any

import httpx
import pyotp

from ..config import settings
from .context import Context
from .passwords import verify_hash

log = logging.getLogger("mailcow.tfa")

try:
    import webauthn
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        UserVerificationRequirement,
    )

    HAVE_WEBAUTHN = True
except Exception:  # noqa: BLE001
    HAVE_WEBAUTHN = False


def _uv(flag: str) -> "UserVerificationRequirement":
    return {
        "required": UserVerificationRequirement.REQUIRED,
        "discouraged": UserVerificationRequirement.DISCOURAGED,
    }.get(flag, UserVerificationRequirement.PREFERRED)


# ---------------------------------------------------------------------------
# read
# ---------------------------------------------------------------------------
def get_tfa(ctx: Context, username: str | None = None, id_: int | None = None) -> dict[str, Any] | None:
    if not username:
        username = ctx.username
    if not username:
        return None
    if id_ is None:
        rows = ctx.db.all("SELECT id, key_id, authmech FROM tfa WHERE username = %s AND active = 1", (username,))
        if not rows:
            return {"name": "none", "pretty": "-", "additional": []}
        return {"additional": rows}
    row = ctx.db.one("SELECT * FROM tfa WHERE username = %s AND id = %s AND active = 1", (username, id_))
    if not row or not row.get("authmech"):
        return {"name": "none", "pretty": "-"}
    mech = row["authmech"]
    if mech == "yubi_otp":
        rows = ctx.db.all(
            "SELECT id, key_id, RIGHT(secret, 12) AS modhex FROM tfa WHERE authmech = 'yubi_otp' AND username = %s AND id = %s",
            (username, id_),
        )
        return {"name": "yubi_otp", "pretty": "Yubico OTP", "additional": rows}
    if mech == "u2f":
        rows = ctx.db.all("SELECT id, key_id FROM tfa WHERE authmech = 'u2f' AND username = %s AND id = %s", (username, id_))
        return {"name": "u2f", "pretty": "Fido U2F", "additional": rows}
    if mech == "hotp":
        return {"name": "hotp", "pretty": "HMAC-based OTP"}
    if mech == "totp":
        rows = ctx.db.all("SELECT id, key_id, secret FROM tfa WHERE authmech = 'totp' AND username = %s AND id = %s", (username, id_))
        return {"name": "totp", "pretty": "Time-based OTP", "additional": rows}
    if mech == "webauthn":
        rows = ctx.db.all("SELECT id, key_id FROM tfa WHERE authmech = 'webauthn' AND username = %s AND id = %s", (username, id_))
        return {"name": "webauthn", "pretty": "WebAuthn", "additional": rows}
    return {"name": "none", "pretty": "-"}


def has_active_tfa(ctx: Context, username: str) -> bool:
    data = get_tfa(ctx, username)
    return bool(data and data.get("additional"))


# ---------------------------------------------------------------------------
# Yubico OTP (validation protocol 2.0)
# ---------------------------------------------------------------------------
YUBICO_API = "https://api.yubico.com/wsapi/2.0/verify"


def yubico_verify(client_id: str, secret_key_b64: str, otp: str, timeout: float = 10.0) -> tuple[bool, str]:
    """Verify a Yubico OTP against YubiCloud, checking the response HMAC. Returns (ok, message)."""
    try:
        key = base64.b64decode(secret_key_b64)
    except Exception:  # noqa: BLE001
        return False, "invalid api key"
    nonce = secrets.token_hex(16)
    params = {"id": client_id, "otp": otp, "nonce": nonce, "timestamp": "1", "sl": "secure"}
    query = "&".join(f"{k}={params[k]}" for k in sorted(params))
    sig = base64.b64encode(hmac.new(key, query.encode(), hashlib.sha1).digest()).decode()
    try:
        resp = httpx.get(YUBICO_API, params={**params, "h": sig}, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return False, f"yubico request failed: {exc}"
    fields: dict[str, str] = {}
    for line in resp.text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            fields[k.strip()] = v.strip()
    resp_sig = fields.pop("h", None)
    check = "&".join(f"{k}={fields[k]}" for k in sorted(fields))
    calc = base64.b64encode(hmac.new(key, check.encode(), hashlib.sha1).digest()).decode()
    if not resp_sig or not hmac.compare_digest(resp_sig, calc):
        return False, "bad response signature"
    if fields.get("otp") != otp or fields.get("nonce") != nonce:
        return False, "otp/nonce mismatch"
    if fields.get("status") != "OK":
        return False, fields.get("status", "unknown")
    return True, "OK"


# ---------------------------------------------------------------------------
# WebAuthn helpers
# ---------------------------------------------------------------------------
def _rp_id(ctx: Context) -> str:
    host = ""
    if ctx.request is not None:
        host = ctx.request.headers.get("host", "")
    host = host.split(":")[0]
    return host or settings.mailcow_hostname


def _origin(ctx: Context) -> str:
    host = ctx.request.headers.get("host", settings.mailcow_hostname) if ctx.request is not None else settings.mailcow_hostname
    scheme = "https" if ctx.is_https else "http"
    return f"{scheme}://{host}"


def webauthn_registration_options(ctx: Context) -> dict[str, Any] | None:
    if not HAVE_WEBAUTHN or not ctx.username:
        return None
    existing = ctx.db.all("SELECT keyhandle FROM tfa WHERE username = %s AND authmech = 'webauthn' AND active = 1", (ctx.username,))
    exclude = []
    for row in existing:
        try:
            exclude.append(PublicKeyCredentialDescriptor(id=base64.b64decode(row["keyhandle"])))
        except Exception:  # noqa: BLE001
            pass
    options = webauthn.generate_registration_options(
        rp_id=_rp_id(ctx),
        rp_name="mailcow",
        user_id=hashlib.sha256(ctx.username.encode()).digest(),
        user_name=ctx.username,
        user_display_name=ctx.username,
        exclude_credentials=exclude,
        authenticator_selection=AuthenticatorSelectionCriteria(user_verification=_uv(settings.webauthn_uv_flag_register)),
        timeout=60000,
    )
    ctx.session["challenge"] = bytes_to_base64url(options.challenge)
    return json.loads(webauthn.options_to_json(options))


def webauthn_authentication_options(ctx: Context) -> dict[str, Any] | None:
    if not HAVE_WEBAUTHN:
        return None
    pending = ctx.session.get("pending_mailcow_cc_username")
    if not pending:
        return None
    rows = ctx.db.all("SELECT keyhandle FROM tfa WHERE username = %s AND authmech = 'webauthn' AND active = 1", (pending,))
    allow = []
    for row in rows:
        try:
            allow.append(PublicKeyCredentialDescriptor(id=base64.b64decode(row["keyhandle"])))
        except Exception:  # noqa: BLE001
            pass
    options = webauthn.generate_authentication_options(
        rp_id=_rp_id(ctx),
        allow_credentials=allow,
        user_verification=_uv(settings.webauthn_uv_flag_login),
        timeout=60000,
    )
    ctx.session["challenge"] = bytes_to_base64url(options.challenge)
    return json.loads(webauthn.options_to_json(options))


# ---------------------------------------------------------------------------
# set / unset
# ---------------------------------------------------------------------------
def set_tfa(ctx: Context, data: dict[str, Any]) -> bool:
    log_data = dict(data)
    if "confirm_password" in log_data:
        log_data["confirm_password"] = "*"
    username = ctx.username
    if not ctx.role or not username:
        ctx.denied(["set_tfa", log_data])
        return False

    # confirm password (admin or mailbox); LDAP/keycloak sources are not supported in this port
    access_denied: bool | None = None
    row = ctx.db.one("SELECT password FROM admin WHERE username = %s", (username,))
    if row:
        access_denied = not verify_hash(row["password"], data.get("confirm_password") or "")
    if access_denied is None:
        row = ctx.db.one("SELECT password, authsource FROM mailbox WHERE username = %s", (username,))
        if row:
            if row.get("authsource") not in (None, "mailcow"):
                access_denied = True
            else:
                access_denied = not verify_hash(row["password"], data.get("confirm_password") or "")
    if access_denied is None or access_denied:
        ctx.denied(["set_tfa", log_data])
        return False

    method = data.get("tfa_method")
    key_id = data.get("key_id") or "unidentified"
    if method == "yubi_otp":
        yubico_id = str(data.get("yubico_id") or "")
        yubico_key = str(data.get("yubico_key") or "")
        token = str(data.get("otp_token") or "")
        if not token.isalnum() or len(token) != 44:
            ctx.err(["set_tfa", log_data], "tfa_token_invalid")
            return False
        ok, msg = yubico_verify(yubico_id, yubico_key, token)
        if not ok:
            ctx.err(["set_tfa", log_data], ["yotp_verification_failed", msg])
            return False
        modhex = token[:12]
        ctx.db.exec("DELETE FROM tfa WHERE username = %s AND authmech = 'yubi_otp' AND secret LIKE %s", (username, "%" + modhex))
        ctx.db.exec(
            "INSERT INTO tfa (key_id, username, authmech, active, secret) VALUES (%s, %s, 'yubi_otp', 1, %s)",
            (key_id, username, f"{yubico_id}:{yubico_key}:{modhex}"),
        )
        ctx.ok(["set_tfa", log_data], ["object_modified", username])
        return True
    if method == "totp":
        secret = str(data.get("totp_secret") or "")
        code = str(data.get("totp_confirm_token") or "")
        try:
            valid = pyotp.TOTP(secret).verify(code, valid_window=1)
        except Exception:  # noqa: BLE001
            valid = False
        if not valid:
            ctx.err(["set_tfa", log_data], "totp_verification_failed")
            return False
        ctx.db.exec(
            "INSERT INTO tfa (username, key_id, authmech, secret, active) VALUES (%s, %s, 'totp', %s, 1)",
            (username, key_id, secret),
        )
        ctx.ok(["set_tfa", log_data], ["object_modified", username])
        return True
    if method == "webauthn":
        if not HAVE_WEBAUTHN:
            ctx.err(["set_tfa", log_data], "webauthn_not_available")
            return False
        challenge = ctx.session.get("challenge")
        credential = data.get("registration")
        if not challenge or not credential:
            ctx.err(["set_tfa", log_data], "webauthn_verification_failed")
            return False
        try:
            if isinstance(credential, str):
                credential = json.loads(credential)
            verification = webauthn.verify_registration_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(challenge),
                expected_rp_id=_rp_id(ctx),
                expected_origin=_origin(ctx),
                require_user_verification=settings.webauthn_uv_flag_register == "required",
            )
        except Exception as exc:  # noqa: BLE001
            ctx.err(["set_tfa", log_data], ["webauthn_verification_failed", str(exc)])
            return False
        finally:
            ctx.session.pop("challenge", None)
        ctx.db.exec(
            "INSERT INTO tfa (username, key_id, authmech, keyhandle, publickey, certificate, counter, active) "
            "VALUES (%s, %s, 'webauthn', %s, %s, %s, %s, 1)",
            (
                username,
                key_id,
                base64.b64encode(verification.credential_id).decode(),
                base64.b64encode(verification.credential_public_key).decode(),
                None,
                verification.sign_count,
            ),
        )
        ctx.ok(["set_tfa", log_data], ["object_modified", username])
        return True
    if method == "none":
        ctx.db.exec("DELETE FROM tfa WHERE username = %s", (username,))
        ctx.ok(["set_tfa", log_data], ["object_modified", username])
        return True
    ctx.err(["set_tfa", log_data], "unknown_tfa_method")
    return False


def unset_tfa_key(ctx: Context, data: dict[str, Any]) -> bool:
    username = ctx.username
    if not ctx.role or not username:
        ctx.denied(["unset_tfa_key", data])
        return False
    try:
        id_ = int(data.get("unset_tfa_key"))
    except (TypeError, ValueError):
        ctx.denied(["unset_tfa_key", data])
        return False
    n = ctx.db.scalar("SELECT COUNT(*) FROM tfa WHERE username = %s AND active = 1", (username,))
    if int(n or 0) == 1:
        ctx.err(["unset_tfa_key", data], "last_key")
        return False
    ctx.db.exec("DELETE FROM tfa WHERE username = %s AND id = %s", (username, id_))
    ctx.ok(["unset_tfa_key", data], ["object_modified", username])
    return True


# ---------------------------------------------------------------------------
# login verification
# ---------------------------------------------------------------------------
def verify_tfa_login(ctx: Context, username: str, data: dict[str, Any]) -> bool:
    method = data.get("tfa_method")
    token = data.get("token")
    if method == "yubi_otp":
        token = str(token or "")
        if not token.isalnum() or len(token) != 44:
            ctx.err(["verify_tfa_login", username, "*"], ["yotp_verification_failed", "token length error"])
            return False
        modhex = token[:12]
        row = ctx.db.one(
            "SELECT id, secret FROM tfa WHERE username = %s AND authmech = 'yubi_otp' AND active = 1 AND secret LIKE %s",
            (username, "%" + modhex),
        )
        if not row:
            ctx.err(["verify_tfa_login", username, "*"], ["yotp_verification_failed", "unknown key"])
            return False
        parts = row["secret"].split(":")
        ok, msg = yubico_verify(parts[0], parts[1], token)
        if not ok:
            ctx.err(["verify_tfa_login", username, "*"], ["yotp_verification_failed", msg])
            return False
        ctx.session["tfa_id"] = row["id"]
        ctx.ok(["verify_tfa_login", username, "*"], "verified_yotp_login")
        return True
    if method == "hotp":
        return False
    if method == "totp":
        rows = ctx.db.all(
            "SELECT id, secret FROM tfa WHERE username = %s AND authmech = 'totp' AND id = %s AND active = 1",
            (username, data.get("id")),
        )
        for row in rows:
            try:
                if pyotp.TOTP(row["secret"]).verify(str(token or ""), valid_window=1):
                    ctx.session["tfa_id"] = row["id"]
                    ctx.ok(["verify_tfa_login", username, "*"], "verified_totp_login")
                    return True
            except Exception:  # noqa: BLE001
                continue
        ctx.err(["verify_tfa_login", username, "*"], "totp_verification_failed")
        return False
    if method == "webauthn":
        if not HAVE_WEBAUTHN:
            ctx.err(["verify_tfa_login", username, "*"], ["webauthn_verification_failed", "library missing"])
            return False
        row = ctx.db.one("SELECT id, key_id, keyhandle, username, publickey, counter FROM tfa WHERE id = %s AND active = 1", (data.get("id"),))
        if not row:
            ctx.err(["verify_tfa_login", username, "*"], ["webauthn_authenticator_failed"])
            return False
        if not row.get("publickey"):
            ctx.err(["verify_tfa_login", username, "*"], ["webauthn_publickey_failed"])
            return False
        if row["username"] != ctx.session.get("pending_mailcow_cc_username"):
            ctx.err(["verify_tfa_login", username, "*"], ["webauthn_username_failed"])
            return False
        challenge = ctx.session.get("challenge")
        try:
            credential = token if isinstance(token, dict) else json.loads(token or "{}")
            verification = webauthn.verify_authentication_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(challenge or ""),
                expected_rp_id=_rp_id(ctx),
                expected_origin=_origin(ctx),
                credential_public_key=base64.b64decode(row["publickey"]),
                credential_current_sign_count=int(row.get("counter") or 0),
                require_user_verification=settings.webauthn_uv_flag_login == "required",
            )
        except Exception as exc:  # noqa: BLE001
            ctx.err(["verify_tfa_login", username, "*"], ["webauthn_verification_failed", str(exc)])
            return False
        finally:
            ctx.session.pop("challenge", None)
        ctx.db.exec("UPDATE tfa SET counter = %s WHERE id = %s", (verification.new_sign_count, row["id"]))
        # role resolution as in PHP
        admin = ctx.db.one("SELECT superadmin FROM admin WHERE username = %s", (row["username"],))
        if admin and int(admin["superadmin"]) == 1:
            ctx.session["mailcow_cc_role"] = "admin"
        elif admin and int(admin["superadmin"]) == 0:
            ctx.session["mailcow_cc_role"] = "domainadmin"
        else:
            mb = ctx.db.one("SELECT username FROM mailbox WHERE username = %s", (row["username"],))
            if mb:
                ctx.session["mailcow_cc_role"] = "user"
            else:
                ctx.err(["verify_tfa_login", username, "*"], ["webauthn_role_failed"])
                return False
        ctx.session["mailcow_cc_username"] = row["username"]
        ctx.session["tfa_id"] = row["id"]
        ctx.ok(["webauthn_login"], ["logged_in_as", row["username"]])
        return True
    if method == "u2f":
        # deprecated; remove leftovers and fail
        ctx.db.exec("DELETE FROM tfa WHERE authmech = 'u2f' AND username = %s", (username,))
        return False
    ctx.err(["verify_tfa_login", username, "*"], "unknown_tfa_method")
    return False


def totp_new_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=settings.otp_label)
