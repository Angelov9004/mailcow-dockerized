"""Integration tests against a real PostgreSQL + Redis (see conftest)."""
from __future__ import annotations

import json

import pyotp
import pytest

DOMAIN = {"domain": "example.org", "description": "test", "aliases": 400, "mailboxes": 10, "defquota": 3072, "maxquota": 10240, "quota": 10240, "active": 1}


def _ok(resp):
    assert resp.status_code == 200, resp.text
    msgs = resp.json()
    assert all(m["type"] in ("success", "info", "warning") for m in msgs), msgs
    return msgs


# ---------------------------------------------------------------------------
# session / login security
# ---------------------------------------------------------------------------
def test_session_cookie_flags(client):
    r = client.get("/api/v1/session")
    cookie = r.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie.lower().replace("samesite=lax", "SameSite=lax")
    assert r.json()["role"] is None


def test_login_wrong_password_publishes_to_netfilter(client, app):
    from mailcow.redisclient import get_redis

    ps = get_redis().pubsub()
    ps.subscribe("F2B_CHANNEL")
    r = client.post("/api/v1/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401 and r.json()["result"] is False
    msgs = [m for m in (ps.get_message(timeout=1) for _ in range(5)) if m and m["type"] == "message"]
    assert any("Invalid password for admin by 127.0.0.1" in m["data"] for m in msgs)


def test_login_regenerates_session_id_and_csrf(client):
    before = client.get("/api/v1/session").json()["csrf_token"]
    sid_before = client.cookies.get("MAILCOWSESS")
    r = client.post("/api/v1/login", json={"username": "admin", "password": "moohoo"})
    assert r.json()["result"] == "admin"
    assert client.cookies.get("MAILCOWSESS") != sid_before
    assert r.json()["csrf_token"] != before


def test_write_without_csrf_is_rejected(admin):
    client, _ = admin
    r = client.post("/api/v1/add/domain", json=DOMAIN)
    assert r.status_code == 403


def test_csrf_token_rotates(api):
    first = api.csrf
    api.post("/api/v1/edit/passwordpolicy", {"attr": {"length": 6}})
    assert api.csrf != first
    # the old token must not work any more
    r = api.c.post("/api/v1/edit/passwordpolicy", json={"attr": {"length": 6}}, headers={"X-CSRF-Token": first})
    assert r.status_code == 403


def test_user_agent_binding(admin):
    client, csrf = admin
    r = client.get("/api/v1/session", headers={"User-Agent": "something else"})
    assert r.json()["role"] is None


def test_api_key_auth_and_ip_acl(api, app):
    _ok(api.post("/api/v1/edit/api", {"attr": {"access": "rw", "active": 1, "allow_from": "10.0.0.0/8"}}))
    _ok(api.post("/api/v1/edit/api", {"attr": {"access": "ro", "active": 1, "allow_from": "10.0.0.0/8"}}))
    from fastapi.testclient import TestClient
    from mailcow.db import get_pool

    with get_pool().connection() as conn:
        keys = {r["access"]: r["api_key"] for r in conn.execute("SELECT access, api_key FROM api").fetchall()}
    allowed = TestClient(app, base_url="https://mail.example.org", client=("10.9.8.7", 1))
    denied = TestClient(app, base_url="https://mail.example.org", client=("8.8.8.8", 1))
    assert allowed.get("/api/v1/get/domain/all", headers={"X-API-Key": keys["rw"]}).status_code == 200
    assert denied.get("/api/v1/get/domain/all", headers={"X-API-Key": keys["rw"]}).status_code == 401
    assert allowed.get("/api/v1/get/domain/all", headers={"X-API-Key": "WRONG-KEY"}).status_code == 401
    # read-only key cannot write
    r = allowed.post("/api/v1/add/domain", json=DOMAIN, headers={"X-API-Key": keys["ro"]})
    assert r.status_code == 403
    # rw key writes without CSRF
    r = allowed.post("/api/v1/add/domain", json={**DOMAIN, "domain": "apikey.example"}, headers={"X-API-Key": keys["rw"]})
    assert r.status_code == 200 and r.json()[-1]["msg"] == ["domain_added", "apikey.example"]
    r = allowed.post("/api/v1/delete/domain", json=["apikey.example"], headers={"X-API-Key": keys["rw"]})
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# objects
# ---------------------------------------------------------------------------
def test_domain_mailbox_alias_lifecycle(api):
    msgs = _ok(api.post("/api/v1/add/domain", DOMAIN))
    assert msgs[-1]["msg"] == ["domain_added", "example.org"]
    # duplicates are refused
    r = api.post("/api/v1/add/domain", DOMAIN)
    assert r.json()[-1]["msg"] == ["domain_exists", "example.org"]
    # quota validation
    r = api.post("/api/v1/add/domain", {**DOMAIN, "domain": "bad.example", "defquota": 20000})
    assert r.json()[-1]["msg"] == "mailbox_defquota_exceeds_mailbox_maxquota"

    # password policy applies to mailboxes
    api.post("/api/v1/edit/passwordpolicy", {"attr": {"length": 8, "numbers": 1}})
    r = api.post("/api/v1/add/mailbox", {"local_part": "info", "domain": "example.org", "name": "Info", "quota": 1024, "password": "short", "password2": "short", "active": 1})
    assert r.json()[-1]["msg"] == "password_complexity"
    msgs = _ok(api.post("/api/v1/add/mailbox", {"local_part": "info", "domain": "example.org", "name": "Info", "quota": 1024, "password": "Secret123", "password2": "Secret123", "active": 1}))
    assert msgs[-1]["msg"] == ["mailbox_added", "info@example.org"]
    r = api.post("/api/v1/add/mailbox", {"local_part": "info", "domain": "example.org", "quota": 1024, "password": "Secret123", "password2": "Secret123", "active": 1})
    assert r.json()[-1]["msg"] == ["object_exists", "info@example.org"]

    # mailbox details
    m = api.get("/api/v1/get/mailbox/info@example.org").json()
    assert m["quota"] == 1024 * 1048576 and m["attributes"]["mailbox_format"] == "maildir:" and m["active"] == 1
    d = api.get("/api/v1/get/domain/example.org").json()
    assert d["mboxes_in_domain"] == 1 and d["quota_used_in_domain"] == 1024 * 1048576

    # alias
    msgs = _ok(api.post("/api/v1/add/alias", {"address": "sales@example.org", "goto": "info@example.org", "active": 1, "sogo_visible": 1}))
    alias_id = msgs[-1]["msg"][2]
    assert isinstance(alias_id, int)
    r = api.post("/api/v1/add/alias", {"address": "info@example.org", "goto": "sales@example.org", "active": 1})
    assert r.json()[-1]["msg"] == ["is_alias_or_mailbox", "info@example.org"]
    a = api.get(f"/api/v1/get/alias/{alias_id}").json()
    assert a["address"] == "sales@example.org" and a["goto"] == "info@example.org"
    _ok(api.post("/api/v1/edit/alias", {"items": [alias_id], "attr": {"active": 0, "private_comment": "x"}}))
    assert api.get(f"/api/v1/get/alias/{alias_id}").json()["active"] == 0

    # dovecot auth backend honours inactive aliases/mailboxes and app password protocol flags
    r = api.c.post("/internal/auth", json={"username": "info@example.org", "password": "Secret123", "real_rip": "1.2.3.4", "service": "imap"})
    assert r.status_code == 200 and r.json()["success"] is True
    r = api.c.post("/internal/auth", json={"username": "info@example.org", "password": "bad", "real_rip": "1.2.3.4", "service": "imap"})
    assert r.status_code == 401
    _ok(api.post("/api/v1/edit/mailbox", {"items": ["info@example.org"], "attr": {"active": 0}}))
    r = api.c.post("/internal/auth", json={"username": "info@example.org", "password": "Secret123", "real_rip": "1.2.3.4", "service": "imap"})
    assert r.status_code == 401
    _ok(api.post("/api/v1/edit/mailbox", {"items": ["info@example.org"], "attr": {"active": 1}}))

    # rspamd helpers
    r = api.c.get("/internal/dynmaps/aliasexp", headers={"Rcpt": "sales+tag@example.org"})
    assert r.text == ""  # alias is inactive
    _ok(api.post("/api/v1/edit/alias", {"items": [alias_id], "attr": {"active": 1}}))
    r = api.c.get("/internal/dynmaps/aliasexp", headers={"Rcpt": "sales+tag@example.org"})
    assert r.text == "info@example.org"
    assert api.c.get("/internal/dynmaps/settings").text.startswith("settings {")

    # quarantine intake + listing + hash link
    r = api.c.post(
        "/internal/meta_exporter/pipe",
        headers={"X-Rspamd-Qid": "ABC", "X-Rspamd-Rcpt": json.dumps(["sales@example.org"]), "X-Rspamd-Score": "12.5", "X-Rspamd-Action": "reject",
                 "X-Rspamd-From": "spammer@evil.org", "X-Rspamd-Symbols": "[]", "X-Rspamd-Subject": "=?utf-8?q?Hallo?=", "X-Rspamd-Ip": "9.9.9.9",
                 "X-Rspamd-User": "unknown", "X-Rspamd-Fuzzy": "unknown"},
        content=b"From: x\r\nSubject: y\r\n\r\nbody",
    )
    assert r.status_code == 200
    q = api.get("/api/v1/get/quarantine/all").json()
    assert q and q[0]["rcpt"] == "info@example.org" and q[0]["subject"] == "Hallo"
    from mailcow.db import get_pool

    with get_pool().connection() as conn:
        qhash = conn.execute("SELECT encode(sha256((id::text || qid)::bytea), 'hex') AS h FROM quarantine").fetchone()["h"]
    assert api.c.get(f"/qhandler/show/{qhash}").status_code == 200
    assert api.c.get("/qhandler/show/" + "0" * 64).status_code == 404
    _ok(api.post("/api/v1/delete/qitem", [q[0]["id"]]))
    assert api.get("/api/v1/get/quarantine/all").json() == {}

    # app passwords: per protocol
    _ok(api.post("/api/v1/add/app-passwd", {"username": "info@example.org", "app_name": "phone", "app_passwd": "AppPass123", "app_passwd2": "AppPass123", "protocols": ["imap_access"], "active": 1}))
    r = api.c.post("/internal/auth", json={"username": "info@example.org", "password": "AppPass123", "real_rip": "1.2.3.4", "service": "imap"})
    assert r.status_code == 200
    r = api.c.post("/internal/auth", json={"username": "info@example.org", "password": "AppPass123", "real_rip": "1.2.3.4", "service": "smtp"})
    assert r.status_code == 401
    # sasl log recorded the last login
    assert api.get("/api/v1/get/last-login/info@example.org").json()["sasl"][0]["service"] == "imap"

    # DKIM
    dk = api.get("/api/v1/get/dkim/example.org").json()
    assert dk["length"] == "2048" and dk["dkim_txt"].startswith("v=DKIM1;k=rsa;t=s;s=email;p=")

    # delete everything
    _ok(api.post("/api/v1/delete/alias", [alias_id]))
    r = api.post("/api/v1/delete/mailbox", ["info@example.org"])
    assert r.json()[-1]["msg"] == ["mailbox_removed", "info@example.org"]
    r = api.post("/api/v1/delete/domain", ["example.org"])
    assert r.json()[-1]["msg"] == ["domain_removed", "example.org"]
    assert api.get("/api/v1/get/domain/all").json() == {}
    api.post("/api/v1/edit/passwordpolicy", {"attr": {"length": 6, "numbers": 0}})


def test_domain_admin_scope(api, app):
    _ok(api.post("/api/v1/add/domain", {**DOMAIN, "domain": "one.example"}))
    _ok(api.post("/api/v1/add/domain", {**DOMAIN, "domain": "two.example"}))
    _ok(api.post("/api/v1/add/domain-admin", {"username": "dadmin", "password": "DaPass123", "password2": "DaPass123", "domains": ["one.example"], "active": 1}))
    from fastapi.testclient import TestClient

    da = TestClient(app, base_url="https://mail.example.org", client=("127.0.0.2", 2))
    r = da.post("/api/v1/login", json={"username": "dadmin", "password": "DaPass123"})
    assert r.json()["result"] == "domainadmin"
    csrf = r.json()["csrf_token"]
    doms = [d["domain_name"] for d in da.get("/api/v1/get/domain/all").json()]
    assert doms == ["one.example"]
    assert da.get("/api/v1/get/domain/two.example").json() == {}
    # cannot create mailboxes in foreign domains
    r = da.post("/api/v1/add/mailbox", json={"local_part": "x", "domain": "two.example", "quota": 100, "password": "Secret123", "password2": "Secret123", "active": 1}, headers={"X-CSRF-Token": csrf})
    assert r.json()[-1]["msg"] == "access_denied"
    csrf = r.headers["x-csrf-token"]
    # cannot add admins
    r = da.post("/api/v1/add/admin", json={"username": "evil", "password": "Secret123", "password2": "Secret123", "active": 1}, headers={"X-CSRF-Token": csrf})
    assert r.json()[-1]["msg"] == "access_denied"
    csrf = r.headers["x-csrf-token"]
    # cannot read fail2ban / logs
    assert da.get("/api/v1/get/fail2ban").json() == {}
    assert da.get("/api/v1/get/logs/ui").json() == {}
    _ok(api.post("/api/v1/delete/domain-admin", ["dadmin"]))
    _ok(api.post("/api/v1/delete/domain", ["one.example", "two.example"]))


def test_user_login_and_self_service(api, app):
    _ok(api.post("/api/v1/add/domain", {**DOMAIN, "domain": "users.example"}))
    _ok(api.post("/api/v1/add/mailbox", {"local_part": "alice", "domain": "users.example", "quota": 100, "password": "Secret123", "password2": "Secret123", "active": 1}))
    from fastapi.testclient import TestClient

    u = TestClient(app, base_url="https://mail.example.org", client=("127.0.0.3", 3))
    r = u.post("/api/v1/login", json={"username": "alice@users.example", "password": "Secret123"})
    assert r.json()["result"] == "user" and r.json()["acl"]["app_passwds"] == 1
    csrf = r.json()["csrf_token"]
    # users see only themselves
    assert u.get("/api/v1/get/mailbox/all").json() == {}
    assert u.get("/api/v1/get/mailbox/alice@users.example").json()["username"] == "alice@users.example"
    # users cannot change quota or ACL
    r = u.post("/api/v1/edit/mailbox", json={"items": ["alice@users.example"], "attr": {"quota": 9000}}, headers={"X-CSRF-Token": csrf})
    assert r.json()[-1]["msg"] == "access_denied"
    csrf = r.headers["x-csrf-token"]
    # password change requires the old password
    r = u.post("/api/v1/edit/user", json={"attr": {"user_old_pass": "wrong", "user_new_pass": "Newpass123", "user_new_pass2": "Newpass123"}}, headers={"X-CSRF-Token": csrf})
    assert r.json()[-1]["msg"] == "access_denied"
    csrf = r.headers["x-csrf-token"]
    r = u.post("/api/v1/edit/user", json={"attr": {"user_old_pass": "Secret123", "user_new_pass": "Newpass123", "user_new_pass2": "Newpass123"}}, headers={"X-CSRF-Token": csrf})
    assert r.json()[-1]["msg"] == ["mailbox_modified", "alice@users.example"]
    csrf = r.headers["x-csrf-token"]
    r = u.c if hasattr(u, "c") else u
    assert r.post("/internal/auth", json={"username": "alice@users.example", "password": "Newpass123", "real_rip": "1.1.1.1", "service": "imap"}).status_code == 200

    # TOTP second factor
    secret = pyotp.random_base32()
    code = pyotp.TOTP(secret).now()
    resp = u.post("/api/v1/add/tfa", json={"tfa_method": "totp", "key_id": "phone", "totp_secret": secret, "totp_confirm_token": code, "confirm_password": "Newpass123"}, headers={"X-CSRF-Token": csrf})
    assert resp.json()[-1]["type"] == "success", resp.text
    csrf = resp.headers["x-csrf-token"]
    u.post("/api/v1/logout", headers={"X-CSRF-Token": csrf})
    r = u.post("/api/v1/login", json={"username": "alice@users.example", "password": "Newpass123"})
    assert r.json()["result"] == "pending" and r.json()["role"] is None
    tfa_id = r.json()["pending_tfa_methods"][0]["id"]
    r = u.post("/api/v1/login/tfa", json={"tfa_method": "totp", "id": tfa_id, "token": "000000"})
    assert r.status_code == 401
    r = u.post("/api/v1/login/tfa", json={"tfa_method": "totp", "id": tfa_id, "token": pyotp.TOTP(secret).now()})
    assert r.json()["result"] == "user"
    # IMAP login is not affected by UI-only TFA
    assert u.post("/internal/auth", json={"username": "alice@users.example", "password": "Newpass123", "real_rip": "1.1.1.1", "service": "imap"}).status_code == 200
    _ok(api.post("/api/v1/delete/domain", ["users.example"]) if False else api.post("/api/v1/delete/mailbox", ["alice@users.example"]))
    _ok(api.post("/api/v1/delete/domain", ["users.example"]))


def test_fail2ban_and_ratelimit_settings(api):
    from mailcow.redisclient import get_redis

    get_redis().set("F2B_OPTIONS", json.dumps({"ban_time": 1800, "max_attempts": 10, "retry_window": 600, "netban_ipv4": 32, "netban_ipv6": 128, "max_ban_time": 10000, "banlist_id": "abc"}))
    r = api.post("/api/v1/edit/fail2ban", {"attr": {"ban_time": 30, "max_attempts": 3, "whitelist": "10.0.0.0/8 bad host", "blacklist": "0.0.0.0/0 203.0.113.0/24"}})
    msgs = r.json()
    # protected networks are reported and skipped, the rest is saved (hostnames are allowed in the whitelist, like PHP)
    assert [m["msg"] for m in msgs if m["type"] == "danger"] == [["network_host_invalid", "0.0.0.0/0"]]
    assert msgs[-1]["msg"] == "f2b_modified"
    f = api.get("/api/v1/get/fail2ban").json()
    assert f["ban_time"] == 60 and f["max_attempts"] == 3 and f["whitelist"] == "10.0.0.0/8\nbad\nhost" and f["blacklist"] == "203.0.113.0/24"
    assert api.c.get("/api/v1/get/fail2ban/banlist/abc").text == "203.0.113.0/24"
    assert api.c.get("/api/v1/get/fail2ban/banlist/wrong").status_code == 404

    _ok(api.post("/api/v1/add/domain", {**DOMAIN, "domain": "rl.example"}))
    _ok(api.post("/api/v1/edit/rl-domain", {"items": ["rl.example"], "attr": {"rl_value": 10, "rl_frame": "h"}}))
    assert api.get("/api/v1/get/rl-domain/rl.example").json() == {"value": "10", "frame": "h"}
    _ok(api.post("/api/v1/delete/domain", ["rl.example"]))


def test_schema_is_idempotent(app):
    import psycopg

    from mailcow.config import settings
    from mailcow.schema import DB_VERSION, current_version, init_db_schema

    with psycopg.connect(settings.dsn) as conn:
        assert current_version(conn) == DB_VERSION
        assert init_db_schema(conn, settings.mailbox_default_attributes) is False
        cols = {r[0] for r in conn.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'mailbox'").fetchall()}
        assert {"username", "password", "attributes", "custom_attributes", "authsource"} <= cols


def test_ui_logs_are_written(api):
    logs = api.get("/api/v1/get/logs/ui/50").json()
    assert any(json.loads(l["call"])[0] == "admin_login" for l in logs)
    assert all(l["remote"] for l in logs)
