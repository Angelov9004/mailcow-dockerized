"""Shared helpers for services (Redis-backed settings that used to live in functions.*.inc.php)."""
from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from ..config import settings
from ..security.context import Context
from ..validators import is_valid_domain_name, to_int

log = logging.getLogger("mailcow.services")


# ---------------------------------------------------------------------------
# ratelimit (functions.ratelimit.inc.php) - stored in Redis hash RL_VALUE
# ---------------------------------------------------------------------------
def ratelimit_get(ctx: Context, scope: str, obj: str) -> dict[str, str] | None:
    from ..security.acl import own_domain_access, own_mailbox_access

    if scope == "domain":
        if not own_domain_access(ctx, obj):
            return None
    elif scope == "mailbox":
        if not own_mailbox_access(ctx, obj) or ctx.role not in ("admin", "domainadmin"):
            return None
    else:
        return None
    try:
        val = ctx.redis.hget("RL_VALUE", obj)
    except Exception as exc:  # noqa: BLE001
        ctx.err(["ratelimit", "get", scope, obj], ["redis_error", str(exc)])
        return None
    if not val:
        return None
    parts = val.split(" / 1")
    if len(parts) != 2:
        return None
    return {"value": parts[0], "frame": parts[1]}


def ratelimit_edit(ctx: Context, scope: str, data: dict[str, Any]) -> bool:
    from ..security.acl import own_domain_access, own_mailbox_access

    if not ctx.has_acl("ratelimit"):
        ctx.denied(["ratelimit", "edit", scope, data])
        return False
    objects = data.get("object")
    objects = objects if isinstance(objects, list) else [objects]
    rl_value = to_int(data.get("rl_value"))
    rl_frame = data.get("rl_frame")
    for obj in objects:
        if rl_frame not in ("s", "m", "h", "d"):
            ctx.err(["ratelimit", "edit", scope, data], "rl_timeframe")
            continue
        if scope == "domain":
            if not own_domain_access(ctx, obj):
                ctx.denied(["ratelimit", "edit", scope, data])
                continue
        elif scope == "mailbox":
            if not own_mailbox_access(ctx, obj) or (ctx.role not in ("admin", "domainadmin") and not ctx.access_all_exception):
                ctx.denied(["ratelimit", "edit", scope, data])
                continue
        else:
            return False
        try:
            if not rl_value:
                ctx.redis.hdel("RL_VALUE", obj)
            else:
                ctx.redis.hset("RL_VALUE", obj, f"{rl_value} / 1{rl_frame}")
        except Exception as exc:  # noqa: BLE001
            ctx.err(["ratelimit", "edit", scope, data], ["redis_error", str(exc)])
            continue
        ctx.ok(["ratelimit", "edit", scope, data], ["rl_saved", obj])
    return True


def ratelimit_delete_hash(ctx: Context, rl_hash: str) -> bool:
    import re

    rl_hash = (rl_hash or "").strip()
    if ctx.role != "admin" or not re.match(r"^RL[0-9A-Za-z=]+$", rl_hash):
        ctx.denied(["ratelimit", "delete", rl_hash])
        return False
    try:
        for line in ctx.redis.lrange("RL_LOG", 0, -1) or []:
            if rl_hash.lower() in line.lower():
                ctx.redis.lrem("RL_LOG", 0, line)
        if ctx.redis.type(rl_hash) == "hash":
            ctx.redis.delete(rl_hash)
            ctx.ok(["ratelimit", "delete", rl_hash], "hash_deleted")
            return True
        ctx.warn(["ratelimit", "delete", rl_hash], "hash_not_found")
        return False
    except Exception as exc:  # noqa: BLE001
        ctx.err(["ratelimit", "delete", rl_hash], ["redis_error", str(exc)])
        return False


# ---------------------------------------------------------------------------
# dockerapi (functions.docker.inc.php)
# ---------------------------------------------------------------------------
def _docker_client() -> httpx.Client:
    # dockerapi uses the mail certificate; names never match, the channel is internal (docker network)
    return httpx.Client(base_url=settings.dockerapi_url, verify=False, timeout=settings.docker_timeout, trust_env=False)


def docker(ctx: Context | None, action: str, service_name: str | None = None, attr1: Any = None, attr2: Any = None) -> Any:
    project = settings.compose_project_name.lower()
    try:
        with _docker_client() as client:
            if action == "get_id":
                resp = client.get("/containers/json")
                for c in resp.json() or []:
                    labels = c.get("Config", {}).get("Labels", {})
                    if labels.get("com.docker.compose.service") == service_name and labels.get("com.docker.compose.project", "").lower() == project:
                        return c["Id"].strip()
                return False
            if action in ("containers", "info") and not service_name:
                resp = client.get("/containers/json")
                out: dict[str, Any] = {}
                for c in resp.json() or []:
                    labels = c.get("Config", {}).get("Labels", {})
                    if labels.get("com.docker.compose.project", "").lower() == project:
                        c.get("Config", {}).pop("Env", None)
                        svc = labels.get("com.docker.compose.service")
                        out[svc] = {"State": c.get("State"), "Config": c.get("Config"), "Id": c["Id"].strip()}
                return out or False
            if action == "info":
                cid = docker(ctx, "get_id", service_name)
                if not cid or not all(ch in "0123456789abcdef" for ch in cid):
                    return False
                resp = client.get(f"/containers/{cid}/json")
                c = resp.json()
                labels = c.get("Config", {}).get("Labels", {})
                if labels.get("com.docker.compose.project", "").lower() != project:
                    return False
                c.get("Config", {}).pop("Env", None)
                return {labels.get("com.docker.compose.service"): {"State": c.get("State"), "Config": c.get("Config"), "Id": c["Id"].strip()}}
            if action == "post":
                if not attr1 or not str(attr1).isalnum():
                    return False
                cid = docker(ctx, "get_id", service_name)
                if not cid:
                    return False
                resp = client.post(f"/containers/{cid}/{attr1}", json=attr2 if attr2 else None)
                return resp.text or True
            if action == "container_stats":
                resp = client.post(f"/container/{service_name}/stats/update")
                return resp.json() or False
            if action == "host_stats":
                resp = client.get("/host/stats")
                return resp.json() or False
    except Exception as exc:  # noqa: BLE001
        log.error("dockerapi %s failed: %s", action, exc)
        return str(exc)
    if action == "broadcast":
        request = {"api_call": "container_post", "container_name": service_name, "post_action": attr1, "request": attr2}
        (ctx.redis if ctx else None) and ctx.redis.publish("MC_CHANNEL", json.dumps(request))
        return True
    return False


# ---------------------------------------------------------------------------
# DKIM (functions.dkim.inc.php) - keys in Redis hashes
# ---------------------------------------------------------------------------
def _rsa_keypair(bits: int) -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    ).decode()
    pub_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    pub = "".join(line for line in pub_pem.splitlines() if not line.startswith("-----"))
    return priv.strip(), pub


def _pub_from_priv(priv_pem: str) -> str:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(priv_pem.encode(), password=None)
    pub_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return "".join(line for line in pub_pem.splitlines() if not line.startswith("-----"))


def _selector_ok(sel: str) -> bool:
    return bool(sel) and all(ch.isalnum() or ch in "-_." for ch in sel)


def dkim_add(ctx: Context, data: dict[str, Any]) -> bool:
    from ..security.acl import own_domain_access
    from ..validators import split_list

    key_length = to_int(data.get("key_size"))
    selector = data.get("dkim_selector") or "dkim"
    for domain in split_list(data.get("domains")):
        if not is_valid_domain_name(domain) or key_length not in (1024, 2048, 3072, 4096, 8192):
            ctx.err(["dkim", "add", data], ["dkim_domain_or_sel_invalid", domain])
            continue
        if ctx.redis.hget("DKIM_PUB_KEYS", domain):
            ctx.err(["dkim", "add", data], ["dkim_domain_or_sel_invalid", domain])
            continue
        if not _selector_ok(selector):
            ctx.err(["dkim", "add", data], ["dkim_domain_or_sel_invalid", domain])
            continue
        if not own_domain_access(ctx, domain):
            ctx.denied(["dkim", "add", data], domain)
            continue
        priv, pub = _rsa_keypair(key_length)
        try:
            ctx.redis.hset("DKIM_PUB_KEYS", domain, pub)
            ctx.redis.hset("DKIM_SELECTORS", domain, selector)
            ctx.redis.hset("DKIM_PRIV_KEYS", f"{selector}.{domain}", priv)
        except Exception as exc:  # noqa: BLE001
            ctx.err(["dkim", "add", data], ["redis_error", str(exc)])
            continue
        ctx.ok(["dkim", "add", data], ["dkim_added", domain])
    return True


def dkim_details(ctx: Context, domain: str, privkey: bool = False) -> dict[str, Any]:
    from ..security.acl import own_domain_access

    if not own_domain_access(ctx, domain) and ctx.role != "admin":
        return {}
    out: dict[str, Any] = {}
    pub = ctx.redis.hget("DKIM_PUB_KEYS", domain)
    if pub:
        out["pubkey"] = pub
        n = len(pub)
        out["length"] = "1024" if n < 391 else "2048" if n < 564 else "3072" if n < 736 else "4096" if n < 1416 else ">= 8192"
        txt = "v=DKIM1;k=rsa;t=s;s=email;p=" + pub
        if settings.split_dkim_255:
            chunks = [txt[i : i + 255] for i in range(0, len(txt), 255)]
            out["dkim_txt"] = '"' + '" "'.join(chunks) + '"'
        else:
            out["dkim_txt"] = txt
        out["dkim_selector"] = ctx.redis.hget("DKIM_SELECTORS", domain)
        if settings.show_dkim_priv_keys or privkey:
            import base64

            out["privkey"] = base64.b64encode((ctx.redis.hget("DKIM_PRIV_KEYS", f"{out['dkim_selector']}.{domain}") or "").encode()).decode()
        else:
            out["privkey"] = ""
    return out


def dkim_delete(ctx: Context, data: dict[str, Any]) -> bool:
    from ..validators import as_list

    if ctx.role != "admin":
        ctx.denied(["dkim", "delete", data])
        return False
    for domain in as_list(data.get("domains")):
        if not is_valid_domain_name(domain):
            ctx.err(["dkim", "delete", data], ["dkim_domain_or_sel_invalid", domain])
            continue
        try:
            selector = ctx.redis.hget("DKIM_SELECTORS", domain)
            ctx.redis.hdel("DKIM_PUB_KEYS", domain)
            ctx.redis.hdel("DKIM_PRIV_KEYS", f"{selector}.{domain}")
            ctx.redis.hdel("DKIM_SELECTORS", domain)
        except Exception as exc:  # noqa: BLE001
            ctx.err(["dkim", "delete", data], ["redis_error", str(exc)])
            continue
        ctx.ok(["dkim", "delete", data], ["dkim_removed", domain])
    return True


def dkim_duplicate(ctx: Context, data: dict[str, Any]) -> bool:
    import base64

    from ..validators import as_list

    if ctx.role != "admin":
        ctx.denied(["dkim", "duplicate", data])
        return False
    from_domain = data.get("from_domain") or ""
    src = dkim_details(ctx, from_domain, privkey=True)
    if not src:
        ctx.err(["dkim", "duplicate", data], ["dkim_domain_or_sel_invalid", from_domain])
        return False
    for to_domain in [d for d in as_list(data.get("to_domain")) if d]:
        try:
            ctx.redis.hset("DKIM_PUB_KEYS", to_domain, src["pubkey"])
            ctx.redis.hset("DKIM_SELECTORS", to_domain, src["dkim_selector"])
            ctx.redis.hset("DKIM_PRIV_KEYS", f"{src['dkim_selector']}.{to_domain}", base64.b64decode(src["privkey"]).decode())
        except Exception as exc:  # noqa: BLE001
            ctx.err(["dkim", "duplicate", data], ["redis_error", str(exc)])
            continue
        ctx.ok(["dkim", "duplicate", data], ["dkim_duplicated", from_domain, to_domain])
    return True


def dkim_import(ctx: Context, data: dict[str, Any]) -> bool:
    if ctx.role != "admin":
        ctx.denied(["dkim", "import", data])
        return False
    priv = (data.get("private_key_file") or "").strip().replace("\r\n", "\n").replace("\r", "\n")
    overwrite = to_int(data.get("overwrite_existing"))
    try:
        pub = _pub_from_priv(priv)
    except Exception as exc:  # noqa: BLE001
        ctx.err(["dkim", "import", data], ["private_key_error", str(exc)])
        return False
    selector = data.get("dkim_selector") or "dkim"
    domain = data.get("domain") or ""
    if not is_valid_domain_name(domain):
        ctx.err(["dkim", "import", data], ["dkim_domain_or_sel_invalid", domain])
        return False
    if ctx.redis.hget("DKIM_PUB_KEYS", domain) and overwrite == 0:
        ctx.err(["dkim", "import", data], ["dkim_domain_or_sel_exists", domain])
        return False
    if not _selector_ok(selector):
        ctx.err(["dkim", "import", data], ["dkim_domain_or_sel_invalid", domain])
        return False
    dkim_delete(ctx, {"domains": domain})
    ctx.redis.hset("DKIM_PUB_KEYS", domain, pub)
    ctx.redis.hset("DKIM_SELECTORS", domain, selector)
    ctx.redis.hset("DKIM_PRIV_KEYS", f"{selector}.{domain}", priv)
    ctx.ok(["dkim", "import", data], ["dkim_added", domain])
    return True


def dkim_blind(ctx: Context) -> list[str]:
    if ctx.role != "admin":
        return []
    from .mailbox import get_alias_domains, get_domains

    known = set(get_domains(ctx)) | set(get_alias_domains(ctx))
    return [d for d in ctx.redis.hkeys("DKIM_PUB_KEYS") if d not in known]


# ---------------------------------------------------------------------------
# quarantine settings (functions.quarantine.inc.php 'edit'/'settings' part)
# ---------------------------------------------------------------------------
def quarantine_settings_get(ctx: Context) -> dict[str, Any]:
    r = ctx.redis
    return {
        "max_size": r.get("Q_MAX_SIZE"),
        "max_age": r.get("Q_MAX_AGE"),
        "retention_size": r.get("Q_RETENTION_SIZE"),
        "max_score": r.get("Q_MAX_SCORE"),
        "release_format": r.get("Q_RELEASE_FORMAT"),
        "sender": r.get("Q_SENDER"),
        "subj": r.get("Q_SUBJ"),
        "bcc": r.get("Q_BCC"),
        "redirect": r.get("Q_REDIRECT"),
        "exclude_domains": json.loads(r.get("Q_EXCLUDE_DOMAINS") or "[]"),
        "html_tmpl": r.get("Q_HTML"),
    }
