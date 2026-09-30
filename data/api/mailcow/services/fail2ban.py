"""Netfilter / fail2ban settings (functions.fail2ban.inc.php) - all state lives in Redis."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from ..config import settings
from ..security.context import Context
from ..validators import as_list, htmlspecialchars, split_list, to_int, valid_hostname, valid_network
from .common import docker

_PROTECTED = lambda: {"0.0.0.0", "0.0.0.0/0", f"{settings.ipv4_network}0/24", f"{settings.ipv4_network}0", settings.ipv6_network}  # noqa: E731


def fail2ban_get(ctx: Context) -> dict[str, Any] | None:
    if ctx.role != "admin":
        return None
    r = ctx.redis
    try:
        opts = json.loads(r.get("F2B_OPTIONS") or "{}")
        opts["regex"] = json.loads(r.get("F2B_REGEX") or "null")
        wl = sorted((r.hgetall("F2B_WHITELIST") or {}).keys())
        opts["whitelist"] = "\n".join(wl)
        bl = sorted((r.hgetall("F2B_BLACKLIST") or {}).keys())
        opts["blacklist"] = "\n".join(bl)
        opts["perm_bans"] = [{"network": k, "ip": k.split("/")[0]} for k in (r.hgetall("F2B_PERM_BANS") or {})]
        active = r.hgetall("F2B_ACTIVE_BANS") or {}
        queue = r.hgetall("F2B_QUEUE_UNBAN") or {}
        bans = []
        for network, until in active.items():
            diff = int(float(until)) - int(time.time())
            bans.append(
                {
                    "queued_for_unban": 1 if str(queue.get(network)) == "1" else 0,
                    "network": network,
                    "ip": network.split("/")[0],
                    "banned_until": "%02dh %02dm %02ds" % (diff // 3600, (diff // 60) % 60, diff % 60),
                }
            )
        opts["active_bans"] = bans
    except Exception as exc:  # noqa: BLE001
        ctx.err(["fail2ban", "get"], ["redis_error", str(exc)])
        return None
    return opts


def fail2ban_edit(ctx: Context, data: dict[str, Any]) -> bool:
    log_ = ["fail2ban", "edit", data]
    if ctx.role != "admin":
        ctx.denied(log_)
        return False
    r = ctx.redis
    action = data.get("action")
    if action:
        if action == "reset-regex":
            r.delete("F2B_REGEX")
            docker(ctx, "post", "netfilter-mailcow", "restart")
            for _ in range(10):
                if r.get("F2B_REGEX"):
                    break
                time.sleep(1)
            else:
                ctx.err(log_, ["reset_f2b_regex"])
                return False
        elif action == "edit-regex":
            regex = as_list(data.get("regex"))
            if regex:
                r.set("F2B_REGEX", json.dumps({str(i + 1): rx for i, rx in enumerate(regex)}))
            ctx.ok(log_, ["object_modified", "regex"])
            return True
        networks = as_list(data.get("network"))
        if networks:
            for network in networks:
                if action == "unban":
                    if valid_network(network):
                        r.hset("F2B_QUEUE_UNBAN", network, 1)
                elif action == "whitelist":
                    if not network:
                        continue
                    if valid_network(network):
                        r.hset("F2B_WHITELIST", network, 1)
                        r.hdel("F2B_BLACKLIST", network)
                        r.hset("F2B_QUEUE_UNBAN", network, 1)
                    else:
                        ctx.err(log_, ["network_host_invalid", network])
                        continue
                elif action == "blacklist":
                    if not network:
                        continue
                    if valid_network(network) and network not in _PROTECTED():
                        r.hset("F2B_BLACKLIST", network, 1)
                        r.hdel("F2B_WHITELIST", network)
                    else:
                        ctx.err(log_, ["network_host_invalid", network])
                        continue
                ctx.ok(log_, ["object_modified", htmlspecialchars(network)])
            return True
    is_now = fail2ban_get(ctx)
    if not is_now:
        ctx.denied(log_)
        return False
    ban_time = to_int(data.get("ban_time", is_now.get("ban_time")))
    ban_time_increment = 1 if str(data.get("ban_time_increment", "")) == "1" else 0
    max_attempts = to_int(data.get("max_attempts", is_now.get("max_attempts")))
    max_ban_time = to_int(data.get("max_ban_time", is_now.get("max_ban_time")))
    retry_window = to_int(data.get("retry_window", is_now.get("retry_window")))
    netban_ipv4 = to_int(data.get("netban_ipv4", is_now.get("netban_ipv4")))
    netban_ipv6 = to_int(data.get("netban_ipv6", is_now.get("netban_ipv6")))
    wl = data.get("whitelist", is_now.get("whitelist"))
    bl = data.get("blacklist", is_now.get("blacklist"))
    manage_external = to_int(data.get("manage_external", 0))
    opts = {
        "ban_time": max(ban_time, 60),
        "ban_time_increment": ban_time_increment == 1,
        "max_ban_time": max(max_ban_time, 60),
        "netban_ipv4": min(max(netban_ipv4, 8), 32),
        "netban_ipv6": min(max(netban_ipv6, 8), 128),
        "max_attempts": max(max_attempts, 1),
        "retry_window": max(retry_window, 1),
        "banlist_id": is_now.get("banlist_id"),
        "manage_external": 1 if manage_external > 0 else 0,
    }
    try:
        r.set("F2B_OPTIONS", json.dumps(opts))
        r.delete("F2B_WHITELIST")
        r.delete("F2B_BLACKLIST")
        for item in split_list(wl):
            if valid_network(item) or valid_hostname(item):
                r.hset("F2B_WHITELIST", item, 1)
            else:
                ctx.err(log_, ["network_host_invalid", item])
        for item in split_list(bl):
            if valid_network(item) and item not in _PROTECTED():
                r.hset("F2B_BLACKLIST", item, 1)
            else:
                ctx.err(log_, ["network_host_invalid", item])
    except Exception as exc:  # noqa: BLE001
        ctx.err(log_, ["redis_error", str(exc)])
        return False
    ctx.ok(log_, "f2b_modified")
    return True


def fail2ban_banlist(ctx: Context, action: str, banlist_id: str | None) -> Any:
    r = ctx.redis
    opts = json.loads(r.get("F2B_OPTIONS") or "{}")
    if banlist_id != opts.get("banlist_id"):
        return None
    if action == "get":
        return "\n".join(list(r.hkeys("F2B_BLACKLIST")) + list(r.hkeys("F2B_ACTIVE_BANS")))
    if action == "refresh":
        if ctx.role != "admin":
            return False
        opts["banlist_id"] = str(uuid.uuid4())
        r.set("F2B_OPTIONS", json.dumps(opts))
        ctx.ok(["fail2ban", "banlist", "refresh"], "f2b_banlist_refreshed")
        return True
    return None
