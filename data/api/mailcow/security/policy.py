"""Password policy: port of password_complexity() and password_check()."""
from __future__ import annotations

import re

from .context import Context

DEFAULT_POLICY = {"length": 6, "chars": 0, "special_chars": 0, "lowerupper": 0, "numbers": 0}


def password_complexity_get(ctx: Context) -> dict[str, int]:
    try:
        raw = ctx.redis.hgetall("PASSWD_POLICY") or {}
    except Exception as exc:  # noqa: BLE001
        ctx.err(["password_complexity", "get"], ["redis_error", str(exc)])
        return dict(DEFAULT_POLICY)
    policy = dict(DEFAULT_POLICY)
    for k in policy:
        if k in raw and str(raw[k]).strip() != "":
            try:
                policy[k] = int(raw[k])
            except ValueError:
                pass
    return policy


def password_complexity_edit(ctx: Context, data: dict) -> bool:
    if ctx.role != "admin":
        ctx.denied(["password_complexity", "edit", data])
        return False
    is_now = password_complexity_get(ctx)
    length = int(data.get("length", is_now["length"]) or is_now["length"])
    if length < 3:
        length = is_now["length"]
    policy = {
        "length": length,
        "chars": int(data.get("chars", is_now["chars"]) or 0),
        "special_chars": int(data.get("special_chars", is_now["special_chars"]) or 0),
        "lowerupper": int(data.get("lowerupper", is_now["lowerupper"]) or 0),
        "numbers": int(data.get("numbers", is_now["numbers"]) or 0),
    }
    try:
        ctx.redis.hset("PASSWD_POLICY", mapping={k: str(v) for k, v in policy.items()})
    except Exception as exc:  # noqa: BLE001
        ctx.err(["password_complexity", "edit", data], ["redis_error", str(exc)])
        return False
    ctx.ok(["password_complexity", "edit", data], "password_policy_saved")
    return True


def password_check(ctx: Context, password1: str | None, password2: str | None) -> bool:
    """Returns True if both passwords match and satisfy the policy; otherwise records a message."""
    policy = password_complexity_get(ctx)
    if not password1 or not password2:
        ctx.err(["password_check"], "password_complexity")
        return False
    if password1 != password2:
        ctx.err(["password_check"], "password_mismatch")
        return False
    given = {
        "length": len(password1),
        "special_chars": 1 if re.search(r"[^a-zA-Z\d]", password1) else 0,
        "chars": 1 if re.search(r"[a-zA-Z]", password1) else 0,
        "numbers": 1 if re.search(r"\d", password1) else 0,
        "lowerupper": 1 if (re.search(r"[a-z]", password1) and re.search(r"[A-Z]", password1)) else 0,
    }
    if (
        given["length"] < policy["length"]
        or (policy["special_chars"] == 1 and given["special_chars"] != 1)
        or (policy["chars"] == 1 and given["chars"] != 1)
        or (policy["numbers"] == 1 and given["numbers"] != 1)
        or (policy["lowerupper"] == 1 and given["lowerupper"] != 1)
    ):
        ctx.err(["password_check"], "password_complexity")
        return False
    return True
