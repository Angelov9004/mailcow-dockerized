"""Shared Redis client (mailcow keeps DKIM keys, rate limits, fail2ban state, quarantine settings in Redis)."""
from __future__ import annotations

import logging
import time

import redis

from .config import settings

log = logging.getLogger("mailcow.redis")

_client: redis.Redis | None = None


def get_redis() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_pass or None,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
            health_check_interval=30,
        )
    return _client


def set_redis(client: redis.Redis) -> None:
    """Used by tests to inject a fake client."""
    global _client
    _client = client


def wait_for_redis(timeout: float = 600.0) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            get_redis().ping()
            return
        except Exception as exc:  # noqa: BLE001
            if time.monotonic() > deadline:
                raise
            log.info("Waiting for Redis... (%s)", exc)
            time.sleep(2)
