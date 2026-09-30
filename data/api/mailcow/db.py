"""PostgreSQL connection pool (psycopg 3, sync, thread pool of workers).

The API is intentionally synchronous per request and uses a pool: it keeps the
code simple, avoids event-loop pitfalls with blocking hash verification, and is
plenty fast for an admin UI + Dovecot auth backend (Dovecot caches results).
"""
from __future__ import annotations

import contextlib
import logging
import time
from typing import Any, Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .config import settings

log = logging.getLogger("mailcow.db")

_pool: ConnectionPool | None = None


def get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(
            conninfo=settings.dsn,
            min_size=settings.db_pool_min,
            max_size=settings.db_pool_max,
            kwargs={"row_factory": dict_row, "autocommit": False},
            open=True,
            name="mailcow",
        )
    return _pool


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


def wait_for_db(timeout: float = 600.0) -> None:
    """Block until PostgreSQL accepts connections (containers start in any order)."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            with psycopg.connect(settings.dsn, connect_timeout=3) as conn:
                conn.execute("SELECT 1")
            return
        except Exception as exc:  # noqa: BLE001
            if time.monotonic() > deadline:
                raise
            log.info("Waiting for database to come up... (%s)", exc)
            time.sleep(2)


@contextlib.contextmanager
def connection() -> Iterator[psycopg.Connection[dict[str, Any]]]:
    """Yield a pooled connection; commits on success, rolls back on error."""
    pool = get_pool()
    with pool.connection() as conn:
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


class DB:
    """Thin helper bound to one connection; used by services within a request."""

    def __init__(self, conn: psycopg.Connection[dict[str, Any]]):
        self.conn = conn

    def one(self, query: str, params: tuple | dict | list | None = None) -> dict[str, Any] | None:
        with self.conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchone()

    def all(self, query: str, params: tuple | dict | list | None = None) -> list[dict[str, Any]]:
        with self.conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchall()

    def exec(self, query: str, params: tuple | dict | list | None = None) -> int:
        with self.conn.cursor() as cur:
            cur.execute(query, params)
            return cur.rowcount

    def scalar(self, query: str, params: tuple | dict | list | None = None) -> Any:
        row = self.one(query, params)
        if not row:
            return None
        return next(iter(row.values()))

    def count(self, query: str, params: tuple | dict | list | None = None) -> int:
        return len(self.all(query, params))

    def insert_returning_id(self, query: str, params: tuple | dict | list | None = None) -> int | None:
        row = self.one(query + " RETURNING id", params)
        return row["id"] if row else None

    def commit(self) -> None:
        self.conn.commit()
