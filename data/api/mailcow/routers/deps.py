"""FastAPI dependencies: one DB connection + request context per request."""
from __future__ import annotations

from typing import Iterator

from fastapi import Request

from ..db import DB, get_pool
from ..security.context import Context, build_context


def get_ctx(request: Request) -> Iterator[Context]:
    pool = get_pool()
    with pool.connection() as conn:
        db = DB(conn)
        ctx = build_context(request, db)
        request.state.ctx = ctx
        try:
            yield ctx
            ctx.flush_log()
            if not ctx.session.destroyed and ctx.session.sid:
                ctx.session.save()
            conn.commit()
        except Exception:
            conn.rollback()
            try:
                ctx.flush_log()
                conn.commit()
            except Exception:  # noqa: BLE001
                conn.rollback()
            raise
