"""Standalone schema initialisation: `python -m mailcow.dbinit` (used by the container entrypoint and update.sh)."""
from __future__ import annotations

import logging
import sys

import psycopg

from .config import settings
from .db import wait_for_db
from .schema import DB_VERSION, init_db_schema

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")


def main() -> int:
    wait_for_db()
    with psycopg.connect(settings.dsn) as conn:
        applied = init_db_schema(conn, settings.mailbox_default_attributes, is_master=settings.master)
    print("DB initialization completed" if applied else f"DB schema already at {DB_VERSION}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
