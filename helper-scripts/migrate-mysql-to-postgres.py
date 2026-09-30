#!/usr/bin/env python3
"""
Migrate an existing mailcow MariaDB/MySQL database into the PostgreSQL schema used by the Python stack.

Usage (run on the host, both databases reachable):

  pip install pymysql "psycopg[binary]"
  python3 helper-scripts/migrate-mysql-to-postgres.py \
      --mysql-host 127.0.0.1 --mysql-port 13306 --mysql-user mailcow --mysql-password ... --mysql-db mailcow \
      --pg-host 127.0.0.1 --pg-port 15432 --pg-user mailcow --pg-password ... --pg-db mailcow

Typical procedure:
  1. Stop the old stack, start only the old MariaDB container (docker compose up -d mysql-mailcow) or use a dump
     restored into a throw-away MariaDB.
  2. Start the new stack once so that the API creates the PostgreSQL schema (docker compose up -d postgres-mailcow api-mailcow).
  3. Run this script. It truncates the target tables and copies everything, translating types and renamed columns.
  4. Start the full stack. Redis data (DKIM keys, rate limits, fail2ban, quarantine settings) is untouched and keeps working.

The script is idempotent: every run replaces the contents of the target tables.
"""
from __future__ import annotations

import argparse
import json
import sys

try:
    import pymysql
    import pymysql.cursors
except ImportError:  # pragma: no cover
    sys.exit("pymysql is required: pip install pymysql")
try:
    import psycopg
except ImportError:  # pragma: no cover
    sys.exit("psycopg is required: pip install 'psycopg[binary]'")

# tables in dependency order (foreign keys reference mailbox/domain)
TABLES = [
    "versions", "admin", "fido2", "_sogo_static_view", "relayhosts", "transports", "api", "sender_acl", "templates",
    "domain", "domain_wide_footer", "tags_domain", "tls_policy_override", "quarantine", "mailbox", "tags_mailbox",
    "sieve_filters", "app_passwd", "user_acl", "alias", "alias_domain", "spamalias", "filterconf", "settingsmap",
    "identity_provider", "logs", "sasl_log", "quota2", "quota2replica", "domain_admins", "da_acl", "da_sso",
    "reset_password", "imapsync", "bcc_maps", "recipient_maps", "tfa", "forwarding_hosts", "sogo_acl",
    "sogo_alarms_folder", "sogo_cache_folder", "sogo_folder_info", "sogo_quick_appointment", "sogo_quick_contact",
    "sogo_sessions_folder", "sogo_store", "sogo_admin", "pushover", "sogo_user_profile", "oauth_clients",
    "oauth_access_tokens", "oauth_authorization_codes", "oauth_refresh_tokens",
]

# column renames (MySQL name -> PostgreSQL name)
RENAMES = {
    "settingsmap": {"desc": "description"},
    "logs": {"user": "username"},
    "quarantine": {"user": "username"},
    "tfa": {"keyHandle": "keyhandle", "publicKey": "publickey"},
    "fido2": {
        "friendlyName": "friendlyname", "rpId": "rpid", "credentialPublicKey": "credentialpublickey",
        "certificateChain": "certificatechain", "certificateIssuer": "certificateissuer",
        "certificateSubject": "certificatesubject", "signatureCounter": "signaturecounter", "AAGUID": "aaguid",
        "credentialId": "credentialid",
    },
}
JSON_COLUMNS = {
    "templates": {"attributes"},
    "domain_wide_footer": {"mbox_exclude", "alias_domain_exclude"},
    "quarantine": {"symbols", "fuzzy_hashes"},
    "mailbox": {"attributes", "custom_attributes"},
    "pushover": {"attributes"},
}
IDENTITY_COLUMNS = {
    "relayhosts": "id", "transports": "id", "alias": "id", "sender_acl": "id", "templates": "id",
    "tls_policy_override": "id", "quarantine": "id", "sieve_filters": "id", "app_passwd": "id", "filterconf": "prefid",
    "settingsmap": "id", "logs": "id", "domain_admins": "id", "imapsync": "id", "bcc_maps": "id", "recipient_maps": "id",
    "tfa": "id", "sogo_acl": "id", "sogo_alarms_folder": "id", "sogo_folder_info": "c_folder_id", "oauth_clients": "id",
}


def pg_columns(pg: psycopg.Connection, table: str) -> list[str]:
    with pg.cursor() as cur:
        cur.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = %s ORDER BY ordinal_position",
            (table,),
        )
        return [r[0] for r in cur.fetchall()]


def convert(table: str, col: str, val):
    if val is None:
        return None
    if col in JSON_COLUMNS.get(table, set()):
        if isinstance(val, (bytes, bytearray)):
            val = val.decode("utf-8", errors="replace")
        if isinstance(val, str):
            try:
                return json.dumps(json.loads(val))
            except ValueError:
                return json.dumps(val)
        return json.dumps(val)
    if isinstance(val, (bytes, bytearray)) and table == "fido2":
        return val
    if isinstance(val, (bytes, bytearray)):
        return val.decode("utf-8", errors="replace")
    return val


def migrate(args: argparse.Namespace) -> None:
    my = pymysql.connect(
        host=args.mysql_host, port=args.mysql_port, user=args.mysql_user, password=args.mysql_password,
        database=args.mysql_db, charset="utf8mb4", cursorclass=pymysql.cursors.SSDictCursor,
    )
    pg = psycopg.connect(
        host=args.pg_host, port=args.pg_port, user=args.pg_user, password=args.pg_password, dbname=args.pg_db, autocommit=False
    )
    with pg.cursor() as cur:
        cur.execute("SET session_replication_role = replica")  # skip FK checks during bulk load
    total = 0
    for table in TABLES:
        with my.cursor() as mc:
            try:
                mc.execute(f"SELECT * FROM `{table}`")
            except pymysql.err.ProgrammingError:
                print(f"  {table}: not present in source, skipping")
                continue
            target_cols = pg_columns(pg, table)
            if not target_cols:
                print(f"  {table}: not present in target, skipping")
                continue
            renames = RENAMES.get(table, {})
            with pg.cursor() as pc:
                if table != "versions":
                    pc.execute(f'TRUNCATE TABLE "{table}"')
                n = 0
                batch = []
                cols_used: list[str] | None = None
                for row in mc:
                    mapped = {}
                    for k, v in row.items():
                        tk = renames.get(k, k)
                        if tk in target_cols:
                            mapped[tk] = convert(table, tk, v)
                    if cols_used is None:
                        cols_used = list(mapped.keys())
                    batch.append([mapped.get(c) for c in cols_used])
                    if len(batch) >= 500:
                        n += _flush(pc, table, cols_used, batch)
                        batch = []
                if batch and cols_used:
                    n += _flush(pc, table, cols_used, batch)
                ident = IDENTITY_COLUMNS.get(table)
                if ident and n:
                    pc.execute(f'SELECT setval(pg_get_serial_sequence(\'"{table}"\', %s), COALESCE(MAX("{ident}"), 0) + 1, false) FROM "{table}"', (ident,))
            total += n
            print(f"  {table}: {n} rows")
    with pg.cursor() as cur:
        cur.execute("SET session_replication_role = DEFAULT")
        # the schema version must reflect the target so the API does not re-run migrations against migrated data
        cur.execute("DELETE FROM versions WHERE application = 'db_schema'")
    pg.commit()
    print(f"done, {total} rows migrated. Start api-mailcow now; it will finalise the schema version.")


def _flush(pc, table: str, cols: list[str], batch: list) -> int:
    col_sql = ", ".join(f'"{c}"' for c in cols)
    placeholders = ", ".join(["%s"] * len(cols))
    jsonb_cast = {c for c in cols if c in JSON_COLUMNS.get(table, set())}
    if jsonb_cast:
        placeholders = ", ".join("%s::jsonb" if c in jsonb_cast else "%s" for c in cols)
    conflict = "ON CONFLICT DO NOTHING" if table == "versions" else ""
    pc.executemany(f'INSERT INTO "{table}" ({col_sql}) VALUES ({placeholders}) {conflict}', batch)
    return len(batch)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mysql-host", default="127.0.0.1")
    ap.add_argument("--mysql-port", type=int, default=13306)
    ap.add_argument("--mysql-user", default="mailcow")
    ap.add_argument("--mysql-password", required=True)
    ap.add_argument("--mysql-db", default="mailcow")
    ap.add_argument("--pg-host", default="127.0.0.1")
    ap.add_argument("--pg-port", type=int, default=15432)
    ap.add_argument("--pg-user", default="mailcow")
    ap.add_argument("--pg-password", required=True)
    ap.add_argument("--pg-db", default="mailcow")
    migrate(ap.parse_args())


if __name__ == "__main__":
    main()
