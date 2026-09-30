"""Integration test fixtures. Requires a reachable PostgreSQL and Redis:

  DBHOST=127.0.0.1 DBPORT=15432 DBUSER=mailcow DBPASS=mailcow DBNAME=mailcow_test REDISHOST=127.0.0.1 REDISPORT=16379 pytest

The database is dropped and recreated for every test session; Redis is flushed.
"""
from __future__ import annotations

import os

import psycopg
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DBHOST", "127.0.0.1")
os.environ.setdefault("DBPORT", "15432")
os.environ.setdefault("DBUSER", "mailcow")
os.environ.setdefault("DBPASS", "mailcow")
os.environ.setdefault("DBNAME", "mailcow_test")
os.environ.setdefault("REDISHOST", "127.0.0.1")
os.environ.setdefault("REDISPORT", "16379")
os.environ.setdefault("REDISPASS", "")
os.environ.setdefault("MAILCOW_HOSTNAME", "mail.example.org")
os.environ.setdefault("MAILCOW_PASS_SCHEME", "BLF-CRYPT")

from mailcow.config import settings  # noqa: E402


def _admin_dsn() -> str:
    return f"host={settings.db_host} port={settings.db_port} dbname=postgres user={settings.db_user} password={settings.db_pass}"


@pytest.fixture(scope="session")
def database():
    with psycopg.connect(_admin_dsn(), autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{settings.db_name}"')
        conn.execute(f'CREATE DATABASE "{settings.db_name}"')
    yield settings.db_name


@pytest.fixture(scope="session")
def app(database):
    from mailcow.redisclient import get_redis

    get_redis().flushdb()
    from mailcow.main import app as _app

    return _app


@pytest.fixture()
def client(app):
    with TestClient(app, base_url="https://mail.example.org", client=("127.0.0.1", 50000)) as c:
        yield c


@pytest.fixture()
def admin(client):
    """Logged in admin session; returns (client, csrf_token)."""
    r = client.post("/api/v1/login", json={"username": "admin", "password": "moohoo"})
    assert r.status_code == 200 and r.json()["result"] == "admin", r.text
    return client, r.json()["csrf_token"]


class Api:
    """Small helper that keeps the rotating CSRF token in sync."""

    def __init__(self, client: TestClient, csrf: str):
        self.c = client
        self.csrf = csrf

    def post(self, path: str, body):
        r = self.c.post(path, json=body, headers={"X-CSRF-Token": self.csrf})
        if "x-csrf-token" in r.headers:
            self.csrf = r.headers["x-csrf-token"]
        return r

    def get(self, path: str):
        return self.c.get(path)


@pytest.fixture()
def api(admin):
    return Api(*admin)
