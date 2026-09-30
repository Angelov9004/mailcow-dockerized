# mailcow on Python + PostgreSQL

This branch replaces the PHP/MariaDB half of mailcow with a Python service backed by PostgreSQL.
The mail path itself (Postfix, Dovecot, Rspamd, ClamAV, SOGo, Unbound, netfilter, ACME, watchdog) is unchanged;
those containers now read their lookup tables from PostgreSQL instead of MariaDB.

## What changed

| Before                                   | Now                                                          |
|------------------------------------------|--------------------------------------------------------------|
| `mysql-mailcow` (MariaDB 10.11)          | `postgres-mailcow` (PostgreSQL 16, `data/conf/postgres/`)    |
| `php-fpm-mailcow` + 240k lines of PHP    | `api-mailcow` (FastAPI, `data/api/`, ~6k lines)              |
| `memcached-mailcow`                      | removed (only the PHP UI used it)                            |
| `data/web/*.php`, Twig templates         | JSON API + a small single page UI (`data/api/mailcow/static`)|
| MySQL unix socket volume in 6 containers | TCP to `postgres:5432` with the password from `mailcow.conf` |
| `mysql:` lookup tables in Postfix        | `pgsql:` lookup tables (`data/Dockerfiles/postfix/postfix.sh`)|
| `driver = mysql` in Dovecot              | `driver = pgsql` (userdb, quota dict, sieve dicts)           |
| SOGo `mysql://` OCS URLs                 | SOGo `postgresql://` OCS URLs                                |
| `SQL_PORT=127.0.0.1:13306`               | `SQL_PORT=127.0.0.1:15432`                                   |

The resulting image set is considerably lighter: no PHP runtime with a dozen extensions, no Composer vendor tree,
no memcached, and a database engine with a much smaller footprint under mailcow's workload.

## Security parity

The Python API re-implements the security behaviour of the PHP UI one for one:

* **Password hashing**: every Dovecot scheme the PHP code accepted is accepted (`BLF-CRYPT`, `SSHA*`, `SHA*-CRYPT`,
  `ARGON2*`, `PBKDF2`, `MD5-CRYPT`, legacy plain schemes). New hashes use `MAILCOW_PASS_SCHEME` (default bcrypt with
  the `$2y$` prefix so Dovecot and SOGo read them unchanged). Comparisons are constant time.
* **Sessions**: server side in Redis, 256 bit ids, `HttpOnly`, `Secure` when served over HTTPS, `SameSite=Lax`,
  bound to the User-Agent that created them, idle timeout `SESSION_LIFETIME` (3 h), id regenerated on login.
* **CSRF**: a per-session token that rotates after every state changing request; sent as `X-CSRF-Token`.
* **Brute force**: failed logins are published on `F2B_CHANNEL` with the exact wording netfilter matches, and each
  failure adds a 0.5 s delay to the session (capped at 30 s).
* **API keys**: `X-API-Key`, read-only vs read/write, IP allow list (`ip_acl`) or explicit skip.
* **Roles and ACLs**: admin / domain admin / user with the same `hasDomainAccess`, `hasMailboxObjectAccess`,
  `hasAliasObjectAccess` semantics and the same `user_acl` / `da_acl` tables. Users only see themselves; domain
  admins only their domains; ACL flags gate app passwords, quarantine, rate limits, TLS policy and so on.
* **Second factor**: TOTP (pyotp), WebAuthn/FIDO2 (py_webauthn, sign counter checked and stored) and Yubico OTP
  (YubiCloud, response HMAC verified). A pending login only gets a session after the second factor succeeds.
* **Password policy**: length / letters / numbers / special / mixed case, enforced for admins, users and app passwords.
* **App passwords**: per protocol (IMAP, SMTP, POP3, Sieve, DAV, EAS), only for active mailboxes in active domains.
* **Audit log**: every action is written to the `logs` table with user, role, remote IP and call, like the PHP logger.
* **Dovecot / SOGo authentication** goes through the same HTTP backend (`/internal/auth`, served on nginx port 9082
  with TLS) and the SOGo SSO password mechanism is unchanged.
* Internal endpoints (`/internal/*`, `/sogo-auth`) are only reachable through the internal nginx listeners; the public
  vhost proxies `/` to the API which serves the UI, `/api/v1`, autoconfig/autodiscover and quarantine links.

## Layout

```
data/api/
  mailcow/main.py            FastAPI app, middleware, bootstrap (schema + Redis defaults)
  mailcow/schema.py          PostgreSQL schema (port of init_db.inc.php), idempotent migrations
  mailcow/security/          passwords, sessions, auth (check_login), ACL, policy, TFA
  mailcow/services/          domains/mailboxes/aliases, admins/keys/app passwords, fail2ban, misc objects
  mailcow/routers/api_v1.py  /api/v1/{get,add,edit,delete}/<category>  (mailcow API compatible)
  mailcow/routers/internal.py Dovecot auth, rspamd dynmaps + metadata exporter, SOGo SSO
  mailcow/routers/ui.py      login/TFA/logout, autoconfig, autodiscover, quarantine links, static UI
  mailcow/static/            single page UI (no build step)
  tests/                     unit + integration tests (real PostgreSQL + Redis)
data/Dockerfiles/api/        image (python:3.12-slim + requirements)
data/conf/postgres/          postgresql.conf, pg_hba.conf
helper-scripts/migrate-mysql-to-postgres.py   data migration from an existing MariaDB
```

## Fresh installation

```
./generate_config.sh
docker compose pull && docker compose build api-mailcow
docker compose up -d
```

Default login is `admin` / `moohoo`, change it immediately (Access page or `helper-scripts/mailcow-reset-admin.sh`).

## Migrating an existing mailcow (MariaDB)

1. Take a backup (`helper-scripts/backup_and_restore.sh backup all` on the old version).
2. Check out this branch, keep your `mailcow.conf`. Change `SQL_PORT` to `127.0.0.1:15432` (or run `update.sh`).
3. Keep the old MariaDB volume around and start it with the old compose file
   (`docker compose -f docker-compose.yml.old up -d mysql-mailcow`) or restore the dump into a temporary MariaDB.
4. Start the new database and API once: `docker compose up -d postgres-mailcow redis-mailcow api-mailcow`
   (the API creates the schema).
5. Copy the data: `python3 helper-scripts/migrate-mysql-to-postgres.py --mysql-password ... --pg-password ...`.
6. `docker compose up -d`. Redis (DKIM keys, rate limits, fail2ban, quarantine settings) is reused as is;
   the mail store (`vmail-vol-1`) is untouched.

Renamed columns (handled by the migration script): `settingsmap.desc -> description`, `logs.user -> username`,
`quarantine.user -> username`, camelCase columns of `tfa`/`fido2` are lower case.

## API

The JSON API keeps the mailcow layout so existing scripts keep working:

```
GET  /api/v1/get/domain/all            X-API-Key: ...
POST /api/v1/add/mailbox               {"local_part": "x", "domain": "example.org", "password": "...", "password2": "...", "quota": 1024, "active": 1}
POST /api/v1/edit/mailbox              {"items": ["x@example.org"], "attr": {"quota": 2048}}
POST /api/v1/delete/mailbox            ["x@example.org"]
```

Browser sessions use `POST /api/v1/login`, `POST /api/v1/login/tfa`, `POST /api/v1/logout` and must send the
`X-CSRF-Token` header (the token comes back in every response header / `GET /api/v1/session`).

Categories implemented: domain, mailbox, alias, alias-domain, admin, domain-admin, app-passwd, user-acl, da-acl,
dkim (add/duplicate/import/delete), fail2ban, passwordpolicy, rl-domain, rl-mbox, relayhost, transport, bcc,
recipient_map, tls-policy-map, rsetting, rspamd-map, fwdhost, quarantine (list/details/delete/release + settings),
tls-policy, quarantine_notification, quarantine_category, spam-score, last-login, logs, status, template, tfa, api.

## Not ported (yet)

These PHP features have no Python counterpart in this branch; the database tables exist so nothing is lost:

* Sync jobs (imapsync) management UI/API (`imapsync` table; the Dovecot runner works with existing rows)
* Sieve filter management, time limited (spam) aliases, resources, domain wide footers, pushover settings UI,
  mailbox/domain templates management, quota notification settings, UI customisation and translations
* Keycloak / LDAP / generic OIDC identity providers (mailboxes with `authsource != mailcow` cannot log in)
* OAuth2 provider endpoints, password reset by e-mail, mailbox rename, EAS device cache reset, mail queue viewer
* MariaDB replication checks in the watchdog (replaced by a PostgreSQL streaming replication check)

## Development

```
cd data/api
pip install -r requirements.txt pytest fakeredis
DBHOST=127.0.0.1 DBPORT=15432 DBUSER=mailcow DBPASS=mailcow REDISHOST=127.0.0.1 REDISPORT=6379 pytest
DEV_MODE=y uvicorn mailcow.main:app --reload      # API docs on /api/docs
```
