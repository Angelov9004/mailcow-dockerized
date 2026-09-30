"""Runtime configuration, read from the environment (mailcow.conf via docker compose).

Mirrors data/web/inc/vars.inc.php. Anything that used to live in vars.local.inc.php
can be overridden with environment variables prefixed MAILCOW_UI_ (see below).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _yes(val: str | None, default: bool = False) -> bool:
    if val is None or val == "":
        return default
    return val.strip().lower() in ("y", "yes", "1", "true")


def _port(val: str | None, default: int) -> int:
    if not val:
        return default
    # values may be "127.0.0.1:993" or "993"
    tail = val.rsplit(":", 1)[-1]
    digits = "".join(ch for ch in tail if ch.isdigit())
    return int(digits) if digits else default


@dataclass
class Settings:
    # database
    db_host: str = field(default_factory=lambda: os.getenv("DBHOST", "postgres"))
    db_port: int = field(default_factory=lambda: int(os.getenv("DBPORT", "5432")))
    db_name: str = field(default_factory=lambda: os.getenv("DBNAME", "mailcow"))
    db_user: str = field(default_factory=lambda: os.getenv("DBUSER", "mailcow"))
    db_pass: str = field(default_factory=lambda: os.getenv("DBPASS", ""))
    db_pool_min: int = field(default_factory=lambda: int(os.getenv("DB_POOL_MIN", "1")))
    db_pool_max: int = field(default_factory=lambda: int(os.getenv("DB_POOL_MAX", "10")))

    # redis
    redis_host: str = field(default_factory=lambda: os.getenv("REDIS_SLAVEOF_IP") or os.getenv("REDISHOST", "redis-mailcow"))
    redis_port: int = field(default_factory=lambda: int(os.getenv("REDIS_SLAVEOF_PORT") or os.getenv("REDISPORT", "6379")))
    redis_pass: str = field(default_factory=lambda: os.getenv("REDISPASS", ""))

    # general
    mailcow_hostname: str = field(default_factory=lambda: os.getenv("MAILCOW_HOSTNAME", "mail.example.org"))
    default_pass_scheme: str = field(default_factory=lambda: os.getenv("MAILCOW_PASS_SCHEME", "BLF-CRYPT"))
    ipv4_network: str = field(default_factory=lambda: os.getenv("IPV4_NETWORK", "172.22.1"))
    ipv6_network: str = field(default_factory=lambda: os.getenv("IPV6_NETWORK", "fd4d:6169:6c63:6f77::/64"))
    compose_project_name: str = field(default_factory=lambda: os.getenv("COMPOSE_PROJECT_NAME", "mailcow-dockerized"))
    master: bool = field(default_factory=lambda: _yes(os.getenv("MASTER"), True))
    dev_mode: bool = field(default_factory=lambda: _yes(os.getenv("DEV_MODE")))
    demo_mode: bool = field(default_factory=lambda: _yes(os.getenv("DEMO_MODE")))
    skip_sogo: bool = field(default_factory=lambda: _yes(os.getenv("SKIP_SOGO")))
    skip_clamd: bool = field(default_factory=lambda: _yes(os.getenv("SKIP_CLAMD")))
    allow_admin_email_login: bool = field(default_factory=lambda: _yes(os.getenv("ALLOW_ADMIN_EMAIL_LOGIN")))
    webauthn_only_trusted_vendors: bool = field(default_factory=lambda: _yes(os.getenv("WEBAUTHN_ONLY_TRUSTED_VENDORS")))
    clustermode: str = field(default_factory=lambda: os.getenv("CLUSTERMODE", ""))
    log_lines: int = field(default_factory=lambda: int(os.getenv("LOG_LINES", "9999")))

    # ports (for autoconfig/autodiscover)
    imap_port: int = field(default_factory=lambda: _port(os.getenv("IMAP_PORT"), 143))
    imaps_port: int = field(default_factory=lambda: _port(os.getenv("IMAPS_PORT"), 993))
    pop_port: int = field(default_factory=lambda: _port(os.getenv("POP_PORT"), 110))
    pops_port: int = field(default_factory=lambda: _port(os.getenv("POPS_PORT"), 995))
    smtp_port: int = field(default_factory=lambda: _port(os.getenv("SMTP_PORT"), 25))
    smtps_port: int = field(default_factory=lambda: _port(os.getenv("SMTPS_PORT"), 465))
    submission_port: int = field(default_factory=lambda: _port(os.getenv("SUBMISSION_PORT"), 587))
    sieve_port: int = field(default_factory=lambda: _port(os.getenv("SIEVE_PORT"), 4190))
    https_port: int = field(default_factory=lambda: _port(os.getenv("HTTPS_PORT"), 443))

    # paths
    sogo_sso_pass_file: str = field(default_factory=lambda: os.getenv("SOGO_SSO_PASS_FILE", "/etc/sogo-sso/sogo-sso.pass"))
    rspamd_custom_maps: str = field(default_factory=lambda: os.getenv("RSPAMD_CUSTOM_MAPS", "/rspamd_custom_maps"))
    dockerapi_url: str = field(default_factory=lambda: os.getenv("DOCKERAPI_URL", "https://dockerapi:443"))
    docker_timeout: int = field(default_factory=lambda: int(os.getenv("DOCKER_TIMEOUT", "60")))

    # UI/security knobs (previously vars.inc.php)
    session_lifetime: int = field(default_factory=lambda: int(os.getenv("MAILCOW_UI_SESSION_LIFETIME", "10800")))
    session_cookie_name: str = "MAILCOWSESS"
    otp_label: str = field(default_factory=lambda: os.getenv("MAILCOW_UI_OTP_LABEL", "mailcow UI"))
    show_dkim_priv_keys: bool = field(default_factory=lambda: _yes(os.getenv("MAILCOW_UI_SHOW_DKIM_PRIV_KEYS")))
    split_dkim_255: bool = field(default_factory=lambda: _yes(os.getenv("MAILCOW_UI_SPLIT_DKIM_255")))
    tagging_limit: int = field(default_factory=lambda: int(os.getenv("MAILCOW_UI_TAGGING_LIMIT", "25")))
    pw_reset_token_limit: int = 3
    pw_reset_token_lifetime: int = 15
    show_last_login: bool = True
    webauthn_uv_flag_register: str = "preferred"
    webauthn_uv_flag_login: str = "preferred"
    webauthn_user_present_flag: bool = True
    default_lang: str = "en-gb"

    mailbox_default_attributes: dict = field(
        default_factory=lambda: {
            "tls_enforce_in": False,
            "tls_enforce_out": False,
            "force_pw_update": False,
            "sogo_access": True,
            "quarantine_notification": "hourly",
            "imap_access": True,
            "pop3_access": True,
            "smtp_access": True,
            "sieve_access": True,
            "quarantine_category": "reject",
            "mailbox_format": "maildir:",
        }
    )

    rspamd_maps: dict = field(
        default_factory=lambda: {
            "regex": {
                "Header-From: Blacklist": "global_mime_from_blacklist.map",
                "Header-From: Whitelist": "global_mime_from_whitelist.map",
                "Envelope Sender Blacklist": "global_smtp_from_blacklist.map",
                "Envelope Sender Whitelist": "global_smtp_from_whitelist.map",
                "Recipient Blacklist": "global_rcpt_blacklist.map",
                "Recipient Whitelist": "global_rcpt_whitelist.map",
                "Fishy TLDS (only fired in combination with bad words)": "fishy_tlds.map",
                "Bad Words (only fired in combination with fishy TLDs)": "bad_words.map",
                "Bad Words DE (only fired in combination with fishy TLDs)": "bad_words_de.map",
                "Bad Languages": "bad_languages.map",
                "Bulk Mail Headers": "bulk_header.map",
                "Bad (Junk) Mail Headers": "bad_header.map",
                "Monitoring Hosts": "monitoring_nolog.map",
            }
        }
    )

    @property
    def dsn(self) -> str:
        return (
            f"host={self.db_host} port={self.db_port} dbname={self.db_name} "
            f"user={self.db_user} password={self.db_pass} application_name=mailcow-api"
        )

    @property
    def sogo_ip(self) -> str:
        return f"{self.ipv4_network}.248"


settings = Settings()
