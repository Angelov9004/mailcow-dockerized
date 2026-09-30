"""Pure unit tests (no database needed): password schemes, validators, IP ACL."""
from __future__ import annotations

import base64
import hashlib

import pytest

from mailcow.security.passwords import hash_password, verify_hash
from mailcow.validators import (
    api_key_token,
    idn_to_ascii,
    ip_acl,
    is_email,
    is_username,
    is_valid_domain_name,
    split_list,
    strip_plus_tag,
    to_int,
    valid_hostname,
    valid_network,
)


@pytest.mark.parametrize("scheme", ["BLF-CRYPT", "SSHA", "SSHA256", "SSHA512", "ARGON2ID"])
def test_hash_roundtrip(scheme):
    h = hash_password("Sup3r-Secret!", scheme)
    assert h.startswith("{" + ("ARGON2ID" if scheme == "ARGON2ID" else scheme) + "}")
    assert verify_hash(h, "Sup3r-Secret!")
    assert not verify_hash(h, "Sup3r-Secret")
    assert not verify_hash(h, "")


def test_bcrypt_uses_php_compatible_prefix():
    assert hash_password("x", "BLF-CRYPT").startswith("{BLF-CRYPT}$2y$10$")


def test_prehashed_password_is_stored_verbatim():
    assert hash_password("{SSHA256}abc") == "{SSHA256}abc"


def test_default_admin_hash_from_upstream():
    assert verify_hash("{SSHA256}K8eVJ6YsZbQCfuJvSUbaQRLr0HPLz5rC9IAp0PAFl0tmNDBkMDc0NDAyOTAxN2Rk", "moohoo")
    assert not verify_hash("{SSHA256}K8eVJ6YsZbQCfuJvSUbaQRLr0HPLz5rC9IAp0PAFl0tmNDBkMDc0NDAyOTAxN2Rk", "moohoo ")


def test_legacy_schemes():
    assert verify_hash("{PLAIN}secret", "secret")
    assert verify_hash("{PLAIN-MD5}" + hashlib.md5(b"secret").hexdigest(), "secret")
    assert verify_hash("{SHA256}" + base64.b64encode(hashlib.sha256(b"secret").digest()).decode(), "secret")
    assert verify_hash("{LDAP-MD5}" + base64.b64encode(hashlib.md5(b"secret").digest()).decode(), "secret")
    assert verify_hash("{PLAIN-TRUNC}3-sec", "secret")
    rounds, salt = 5000, "saltsalt"
    pbk = hashlib.pbkdf2_hmac("sha1", b"secret", salt.encode(), rounds).hex()
    assert verify_hash(f"{{PBKDF2}}$1${salt}${rounds}${pbk}", "secret")
    # dovecot "doveadm pw -s SHA512-CRYPT"
    assert verify_hash("{SHA512-CRYPT}$6$rounds=5000$saltsalt$", "x") is False


def test_malformed_hashes_never_verify():
    assert not verify_hash("", "x")
    assert not verify_hash(None, "x")
    assert not verify_hash("nobraces", "x")
    assert not verify_hash("{UNKNOWN}abc", "x")
    assert not verify_hash("{SSHA}not-base64!!", "x")


def test_validators():
    assert is_email("john.doe@example.org")
    assert not is_email("john@localhost")
    assert not is_email("not an email")
    assert is_username("admin_user.1-x")
    assert not is_username("admin user")
    assert is_valid_domain_name("mail.example.org")
    assert not is_valid_domain_name("localhost")
    assert not is_valid_domain_name("-bad.example.org")
    assert idn_to_ascii("bücher.example") == "xn--bcher-kva.example"
    assert valid_network("10.0.0.0/8") and valid_network("2001:db8::1") and not valid_network("10.0.0.256")
    assert valid_hostname("mail.example.org") and not valid_hostname("bad host")
    assert split_list("a, b;c\nd  e") == ["a", "b", "c", "d", "e"]
    assert strip_plus_tag("user+tag@example.org") == "user@example.org"
    assert to_int("12abc") == 12 and to_int(None) == 0 and to_int("") == 0
    assert len(api_key_token()) == 34


def test_ip_acl():
    assert ip_acl("10.1.2.3", ["10.0.0.0/8"])
    assert ip_acl("192.168.1.1", ["192.168.1.1"])
    assert not ip_acl("192.168.1.2", ["192.168.1.1"])
    assert not ip_acl("10.1.2.3", ["11.0.0.0/8", "garbage"])
    assert ip_acl("2001:db8::5", ["2001:db8::/32"])
    assert not ip_acl("not-an-ip", ["0.0.0.0/0"])
