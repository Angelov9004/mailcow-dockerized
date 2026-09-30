"""Password hashing and verification, compatible with Dovecot password schemes.

Port of hash_password() / verify_hash() / verify_salted_hash() from functions.inc.php.
Every scheme the PHP code accepted is accepted here, and hashes produced here are
readable by Dovecot and SOGo unchanged.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets

import bcrypt

try:  # argon2 is optional but recommended
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

    _argon2 = PasswordHasher()
except Exception:  # noqa: BLE001
    _argon2 = None

try:
    from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt, des_crypt
except Exception:  # noqa: BLE001
    md5_crypt = sha256_crypt = sha512_crypt = des_crypt = None

PREHASHED_RE = re.compile(
    r"^\{(ARGON2I|ARGON2ID|BLF-CRYPT|CLEAR|CLEARTEXT|CRYPT|DES-CRYPT|LDAP-MD5|MD5|MD5-CRYPT|PBKDF2|PLAIN|PLAIN-MD4|PLAIN-MD5|PLAIN-TRUNC|SHA|SHA1|SHA256|SHA256-CRYPT|SHA512|SHA512-CRYPT|SMD5|SSHA|SSHA256|SSHA512)\}",
    re.IGNORECASE,
)
HASH_RE = re.compile(r"^\{(.+?)\}(.+)$", re.IGNORECASE | re.DOTALL)


def _salted(algo: str, password: str) -> str:
    salt = secrets.token_hex(8).encode()  # bin2hex(16 random bytes) -> 16 ascii chars like PHP
    digest = hashlib.new(algo, password.encode() + salt).digest()
    return base64.b64encode(digest + salt).decode()


def hash_password(password: str, scheme: str | None = None) -> str:
    """Hash with the configured scheme (MAILCOW_PASS_SCHEME), default BLF-CRYPT.

    Pre-hashed passwords (with a {SCHEME} prefix) are stored unchanged, like PHP.
    """
    if PREHASHED_RE.match(password):
        return password
    scheme = (scheme or os.getenv("MAILCOW_PASS_SCHEME") or "BLF-CRYPT").upper()
    if scheme == "SSHA":
        return "{SSHA}" + _salted("sha1", password)
    if scheme == "SSHA256":
        return "{SSHA256}" + _salted("sha256", password)
    if scheme == "SSHA512":
        return "{SSHA512}" + _salted("sha512", password)
    if scheme in ("ARGON2ID", "ARGON2I") and _argon2 is not None:
        return "{ARGON2ID}" + _argon2.hash(password)
    # BLF-CRYPT default; PHP password_hash(PASSWORD_BCRYPT) uses cost 10 and $2y$ prefix
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=10)).decode()
    if hashed.startswith("$2b$"):
        hashed = "$2y$" + hashed[4:]
    return "{BLF-CRYPT}" + hashed


def _verify_salted_hash(hash_b64: str, password: str, algo: str, digest_len: int) -> bool:
    try:
        raw = base64.b64decode(hash_b64)
    except Exception:  # noqa: BLE001
        return False
    if len(raw) < digest_len:
        return False
    digest, salt = raw[:digest_len], raw[digest_len:]
    calc = hashlib.new(algo, password.encode() + salt).digest()
    return hmac.compare_digest(calc, digest)


def _verify_crypt(hashed: str, password: str) -> bool:
    """PHP password_verify() over crypt(3) style strings."""
    try:
        if hashed.startswith(("$2y$", "$2a$", "$2b$", "$2x$")):
            h = hashed
            if h.startswith("$2y$") or h.startswith("$2x$"):
                h = "$2b$" + h[4:]
            return bcrypt.checkpw(password.encode(), h.encode())
        if hashed.startswith("$argon2"):
            if _argon2 is None:
                return False
            try:
                return _argon2.verify(hashed, password)
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                return False
        if hashed.startswith("$6$") and sha512_crypt is not None:
            return sha512_crypt.verify(password, hashed)
        if hashed.startswith("$5$") and sha256_crypt is not None:
            return sha256_crypt.verify(password, hashed)
        if hashed.startswith("$1$") and md5_crypt is not None:
            return md5_crypt.verify(password, hashed)
        if des_crypt is not None and len(hashed) == 13:
            return des_crypt.verify(password, hashed)
    except (ValueError, TypeError):
        return False
    return False


def verify_hash(hashed: str | None, password: str | None) -> bool:
    """Port of verify_hash(). Returns False for unknown schemes or malformed hashes."""
    if not hashed or password is None:
        return False
    m = HASH_RE.match(hashed)
    if not m:
        return False
    scheme = m.group(1).upper()
    body = m.group(2)

    if scheme in ("ARGON2I", "ARGON2ID", "BLF-CRYPT", "CRYPT", "DES-CRYPT", "MD5-CRYPT", "MD5", "SHA256-CRYPT", "SHA512-CRYPT"):
        return _verify_crypt(body, password)
    if scheme in ("CLEAR", "CLEARTEXT", "PLAIN"):
        return hmac.compare_digest(password.encode(), body.encode())
    if scheme == "LDAP-MD5":
        try:
            return hmac.compare_digest(hashlib.md5(password.encode()).digest(), base64.b64decode(body))  # noqa: S324
        except Exception:  # noqa: BLE001
            return False
    if scheme == "PBKDF2":
        parts = body.split("$")
        if len(parts) < 5:
            return False
        salt, rounds, digest = parts[2], parts[3], parts[4]
        try:
            calc = hashlib.pbkdf2_hmac("sha1", password.encode(), salt.encode(), int(rounds)).hex()
        except ValueError:
            return False
        return hmac.compare_digest(calc, digest)
    if scheme == "PLAIN-MD4":
        try:
            calc = hashlib.new("md4", password.encode()).hexdigest()
        except ValueError:
            return False
        return hmac.compare_digest(calc, body)
    if scheme == "PLAIN-MD5":
        return hmac.compare_digest(hashlib.md5(password.encode()).hexdigest(), body)  # noqa: S324
    if scheme == "PLAIN-TRUNC":
        parts = body.split("-", 1)
        if len(parts) > 1:
            try:
                trunc_len = int(parts[0])
            except ValueError:
                return False
            return hmac.compare_digest(password[:trunc_len].encode(), parts[1].encode())
        return hmac.compare_digest(password.encode(), body.encode())
    if scheme in ("SHA", "SHA1", "SHA256", "SHA512"):
        algo = "sha1" if scheme in ("SHA", "SHA1") else scheme.lower()
        try:
            return hmac.compare_digest(hashlib.new(algo, password.encode()).digest(), base64.b64decode(body))
        except Exception:  # noqa: BLE001
            return False
    if scheme == "SMD5":
        return _verify_salted_hash(body, password, "md5", 16)
    if scheme == "SSHA":
        return _verify_salted_hash(body, password, "sha1", 20)
    if scheme == "SSHA256":
        return _verify_salted_hash(body, password, "sha256", 32)
    if scheme == "SSHA512":
        return _verify_salted_hash(body, password, "sha512", 64)
    return False
