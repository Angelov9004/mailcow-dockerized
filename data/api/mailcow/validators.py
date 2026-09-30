"""Input validators, ported 1:1 from functions.inc.php (valid_network, ip_acl, is_valid_domain_name, ...)."""
from __future__ import annotations

import ipaddress
import re
import secrets
import string

# PHP FILTER_VALIDATE_EMAIL is stricter than RFC 5322; this regex mirrors its practical behaviour:
# local part of printable non-space chars without consecutive dots, domain with at least one dot.
_EMAIL_RE = re.compile(
    r"^(?!\.)(?!.*\.\.)[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}(?<!\.)@"
    r"(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_USERNAME_CHARS = re.compile(r"^[A-Za-z0-9_.\-]+$")
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$")


def is_email(value: str | None) -> bool:
    return bool(value) and bool(_EMAIL_RE.match(value))


def is_username(value: str | None) -> bool:
    """PHP: filter_var(EMAIL) || ctype_alnum(str_replace(['_','.','-'], '', $user))"""
    if not value:
        return False
    return is_email(value) or bool(_USERNAME_CHARS.match(value))


def is_valid_domain_name(domain: str | None) -> bool:
    """Port of is_valid_domain_name(): labels of alnum/-, no leading/trailing -, total <= 253, contains a dot."""
    if not domain:
        return False
    if len(domain) > 253:
        return False
    if not re.match(r"^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$", domain, re.IGNORECASE):
        return False
    if not re.match(r"^.{1,253}$", domain):
        return False
    if not re.match(r"^[^\.]{1,63}(\.[^\.]{1,63})*$", domain):
        return False
    return "." in domain


def idn_to_ascii(domain: str) -> str:
    try:
        return domain.encode("idna").decode("ascii")
    except Exception:  # noqa: BLE001
        return domain


def idn_to_utf8(domain: str) -> str:
    try:
        return domain.encode("ascii").decode("idna")
    except Exception:  # noqa: BLE001
        return domain


def valid_network(network: str | None) -> bool:
    """Port of valid_network(): a single IP or a CIDR network."""
    if not network:
        return False
    try:
        if "/" in network:
            ipaddress.ip_network(network, strict=False)
        else:
            ipaddress.ip_address(network)
        return True
    except ValueError:
        return False


def valid_hostname(hostname: str | None) -> bool:
    return bool(hostname) and bool(_HOSTNAME_RE.match(hostname))


def valid_ip(value: str | None) -> bool:
    try:
        ipaddress.ip_address(value or "")
        return True
    except ValueError:
        return False


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local)


def ip_acl(ip: str, networks: list[str]) -> bool:
    """Port of ip_acl(): True if ip matches any entry (plain IP or CIDR)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for network in networks:
        network = network.strip()
        if not network:
            continue
        try:
            if "/" in network:
                net = ipaddress.ip_network(network, strict=False)
                if addr.version == net.version and addr in net:
                    return True
            else:
                if addr == ipaddress.ip_address(network):
                    return True
        except ValueError:
            continue
    return False


def split_list(value: str | list | None) -> list[str]:
    """PHP: array_map('trim', preg_split('/( |,|;|\\n)/', $x)) + array_filter"""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        items = []
        for v in value:
            items.extend(split_list(v))
        return items
    return [p.strip() for p in re.split(r"[ ,;\n]", str(value)) if p.strip()]


def strip_tags(value: str | None) -> str:
    if value is None:
        return ""
    return re.sub(r"<[^>]*>", "", str(value))


def htmlspecialchars(value: str | None) -> str:
    if value is None:
        return ""
    return (
        str(value)
        .replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def to_int(value, default: int = 0) -> int:
    """PHP intval(): tolerant conversion."""
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            m = re.match(r"^\s*([-+]?\d+)", str(value))
            return int(m.group(1)) if m else default


def readable_random_string(length: int = 8) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def api_key_token() -> str:
    """5 groups of 6 upper hex chars separated by dashes, identical format to PHP."""
    return "-".join(secrets.token_hex(3).upper() for _ in range(5))


def strip_plus_tag(address: str) -> str:
    """preg_replace('/^(.*?)\\+.*(@.*)$/', '$1$2', $rcpt)"""
    return re.sub(r"^(.*?)\+.*(@.*)$", r"\1\2", address)


def parse_email(email: str) -> tuple[str, str] | None:
    if not is_email(email):
        return None
    local, _, domain = email.rpartition("@")
    return local, domain
