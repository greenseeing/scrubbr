import ipaddress
import random
import re
import string

from scrubbr.kinds import Kind

HEX_MIN_CHARS = 32

EMAIL_PATTERN = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
UUID_PATTERN = (
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)
HEX_PATTERN = rf"[0-9A-Fa-f]{{{HEX_MIN_CHARS},}}"

_HEX = re.compile(HEX_PATTERN)
_UUID = re.compile(UUID_PATTERN)
_EMAIL = re.compile(EMAIL_PATTERN)

# RFC 5737 / RFC 3849 documentation ranges: unmistakably fake to anyone reading the log.
# The alias pools and the keep-allowlists derive from the same literals, so the tool can
# never mint an alias that its own allowlist would then treat differently.
IPV4_POOLS = ("203.0.113.", "198.51.100.", "192.0.2.")
IPV6_PREFIX = "2001:db8::"
DOCUMENTATION_V4 = tuple(ipaddress.ip_network(f"{pool}0/24") for pool in IPV4_POOLS)
DOCUMENTATION_V6 = ipaddress.ip_network(f"{IPV6_PREFIX}/32")

RESERVED_MAC_PREFIXES = ("ffff", "01005e", "3333", "0180c2", "00005e", "01000c")

READABLE = {
    Kind.HOSTNAME: "host",
    Kind.USERNAME: "user",
    Kind.SSID: "network",
    Kind.DISK_ID: "disk",
}

BASE64URL = string.ascii_letters + string.digits + "-_"
CRYPT_ALPHABET = "./" + string.ascii_letters + string.digits

_STRIP_SEPARATORS = str.maketrans("", "", ":-.")


def classify(text: str) -> Kind | None:
    """The kind a value's bare shape reads as, regardless of which rule found it."""
    if _HEX.fullmatch(text):
        return Kind.HEX
    if _UUID.fullmatch(text):
        return Kind.UUID
    if _EMAIL.fullmatch(text):
        return Kind.EMAIL
    return None


def classify_literal(text: str) -> Kind:
    """The kind a user-declared literal reads as; REDACTED when its shape says nothing.

    Unlike classify() this may return the IP kinds, which own keep-allowlists — safe only
    because extra-literals are forced past those allowlists in scrub.
    """
    shaped = classify(text)
    if shaped is not None:
        return shaped
    try:
        ipaddress.IPv4Address(text)
        return Kind.IPV4
    except ValueError:
        pass
    try:
        ipaddress.IPv6Address(text)
        return Kind.IPV6
    except ValueError:
        return Kind.REDACTED


def normalize(kind: Kind, text: str) -> str:
    match kind:
        case Kind.MAC:
            return text.lower().translate(_STRIP_SEPARATORS)
        case Kind.UUID:
            return text.lower().replace("-", "")
        case Kind.HEX | Kind.FINGERPRINT | Kind.IPV6:
            return text.lower()
        case _:
            return text


def is_reserved_mac(text: str) -> bool:
    canonical = normalize(Kind.MAC, text)
    return canonical == "000000000000" or canonical.startswith(RESERVED_MAC_PREFIXES)


def mint(kind: Kind, normalized: str, rng: random.Random, index: int) -> str:
    if kind in READABLE:
        return f"{READABLE[kind]}-{_letters(index)}"
    match kind:
        case Kind.MAC:
            return _mint_mac(rng)
        case Kind.UUID:
            return _mint_uuid(rng, normalized)
        case Kind.IPV4:
            pool = IPV4_POOLS[(index // 254) % len(IPV4_POOLS)]
            return f"{pool}{index % 254 + 1}"
        case Kind.IPV6:
            return f"{IPV6_PREFIX}{index + 1:x}"
        case Kind.LINK_LOCAL_ID:
            raw = rng.randbytes(8).hex()
            return ":".join(raw[i : i + 4] for i in range(0, 16, 4))
        case Kind.EMAIL:
            return f"person-{_letters(index)}@example.invalid"
        case Kind.PEM:
            return f"\n[scrubbr: redacted, {len(normalized)} bytes]\n"
        case Kind.HEX:
            return _random_hex(rng, len(normalized), normalized)
        case Kind.FINGERPRINT:
            groups = len(normalized.split(":"))
            return ":".join(rng.randbytes(1).hex() for _ in range(groups))
        case Kind.JWT:
            return ".".join(
                _random_from(rng, BASE64URL, max(len(part), 8))
                for part in normalized.split(".")
            )
        case Kind.CRYPT_HASH:
            head, salt, digest = normalized.rsplit("$", 2)
            return (
                f"{head}${_random_from(rng, CRYPT_ALPHABET, len(salt))}"
                f"${_random_from(rng, CRYPT_ALPHABET, len(digest))}"
            )
        case Kind.SECRET_VALUE:
            if _is_hex(normalized):
                return _random_hex(rng, len(normalized), normalized)
            return _random_from(rng, string.ascii_letters + string.digits, len(normalized))
        case Kind.REDACTED:
            return "[REDACTED]"
    raise AssertionError(f"no minter for {kind}")


def render(kind: Kind, canonical: str, like: str) -> str:
    match kind:
        case Kind.MAC:
            return _format_mac(canonical, like)
        case Kind.UUID:
            return _format_uuid(canonical, like)
        case Kind.HEX | Kind.FINGERPRINT:
            return _match_case(canonical, like)
        case _:
            return canonical


def embedded_mac(address: ipaddress.IPv6Address) -> bytes | None:
    """The MAC hiding in a Modified EUI-64 interface identifier, if there is one.

    SLAAC builds the low 64 bits from the hardware address by splicing ff:fe into the
    middle and flipping the U/L bit, so a link-local address can carry a MAC in full even
    though it looks nothing like one.
    """
    iid = address.packed[8:]
    if iid[3] != 0xFF or iid[4] != 0xFE:
        return None
    return bytes([iid[0] ^ 0x02]) + iid[1:3] + iid[5:8]


def to_eui64(mac: bytes) -> str:
    iid = bytes([mac[0] ^ 0x02]) + mac[1:3] + b"\xff\xfe" + mac[3:6]
    return ":".join(iid.hex()[i : i + 4] for i in range(0, 16, 4))


def _letters(index: int) -> str:
    out = ""
    index += 1
    while index:
        index, rest = divmod(index - 1, 26)
        out = chr(ord("a") + rest) + out
    return out


def _mint_mac(rng: random.Random) -> str:
    raw = bytearray(rng.randbytes(6))
    # Clear I/G (unicast) and set U/L (locally administered). This one mask is also what
    # makes every reserved range unreachable: they are all multicast or universal.
    raw[0] = (raw[0] & 0xFC) | 0x02
    return raw.hex()


def _variant_mask(octet: int) -> int:
    """The width of the variant marker, which RFC 9562 makes depend on its own value.

    NCS uses one bit, the RFC 9562 variant two, and the Microsoft and reserved variants
    three. Copying a fixed two bits would drag a payload bit of an NCS uuid into the alias
    and could not tell the three-bit variants apart.
    """
    if not octet & 0x80:
        return 0x80
    if octet & 0xC0 == 0x80:
        return 0xC0
    return 0xE0


def _mint_uuid(rng: random.Random, like: str) -> str:
    original = bytes.fromhex(like)
    raw = bytearray(rng.randbytes(16))
    raw[6] = (raw[6] & 0x0F) | (original[6] & 0xF0)
    mask = _variant_mask(original[8])
    raw[8] = (raw[8] & ~mask & 0xFF) | (original[8] & mask)
    return raw.hex()


def _match_case(value: str, like: str) -> str:
    return value.upper() if any(c.isupper() for c in like) else value


def _format_mac(canonical: str, like: str) -> str:
    octets = [canonical[i : i + 2] for i in range(0, 12, 2)]
    if "." in like:
        shaped = ".".join(canonical[i : i + 4] for i in range(0, 12, 4))
    elif "-" in like:
        shaped = "-".join(octets)
    elif ":" in like:
        shaped = ":".join(octets)
    else:
        shaped = canonical
    return _match_case(shaped, like)


def _format_uuid(canonical: str, like: str) -> str:
    parts = (canonical[:8], canonical[8:12], canonical[12:16], canonical[16:20], canonical[20:])
    return _match_case("-".join(parts), like)


def _random_hex(rng: random.Random, length: int, like: str) -> str:
    value = rng.randbytes((length + 1) // 2).hex()[:length]
    return _match_case(value, like)


def _random_from(rng: random.Random, alphabet: str, length: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def _is_hex(value: str) -> bool:
    return len(value) >= 8 and all(c in string.hexdigits for c in value)
