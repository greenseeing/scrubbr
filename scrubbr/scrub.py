import ipaddress
from collections import Counter

from pydantic import BaseModel, ConfigDict

from scrubbr.alias import AliasBook
from scrubbr.detect import detect
from scrubbr.identity import SYSTEM_USERNAMES, LocalIdentity
from scrubbr.kinds import Finding, Kind, Residual
from scrubbr.residual import find_residuals
from scrubbr.shapes import (
    DOCUMENTATION_V4,
    DOCUMENTATION_V6,
    classify,
    embedded_mac,
    is_reserved_mac,
    to_eui64,
)

NO_IDENTITY = LocalIdentity()

MIN_UNRESOLVED_GROUPS = 6
MANUAL_IID_MAX = 0xFFFF


class ScrubResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    text: str
    findings: list[Finding]
    residuals: list[Residual]
    counts: dict[Kind, int]


def scrub(
    text: str, identity: LocalIdentity = NO_IDENTITY, book: AliasBook | None = None
) -> ScrubResult:
    if book is None:
        book = AliasBook()
    findings, replacements, unresolved = _sweep(text, identity, (), book)

    # A value found behind a keyword has to be scrubbed everywhere else it appears too,
    # or `psk=hunter2` is rewritten while the bare `hunter2` two lines down survives.
    promoted = tuple(
        {(f.text, f.kind) for f in findings if f.kind in {Kind.SECRET_VALUE, Kind.SSID}}
    )
    if promoted:
        findings, replacements, unresolved = _sweep(text, identity, promoted, book)

    out, written = _splice(text, replacements)
    counts = Counter(finding.kind for finding in _distinct(findings))
    return ScrubResult(
        text=out,
        findings=findings,
        residuals=find_residuals(out, written, unresolved),
        counts=dict(counts),
    )


def _sweep(
    text: str,
    identity: LocalIdentity,
    promoted: tuple[tuple[str, Kind], ...],
    book: AliasBook,
) -> tuple[list[Finding], list[tuple[int, int, str]], list[str]]:
    findings: list[Finding] = []
    replacements: list[tuple[int, int, str]] = []
    unresolved: list[str] = []

    for match in detect(text, identity, promoted):
        kind = _by_shape(match.kind, match.text)
        if kind is Kind.IPV6 and not _parses_as_ipv6(match.text):
            # Colon-hex that is neither a MAC, a fingerprint nor a valid address. Leave it
            # alone, but say so: silently passing it through is how things leak. Only runs
            # at least as long as a MAC qualify, or every "22:20:36" in the timestamp
            # column gets reported and the warning stops being read.
            if match.text.count(":") + 1 >= MIN_UNRESOLVED_GROUPS:
                unresolved.append(match.text)
            continue
        replacement = _replacement(kind, match.text, book)
        if replacement is None:
            continue
        findings.append(Finding(kind=kind, start=match.start, end=match.end, text=match.text))
        replacements.append((match.start, match.end, replacement))
    return findings, replacements, unresolved


def _by_shape(kind: Kind, text: str) -> Kind:
    """What a value *is*, regardless of which rule happened to find it.

    Aliases are pooled per kind, so a secret caught behind `psk=` must land in the same
    pool as the identical value caught bare — otherwise one value gets two replacements
    and the log stops correlating.

    Every shape classify() can return is a kind that is *always* replaced. That is the
    whole rule: a value must never be reclassified into a kind that owns an allowlist, or
    the allowlist starts deciding the fate of something it was never written to judge.
    Routing 8-group fingerprints to IPV6 for pooling did exactly that and silently
    stopped scrubbing them, because most of the IPv6 space reads as reserved.
    """
    if kind is not Kind.SECRET_VALUE:
        return kind
    return classify(text) or kind


def _parses_as_ipv6(text: str) -> bool:
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


def _distinct(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[Kind, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.kind, finding.text.lower())
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def _splice(
    text: str, replacements: list[tuple[int, int, str]]
) -> tuple[str, list[tuple[int, int]]]:
    out: list[str] = []
    written: list[tuple[int, int]] = []
    cursor = 0
    length = 0
    for start, end, value in replacements:
        gap = text[cursor:start]
        out.append(gap)
        length += len(gap)
        written.append((length, length + len(value)))
        out.append(value)
        length += len(value)
        cursor = end
    out.append(text[cursor:])
    return "".join(out), written


def _replacement(kind: Kind, text: str, book: AliasBook) -> str | None:
    """The alias for this value, or None to leave the text exactly as it is."""
    match kind:
        case Kind.MAC:
            if is_reserved_mac(text):
                return None
        case Kind.IPV4:
            if not _should_scrub_v4(text):
                return None
        case Kind.IPV6:
            return _ipv6_replacement(text, book)
        case Kind.USERNAME:
            if text in SYSTEM_USERNAMES:
                return None
    return book.alias_for(kind, text)


def _should_scrub_v4(text: str) -> bool:
    try:
        address = ipaddress.IPv4Address(text)
    except ValueError:
        return False
    if any(address in network for network in DOCUMENTATION_V4):
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_multicast
        or address.is_reserved
        or address.is_link_local
        or address.is_unspecified
    )


def _ipv6_replacement(text: str, book: AliasBook) -> str | None:
    try:
        address = ipaddress.IPv6Address(text)
    except ValueError:
        return None

    if address.is_link_local:
        identifier = int.from_bytes(address.packed[8:], "big")
        if identifier <= MANUAL_IID_MAX:
            # fe80::1 and friends are hand-assigned and name nobody; keeping them
            # preserves the useful fact that the traffic never left the segment.
            return None
        embedded = embedded_mac(address)
        if embedded is not None:
            alias = bytes.fromhex(book.canonical_alias(Kind.MAC, embedded.hex()))
            return f"fe80::{to_eui64(alias)}"
        # Native EUI-64, or an RFC 7217 opaque identifier. Neither carries the ff:fe
        # marker, and an opaque identifier is stable per network -- it fingerprints the
        # machine just as well as the hardware address does.
        return f"fe80::{book.canonical_alias(Kind.LINK_LOCAL_ID, f'{identifier:016x}')}"

    if (
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_reserved
        or address in DOCUMENTATION_V6
    ):
        return None
    # A routable prefix is itself identifying, so these are aliased whole rather than
    # having only their interface identifier rewritten.
    return book.alias_for(Kind.IPV6, text)
