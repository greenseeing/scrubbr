import ipaddress
from collections import Counter
from collections.abc import Mapping
from types import MappingProxyType

from pydantic import BaseModel, ConfigDict

from scrubbr.alias import AliasBook
from scrubbr.detect import detect
from scrubbr.identity import SYSTEM_USERNAMES, LocalIdentity
from scrubbr.kinds import Disposition, Finding, Kind, Residual
from scrubbr.residual import find_residuals
from scrubbr.shapes import (
    DOCUMENTATION_V4,
    DOCUMENTATION_V6,
    IPV4_POOL_SIZE,
    classify,
    embedded_ids,
    embedded_mac,
    is_reserved_mac,
    is_synthetic,
    to_eui64,
)

NO_IDENTITY = LocalIdentity()

MIN_UNRESOLVED_GROUPS = 6
MANUAL_IID_MAX = 0xFFFF

_NO_KEEP: frozenset[tuple[Kind, str]] = frozenset()
_NO_OVERRIDES: Mapping[tuple[Kind, str], str] = MappingProxyType({})


def decision_key(kind: Kind, text: str) -> tuple[Kind, str]:
    """One key per distinct value — the same case-insensitive identity _distinct uses."""
    return (kind, text.lower())


class ScrubResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    text: str
    findings: list[Finding]
    residuals: list[Residual]
    counts: dict[Kind, int]


def scrub(
    text: str,
    identity: LocalIdentity = NO_IDENTITY,
    book: AliasBook | None = None,
    *,
    keep: frozenset[tuple[Kind, str]] = _NO_KEEP,
    overrides: Mapping[tuple[Kind, str], str] = _NO_OVERRIDES,
) -> ScrubResult:
    if book is None:
        book = AliasBook()
    findings, replacements, warnings = _sweep(text, identity, (), book, keep, overrides)

    promoted = _promotions(findings)
    if promoted:
        findings, replacements, warnings = _sweep(
            text, identity, promoted, book, keep, overrides
        )

    out, written = _splice(text, replacements)
    residuals = find_residuals(out, written, warnings)
    residuals.extend(_pool_overflow(book))
    counts = Counter(finding.kind for finding in _distinct(findings))
    return ScrubResult(
        text=out,
        findings=findings,
        residuals=residuals,
        counts=dict(counts),
    )


def _promotions(findings: list[Finding]) -> tuple[tuple[str, Kind], ...]:
    """Values a first pass confirmed that a second pass must catch wherever they appear.

    A secret found behind a keyword (`psk=hunter2`) has to be scrubbed at its bare
    occurrences too, or the labelled copy is rewritten while the bare one two lines down
    survives. A value the CALLER declared (--also / --also-host / -person / -project) that
    WRAPS an id (`--name=<kid>.pem`) is the same problem one level down: the wrapper scrubs
    its own occurrence, so the id it carries is pulled out and scrubbed everywhere else as
    well. Both are additive -- the first-pass matches still stand, this only ever scrubs
    more -- and deriving them from the kept-filtered findings is what makes keeping a value
    also un-promote its bare occurrences.

    Extraction is keyed on `forced` (caller-declared), not on a kind: the same wrapper leak
    reaches through every declaration flag, and `--also-project 'proj-<kid>-prod'` classifies
    HOSTNAME/PERSON/PROJECT rather than REDACTED. It is deliberately NOT applied to
    shape-detected findings -- an opaque provider token that happens to contain a hex run
    carries no caller assertion that the run is a reusable id, so scrubbing every bare copy of
    it would destroy correlation data the tool exists to preserve.

    The wrapper and the id it carries are distinct values, so they mint distinct surrogates
    (`redacted-a` for `--name=<kid>.pem`, `redacted-b` for the bare id). That costs a little
    correlation in the output; sharing one alias would mean aliasing the wrapper by its
    embedded id, which no longer holds for a wrapper carrying two. Nothing leaks either way,
    and the review picker now offers the bare id directly, so the common path is one alias.
    """
    promoted: set[tuple[str, Kind]] = set()
    for finding in findings:
        if finding.kind in {Kind.SECRET_VALUE, Kind.SSID}:
            promoted.add((finding.text, finding.kind))
        elif finding.forced:
            promoted.update((core, Kind.REDACTED) for core in embedded_ids(finding.text))
    return tuple(promoted)


def _pool_overflow(book: AliasBook) -> list[Residual]:
    """Warn once the IPv4 documentation pool has run out of distinct addresses.

    RFC 5737 gives only 762 usable documentation hosts. Beyond that the pool wraps, so
    two distinct source addresses can share one alias -- say so rather than let the log
    quietly stop correlating.
    """
    overflow = book.issued(Kind.IPV4) - IPV4_POOL_SIZE
    if overflow <= 0:
        return []
    return [
        Residual(
            line=1,
            text=f"{overflow} address(es) past the {IPV4_POOL_SIZE}-address documentation pool",
            reason="ipv4 documentation alias pool exhausted; aliases may repeat",
        )
    ]


def _sweep(
    text: str,
    identity: LocalIdentity,
    promoted: tuple[tuple[str, Kind], ...],
    book: AliasBook,
    keep: frozenset[tuple[Kind, str]],
    overrides: Mapping[tuple[Kind, str], str],
) -> tuple[list[Finding], list[tuple[int, int, str]], list[tuple[str, str]]]:
    findings: list[Finding] = []
    replacements: list[tuple[int, int, str]] = []
    warnings: list[tuple[str, str]] = []
    # Values a scrub decision has already been made for: a keyword-confirmed secret to scrub
    # everywhere (promotion), or one the caller declared. Either outranks a WARN-tier match.
    demanded = {value.lower() for value, _ in promoted}
    demanded |= {value.lower() for value in identity.extra}
    demanded |= {value.lower() for value, _ in identity.roles}

    for match in detect(text, identity, promoted):
        if not match.forced and is_synthetic(match.text):
            # Our own minted secret/email surrogate, seen again on a re-scrub. Keep it
            # verbatim so a second pass is a fixed point. A value the caller explicitly
            # declared (--also) is never skipped here: an intentional request always wins.
            continue
        kind = _by_shape(match.kind, match.text)
        if kind is Kind.IPV6 and not _parses_as_ipv6(match.text):
            # Colon-hex that is neither a MAC, a fingerprint nor a valid address. Leave it
            # alone, but say so: silently passing it through is how things leak. Only runs
            # at least as long as a MAC qualify, or every "22:20:36" in the timestamp
            # column gets reported and the warning stops being read.
            if match.text.count(":") + 1 >= MIN_UNRESOLVED_GROUPS:
                warnings.append((match.text, "unrecognized structure"))
            continue
        key = decision_key(kind, match.text)
        override = overrides.get(key)
        if match.disposition is Disposition.WARN and not (
            override or match.text.lower() in demanded
        ):
            # Distinctive enough to flag but too collision-prone to rewrite on its own:
            # surface it in the same warning channel as the residual net. An explicit scrub
            # decision -- a review override, a promotion, or --also -- overrides the warning
            # so a confirmed secret can never be scrubbed in one place and left in another.
            warnings.append((match.text, match.reason or "flagged for review"))
            continue
        if key in keep:
            continue
        replacement = override or _replacement(kind, match.text, book, match.forced)
        if replacement is None:
            continue
        if text[match.start : match.start + len(replacement)] == replacement:
            # This occurrence is already exactly its own alias -- a declared stem literal
            # sitting inside its surrogate (redacted inside redacted-a). Re-splicing would
            # grow redacted-a-a; leaving it is the fixed point. Bound to the actual minted
            # alias, so an unrelated compound that merely looks like a label (user-alice)
            # is still scrubbed.
            continue
        findings.append(
            Finding(
                kind=kind,
                start=match.start,
                end=match.end,
                text=match.text,
                alias=replacement,
                disposition=Disposition.SCRUB,
                forced=match.forced,
            )
        )
        replacements.append((match.start, match.end, replacement))
    return findings, replacements, warnings


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


def _replacement(kind: Kind, text: str, book: AliasBook, forced: bool = False) -> str | None:
    """The alias for this value, or None to leave the text exactly as it is.

    A forced value -- one the caller declared via --also -- only ever flips keep
    decisions to scrub; it never changes how an already-scrubbed value is scrubbed.
    """
    match kind:
        case Kind.MAC:
            if is_reserved_mac(text):
                return None
        case Kind.IPV4:
            if not forced and not _should_scrub_v4(text):
                return None
        case Kind.IPV6:
            replacement = _ipv6_replacement(text, book)
            if replacement is None and forced:
                return book.alias_for(Kind.IPV6, text)
            return replacement
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
