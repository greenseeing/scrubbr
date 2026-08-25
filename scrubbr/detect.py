import re
from dataclasses import dataclass
from functools import lru_cache

from scrubbr.identity import LocalIdentity
from scrubbr.kinds import Disposition, Kind
from scrubbr.shapes import EMAIL_PATTERN, HEX_PATTERN, UUID_PATTERN, classify_literal

# An RSA-8192 key is around 12 KB of base64, so this fits any real key while keeping an
# unterminated BEGIN marker from backtracking across the whole file.
PEM_MAX_BODY = 20_000

NO_IDENTITY = LocalIdentity()

SECRET_KEYWORDS = (
    "psk",
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
    "client_secret",
    "private_key",
)


@dataclass(frozen=True)
class Rule:
    name: str
    kind: Kind
    pattern: str
    value_group: str | None = None
    forced: bool = False
    disposition: Disposition = Disposition.SCRUB
    # Shown in the review when the rule only WARNs, explaining why a match is flagged but
    # left in place.
    warn_reason: str | None = None


@dataclass(frozen=True)
class Match:
    kind: Kind
    start: int
    end: int
    text: str
    forced: bool = False
    disposition: Disposition = Disposition.SCRUB
    reason: str | None = None


# Distinctive-prefix provider credentials, tried ahead of everything else. Each is
# well-specified (fixed prefix + validated length/charset), which is the gate for SCRUB;
# a shape too collision-prone to auto-rewrite is downgraded to WARN, never suppressed.
# Public identifiers that merely share a shape (Stripe pk_, Twilio AC) get no rule at all.
PROVIDER_RULES: tuple[Rule, ...] = (
    # GitHub PAT / OAuth: fixed prefix + 36 base62. Classified SECRET_VALUE so the
    # replacement is a shape-preserving random string, never a readable or deterministic
    # alias -- a deterministic alias of a real secret would be a confirmation oracle.
    Rule(
        "github_token",
        Kind.SECRET_VALUE,
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b",
        disposition=Disposition.SCRUB,
    ),
    # Twilio API key: SK + 32 hex. The 32-hex tail collides with MD5 digests and IDs that
    # fill ordinary logs, so it is flagged for review rather than auto-scrubbed.
    Rule(
        "twilio_sk",
        Kind.SECRET_VALUE,
        r"\bSK[0-9a-fA-F]{32}\b",
        disposition=Disposition.WARN,
        warn_reason="possible twilio api key (32-hex; not auto-scrubbed)",
    ),
)

# Ordered most-specific first. Alternation resolves precedence: at any position the
# earliest alternative that matches wins, which is what makes the colon-hex family
# (fingerprint / MAC / IPv6) disambiguate correctly.
STRUCTURAL_RULES: tuple[Rule, ...] = (
    Rule(
        "pem",
        Kind.PEM,
        # The body stays a wildcard on purpose. Narrowing it to the base64 alphabet would
        # make one stray character anywhere in the block fail the whole alternative and
        # pass the key through verbatim; the length bound alone removes the backtracking.
        r"-----BEGIN [A-Z0-9 ._-]{0,100}-----"
        rf"(?P<pem_body>[\s\S]{{0,{PEM_MAX_BODY}}}?)"
        r"-----END [A-Z0-9 ._-]{0,100}-----",
        value_group="pem_body",
    ),
    # A log cut off mid-key has a BEGIN marker and no END. The complete rule above is
    # tried first, so this only ever fires on a truncated block -- without it the key body
    # matches nothing at all and survives verbatim, which truncated diagnostics make common.
    Rule(
        "pem_truncated",
        Kind.PEM,
        r"-----BEGIN [A-Z0-9 ._-]{0,100}-----"
        rf"(?P<pem_open>(?:\r?\n[A-Za-z0-9+/=]{{16,80}}){{1,{PEM_MAX_BODY // 16}}})",
        value_group="pem_open",
    ),
    Rule(
        "crypt_hash",
        Kind.CRYPT_HASH,
        r"\$(?:1|5|6|2[aby]|apr1)\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{20,90}",
    ),
    Rule("jwt", Kind.JWT, r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*"),
    Rule("disk_id", Kind.DISK_ID, r"/dev/disk/by-id/(?P<disk_id_val>[A-Za-z0-9._:+-]+)",
         value_group="disk_id_val"),
    # 8+ colon-hex groups: a digest fingerprint, never a MAC.
    Rule(
        "fingerprint",
        Kind.FINGERPRINT,
        r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){7,}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])",
    ),
    Rule("uuid", Kind.UUID, rf"(?<![0-9A-Fa-f-]){UUID_PATTERN}(?![0-9A-Fa-f-])"),
    # Exactly six 2-digit groups with a consistent separator, fenced by lookarounds so it
    # cannot bite a slice out of a longer colon-hex chain.
    # One rule per separator rather than one rule with a backreferenced separator: each
    # fence then excludes only its OWN separator, so a colon-separated address is still
    # found in "aa:bb:cc:dd:ee:ff-eth0" and "wlan0-aa:bb:cc:dd:ee:ff", while a
    # hyphen-separated one is still fenced off from a longer hyphenated run.
    Rule(
        "mac_colon",
        Kind.MAC,
        r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])",
    ),
    Rule(
        "mac_hyphen",
        Kind.MAC,
        r"(?<![0-9A-Fa-f-])(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f-])",
    ),
    # A trailing dot only disqualifies the dotted form when more hex follows it.
    Rule(
        "mac_cisco",
        Kind.MAC,
        r"(?<![0-9A-Fa-f])(?<![0-9A-Fa-f]\.)"
        r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}"
        r"(?![0-9A-Fa-f])(?!\.[0-9A-Fa-f])",
    ),
    # Bare 12-hex is only a MAC when something says so; on its own it is indistinguishable
    # from a truncated hash, and scrubbing every 12-hex run would wreck ordinary logs.
    Rule(
        "mac_bare",
        Kind.MAC,
        r"(?i:mac|hwaddr|hw_addr|bssid|ether|lladdr|hw)(?:\s+address)?\s*[=:]?\s*"
        r"(?P<mac_bare_val>[0-9A-Fa-f]{12})(?![0-9A-Za-z])",
        value_group="mac_bare_val",
    ),
    # Ahead of the identity literals: a username is usually the local part of its owner's
    # address, and letting the literal win would rewrite "dev@example.com" to
    # "user-a@example.com", keeping the domain — normally the more identifying half.
    Rule("email", Kind.EMAIL, EMAIL_PATTERN),
)

CONTEXTUAL_RULES: tuple[Rule, ...] = (
    Rule(
        "ssid",
        Kind.SSID,
        r"(?i:ssid)\s*[=:]\s*(?P<ssid_q>[\"'])(?P<ssid_val>[^\"']*)(?P=ssid_q)",
        value_group="ssid_val",
    ),
    Rule(
        "secret_kv",
        Kind.SECRET_VALUE,
        r"(?i:" + "|".join(SECRET_KEYWORDS) + r")\s*[=:]\s*"
        r"(?P<secret_q>[\"']?)(?P<secret_val>[^\s\"',;]+)(?P=secret_q)",
        value_group="secret_val",
    ),
    Rule(
        "home_path",
        Kind.USERNAME,
        r"/home/(?P<home_user>[a-z_][a-z0-9_-]{0,31})",
        value_group="home_user",
    ),
    Rule(
        "ipv6",
        Kind.IPV6,
        r"(?<![0-9A-Fa-f:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])",
    ),
    Rule("ipv4", Kind.IPV4, r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])"),
    Rule(
        "hex",
        Kind.HEX,
        rf"(?<![0-9A-Za-z])(?:0[xX])?(?P<hex_val>{HEX_PATTERN})(?![0-9A-Za-z])",
        value_group="hex_val",
    ),
)


def _literal_rules(
    identity: LocalIdentity, promoted: tuple[tuple[str, Kind], ...]
) -> tuple[Rule, ...]:
    # value, kind, forced, fold_case
    literals: list[tuple[str, Kind, bool, bool]] = []
    if identity.hostname:
        literals.append((identity.hostname, Kind.HOSTNAME, False, False))
        short = identity.hostname.split(".")[0]
        if short != identity.hostname:
            literals.append((short, Kind.HOSTNAME, False, False))
    # An extra value is explicitly declared, so it is scrubbed unconditionally -- forced
    # past the keep-allowlists that judge only incidental matches.
    literals.extend((value, classify_literal(value), True, False) for value in identity.extra)
    # A role hint carries its surrogate kind explicitly and folds case, so alice/Alice/ALICE
    # collapse to one person-a rather than shape-classifying to a generic redacted-*.
    literals.extend((value, kind, True, True) for value, kind in identity.roles)
    if identity.username:
        literals.append((identity.username, Kind.USERNAME, False, False))
    literals.extend((value, kind, False, False) for value, kind in promoted)
    # Longest first: a username is frequently a substring of the hostname ("dev" inside
    # "dev-thinkpad"), and the longer match has to win at that position.
    literals.sort(key=lambda entry: len(entry[0]), reverse=True)
    return tuple(
        Rule(f"literal_{index}", kind, _literal_pattern(value, kind, fold_case), forced=forced)
        for index, (value, kind, forced, fold_case) in enumerate(literals)
    )


def _literal_pattern(value: str, kind: Kind, fold_case: bool = False) -> str:
    escaped = re.escape(value)
    if kind is Kind.IPV6 or fold_case:
        # Forcing must survive the log spelling FE80::1 as fe80::1, or a role hint's name
        # appearing in a different case than it was declared.
        escaped = f"(?i:{escaped})"
    return rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])"


@lru_cache(maxsize=64)
def _compiled(
    identity: LocalIdentity, promoted: tuple[tuple[str, Kind], ...]
) -> tuple[re.Pattern[str], dict[str, Rule]]:
    rules = (
        PROVIDER_RULES
        + STRUCTURAL_RULES
        + _literal_rules(identity, promoted)
        + CONTEXTUAL_RULES
    )
    combined = "|".join(f"(?P<{rule.name}>{rule.pattern})" for rule in rules)
    return re.compile(combined), {rule.name: rule for rule in rules}


def detect(
    text: str,
    identity: LocalIdentity = NO_IDENTITY,
    promoted: tuple[tuple[str, Kind], ...] = (),
) -> list[Match]:
    """Locate everything worth replacing.

    `promoted` carries values a first pass discovered behind a keyword — `psk=secret` —
    so that a second pass also catches them where they appear bare and unlabelled.
    """
    pattern, by_name = _compiled(identity, promoted)
    matches: list[Match] = []
    for found in pattern.finditer(text):
        # lastgroup is always the winning rule's own group: value groups nested inside an
        # alternative close before the group that encloses them.
        name = found.lastgroup
        if name is None:
            raise AssertionError("a match must belong to exactly one rule")
        rule = by_name[name]
        group = rule.value_group or rule.name
        start, end = found.span(group)
        if start < 0 or start == end:
            continue
        matches.append(
            Match(
                kind=rule.kind,
                start=start,
                end=end,
                text=text[start:end],
                forced=rule.forced,
                disposition=rule.disposition,
                reason=rule.warn_reason,
            )
        )
    return matches
