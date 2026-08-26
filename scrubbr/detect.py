import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache

from scrubbr.identity import LocalIdentity
from scrubbr.kinds import Disposition, Kind
from scrubbr.shapes import (
    EMAIL_PATTERN,
    HEX_PATTERN,
    UUID_PATTERN,
    classify,
    classify_literal,
    shannon_entropy,
)
from scrubbr.validate import valid_github_token, valid_jwt

# An RSA-8192 key is around 12 KB of base64, so this fits any real key while keeping an
# unterminated BEGIN marker from backtracking across the whole file.
PEM_MAX_BODY = 20_000

NO_IDENTITY = LocalIdentity()

# A bare, ambiguous stem (`token=…`) only scrubs a value that clears BOTH gates, so
# `token=0` / `token=next` are left alone while a real high-entropy value is not.
KEYWORD_VALUE_MIN_LEN = 10
KEYWORD_VALUE_MIN_ENTROPY = 3.5

# Stems whose compound/prefixed form is distinctive enough to scrub any non-empty value.
# Each word boundary inside a stem is an optional [-_] so one entry matches snake_case,
# kebab-case, camelCase and SCREAMING variants under (?i:). A separator-prefixed key such
# as DB_PASSWORD or MYAPP_API_KEY is still caught because the stem then sits right after a
# '_' (see _STEM_BOUNDARY). Ordering among strong stems is irrelevant -- they all scrub the
# same value to the same SECRET_VALUE kind.
STRONG_STEMS: tuple[str, ...] = (
    "passwd",
    "password",
    "passphrase",
    "pwd",
    "psk",
    "client[-_]?secret",
    "secret",
    "api[-_]?key",
    "auth[-_]?key",
    "access[-_]?key",
    "account[-_]?key",
    "service[-_]?key",
    "database[-_]?key",
    "db[-_]?key",
    "priv(?:ate)?[-_]?key",
    "client[-_]?key",
    "access[-_]?token",
    "auth[-_]?token",
    "refresh[-_]?token",
    "bearer",
    "authorization",
    "credentials?",
    "oauth",
    "connection[-_]?string",
    "database[-_]?url",
    "db[-_]?url",
    "database[-_]?pass(?:word)?",
    "db[-_]?pass(?:word)?",
)

# Bare, ambiguous stems: gated on value length AND entropy so ordinary diagnostics
# (`token=0`, `session=idle`) survive but a real secret does not.
GENERIC_STEMS: tuple[str, ...] = ("key", "token", "session", "cert", "connection", "dsn")

# The stem must begin at a segment boundary -- start of a run of letters/digits, or right
# after a separator like '_'/'-'/space. A FIXED-WIDTH negative lookbehind rather than a
# variable-width \w* affix on purpose: it costs O(1) per position, so a pathological
# unbroken word/hex run (which no larger rule consumes) can't wedge the scanner walking it
# position by position. '_' is not in [A-Za-z0-9], so DB_PASSWORD / MYAPP_API_KEY still hit.
_STEM_BOUNDARY = r"(?<![A-Za-z0-9])"


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
    # A gated rule only scrubs a captured value that clears the length+entropy gate; below
    # it the value is left in place (not warned) -- it is ordinary, not a secret.
    gated: bool = False
    # An offline validator (checksum / structural parse). When it fails, the match is
    # DOWNGRADED SCRUB -> WARN -- surfaced, never suppressed -- so a truncated or malformed
    # token in a log is still flagged rather than silently passed.
    validator: Callable[[str], bool] | None = None
    downgrade_reason: str | None = None


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
# Public identifiers that merely share a shape (Stripe pk_, AWS AGPA/AIDA identity ids,
# Twilio AC) get no rule at all. Every entry classifies to SECRET_VALUE so its replacement
# is a shape-preserving random string, never a readable or deterministic alias -- a
# deterministic alias of a real secret would be a confirmation oracle. Adding a provider is
# one line here: the red-team-corrected catalog is the spec (research brief Appendix A.1),
# not the raw survey regexes. Every quantifier is bounded, so no entry can backtrack
# catastrophically on a large adversarial dump.
PROVIDER_RULES: tuple[Rule, ...] = (
    # -- GitHub: 36 base62 (classic) / 82 (fine-grained) after the prefix. The classic token
    #    carries a trailing CRC32; a failing one downgrades to WARN (never dropped). --
    Rule(
        "github_token",
        Kind.SECRET_VALUE,
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b",
        validator=valid_github_token,
        downgrade_reason="github token failed its checksum (truncated or mistyped; still flagged)",
    ),
    Rule("github_pat", Kind.SECRET_VALUE, r"\bgithub_pat_[0-9A-Za-z_]{82}\b"),
    # -- GitLab PAT. A trailing (?!...) fence rather than \b: '-' is in the charset but not
    #    a word char, so \b would FAIL (leaking the token) when the token ends in '-'. --
    Rule("gitlab_pat", Kind.SECRET_VALUE, r"\bglpat-[0-9A-Za-z_-]{20,64}(?![0-9A-Za-z_-])"),
    # -- AWS access key id: base32 tail. Only AKIA/ASIA -- the AGPA/AIDA/AROA/AIPA identity
    #    ids share the length but are public and excluded by construction. --
    Rule("aws_access_key", Kind.SECRET_VALUE, r"\b(?:AKIA|ASIA)[A-Z2-7]{16}\b"),
    # -- Slack bot / user tokens. The bot tail is bounded so a token glued to an adjacent
    #    hyphenated field can only over-consume a bounded amount, never run away. --
    Rule("slack_bot", Kind.SECRET_VALUE, r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]{0,64}"),
    Rule("slack_user", Kind.SECRET_VALUE, r"\bxox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}"),
    # -- Stripe secret / restricted. pk_ (publishable) is public and gets no rule. --
    Rule(
        "stripe_secret",
        Kind.SECRET_VALUE,
        r"\b(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}\b",
    ),
    # -- Google API key (trailing fence, not \b, so a key ending in '-' still matches) --
    Rule("google_api_key", Kind.SECRET_VALUE, r"\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
    # -- SendGrid (trailing fence, not \b, for the same '-'-in-charset reason) --
    Rule(
        "sendgrid",
        Kind.SECRET_VALUE,
        r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![0-9A-Za-z_-])",
    ),
    # -- OpenAI: the T3BlbkFJ infix anchor is mandatory; both flanks are bounded --
    Rule(
        "openai",
        Kind.SECRET_VALUE,
        r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{0,120}T3BlbkFJ[A-Za-z0-9_-]{0,120}",
    ),
    # -- Anthropic (incl. the oauth oat01 variant) --
    Rule("anthropic", Kind.SECRET_VALUE, r"\bsk-ant-(?:api03|oat01)-[a-zA-Z0-9_-]{93}AA\b"),
    # -- npm: fixed length 36 --
    Rule("npm", Kind.SECRET_VALUE, r"\bnpm_[A-Za-z0-9]{36}\b"),
    # -- PyPI: macaroon header anchor, upper-bounded so it can't run past the token --
    Rule("pypi", Kind.SECRET_VALUE, r"\bpypi-AgEIcHlwaS5vcmc[\w-]{50,255}"),
    # -- Azure storage: base64 of 64 bytes is 88 chars ending in '==', i.e. 86 body chars
    #    then the padding (the appendix's {88}== was off by two and matched nothing real).
    #    The AccountKey= label and == padding stay readable; only the body is scrubbed. --
    Rule(
        "azure_storage",
        Kind.SECRET_VALUE,
        r"AccountKey=(?P<azure_key>[A-Za-z0-9+/]{86})==",
        value_group="azure_key",
    ),
    # -- Slack / Discord webhooks: the host stays readable; only the credential path is
    #    scrubbed. --
    Rule(
        "slack_webhook",
        Kind.SECRET_VALUE,
        r"https://hooks\.slack\.com/(?:services|workflows|triggers)/"
        r"(?P<slack_hook>[A-Za-z0-9+/]{43,56})",
        value_group="slack_hook",
    ),
    Rule(
        "discord_webhook",
        Kind.SECRET_VALUE,
        r"https://discord\.com/api/webhooks/[0-9]{17,19}/(?P<discord_hook>[A-Za-z0-9_-]{10,120})",
        value_group="discord_hook",
    ),
    # -- Twilio API key: SK + 32 hex. The 32-hex tail collides with MD5 digests and IDs
    #    that fill ordinary logs, so it is flagged for review rather than auto-scrubbed. --
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
    Rule(
        "jwt",
        Kind.JWT,
        r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*",
        validator=valid_jwt,
        downgrade_reason="malformed jwt (does not parse; still flagged)",
    ),
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
    # Structured credentials that live in a shape rather than key=value. These must precede
    # secret_kv so `Authorization: Bearer <t>` scrubs the token, not the word "Bearer" (which
    # the bare `authorization`/`bearer` stems would otherwise capture up to the space).
    #
    # Authorization: Bearer/Basic -- keep the header label, scrub only the credential. The
    # label and scheme may be JSON-quoted (structlog output), and the value runs to the next
    # delimiter (whitespace/quote/comma/semicolon) rather than an RFC token charset, so an
    # `id:secret`-shaped value is scrubbed whole instead of truncated at the ':'.
    Rule(
        "authz_header",
        Kind.SECRET_VALUE,
        r"[\"']?(?i:authorization)[\"']?\s*:\s*[\"']?(?i:bearer|basic)\s+"
        r"(?P<authz_val>[^\s\"',;]{1,4096})",
        value_group="authz_val",
    ),
    # URL userinfo / DSN: scheme://user:pass@host. Scrub only the password, leaving the
    # scheme, host and db name readable. Covers http(s), postgres, mysql, mongodb(+srv),
    # redis, amqp, ... The scheme is length-bounded so a long [a-z0-9+.-] run with no `://`
    # cannot backtrack quadratically; the length bounds (not the character classes) are what
    # keep matching linear. The user class excludes '/' so it stops at a path; the password
    # class must NOT -- a base64 password contains '/', and excluding it there would make the
    # whole match fail and leak the password. The password ends unambiguously at the '@'.
    Rule(
        "url_userinfo",
        Kind.SECRET_VALUE,
        r"[a-zA-Z][a-zA-Z0-9+.-]{0,31}://[^:@/\s]{0,256}:(?P<uri_pass>[^@\s]{1,256})@",
        value_group="uri_pass",
    ),
    Rule(
        "ssid",
        Kind.SSID,
        r"(?i:ssid)\s*[=:]\s*(?P<ssid_q>[\"'])(?P<ssid_val>[^\"']*)(?P=ssid_q)",
        value_group="ssid_val",
    ),
    # A distinctive stem confirms any non-empty value is a secret: scrub it ungated.
    Rule(
        "secret_kv",
        Kind.SECRET_VALUE,
        _STEM_BOUNDARY + r"(?i:" + "|".join(STRONG_STEMS) + r")\s*[=:]\s*"
        r"(?P<strong_q>[\"']?)(?P<strong_val>[^\s\"',;]+)(?P=strong_q)",
        value_group="strong_val",
    ),
    # A bare, ambiguous stem: the value must be >=10 chars (here) AND high-entropy (gated in
    # detect) before it scrubs, so `token=0`/`session=idle` are left alone. Tried after the
    # strong rule so `api_key=…` is caught ungated rather than gated on entropy.
    Rule(
        "secret_kv_generic",
        Kind.SECRET_VALUE,
        _STEM_BOUNDARY + r"(?i:" + "|".join(GENERIC_STEMS) + r")\s*[=:]\s*"
        rf"(?P<generic_q>[\"']?)(?P<generic_val>[^\s\"',;]{{{KEYWORD_VALUE_MIN_LEN},}})(?P=generic_q)",
        value_group="generic_val",
        gated=True,
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

# Linux-diagnostic identifiers: the class scrubbr's domain is full of and used to walk past.
# Each is distinctive (a fixed prefix or a label), so all SCRUB; the bare, ambiguous forms
# (a bare 32-hex, a bare 16-hex WWN) are left to the HEX rule / residual net. Typed numbered
# surrogates (machine-a, serial-b, cloud-c, hostkey-d) keep distinct ids distinguishable and,
# because a readable counter never re-matches its own rule, make a re-scrub a fixed point.
DIAGNOSTIC_RULES: tuple[Rule, ...] = (
    # 32-hex-no-dash system fingerprint behind its journald/dbus label -- a distinct kind
    # from the dashed UUID. The bare 32-hex form stays with the HEX rule.
    Rule(
        "system_id",
        Kind.MACHINE_ID,
        r"(?i:(?:machine|boot|(?:systemd[-_ ]?)?invocation)[-_ ]?id)\s*[=:]\s*"
        r"(?P<sysid_val>[0-9a-fA-F]{32})(?![0-9a-fA-F])",
        value_group="sysid_val",
    ),
    # SSH host-key fingerprint: SHA256: + 43 base64 (no padding). Prefix kept readable.
    Rule(
        "ssh_fingerprint",
        Kind.SSH_FINGERPRINT,
        r"\bSHA256:(?P<ssh_fp_val>[A-Za-z0-9+/]{43})(?![A-Za-z0-9+/=])",
        value_group="ssh_fp_val",
    ),
    # Hardware serials behind a label (dmidecode / sysfs / lsblk / udev / smartctl WWN),
    # including udev's ID_SERIAL_SHORT bare serial. The value must carry a digit and be >=4
    # chars, so placeholders ("Not Specified", "None") are left. A leading boundary plus a
    # BOUNDED digit lookahead (not `*`) and a value class without ':' keep matching linear --
    # an unbounded `[...:]*[0-9]` lookahead over many `serial:` labels is O(n^2).
    Rule(
        "hw_serial",
        Kind.HARDWARE_ID,
        r"(?<![A-Za-z0-9])(?i:(?:board|product|chassis|system)?[-_ ]?"
        r"serial(?:\s*number|_short|_id)?"
        r"|lu\s*wwn(?:\s*device\s*id)?|wwn)\s*[=:]\s*(?:0x)?"
        r"(?P<serial_val>(?=[A-Za-z0-9._+-]{0,64}[0-9])[A-Za-z0-9._+-]{4,64})",
        value_group="serial_val",
    ),
    # NVMe EUI-64 and iSCSI IQN carry their own distinctive prefixes.
    Rule(
        "nvme_eui",
        Kind.HARDWARE_ID,
        r"\beui\.(?P<nvme_val>[0-9a-fA-F]{16,32})\b",
        value_group="nvme_val",
    ),
    Rule(
        "iscsi_iqn",
        Kind.HARDWARE_ID,
        r"\b(?P<iqn_val>iqn\.\d{4}-\d{2}\.[A-Za-z0-9.:-]{3,256})",
        value_group="iqn_val",
    ),
    # AWS resource ids (i-/vol-/eni-/snap- + hex): keep the type prefix, scrub the id.
    Rule(
        "aws_resource_id",
        Kind.CLOUD_ID,
        r"\b(?:i|vol|eni|snap)-(?P<aws_res_val>[0-9a-f]{8,17})\b",
        value_group="aws_res_val",
    ),
    # AWS account id behind a label (a bare 12-digit number is far too ambiguous to scrub).
    Rule(
        "aws_account_id",
        Kind.CLOUD_ID,
        r"(?i:account[-_]?id|owner[-_]?id)\s*[=:]\s*(?P<aws_acct_val>[0-9]{12})(?![0-9])",
        value_group="aws_acct_val",
    ),
    # AWS ARN: keep arn:partition:service:region:, scrub the account:resource tail.
    Rule(
        "aws_arn",
        Kind.CLOUD_ID,
        r"\barn:(?:aws|aws-cn|aws-us-gov):[a-z0-9-]{1,32}:[a-z0-9-]{0,32}:"
        r"(?P<arn_val>[^\s\"',]{1,512})",
        value_group="arn_val",
    ),
    # cloud-config-url and the kernel netconfig ip= param both point at or fingerprint the host.
    Rule(
        "cloud_config_url",
        Kind.CLOUD_ID,
        r"(?i:cloud-config-url)\s*=\s*(?P<ccu_val>\S{1,512})",
        value_group="ccu_val",
    ),
    # kernel_ip is the /proc/cmdline `ip=client:server:gw:netmask:host:dev:autoconf` param,
    # whose fields are dotted IPv4 (or empty). The bounded dot-lookahead requires such a field
    # so an ordinary `ip=<ipv6>` connection-log field is NOT swallowed -- that would preempt
    # the ipv6 rule and redact a hand-assigned link-local the keep-policy deliberately keeps.
    Rule(
        "kernel_ip",
        Kind.CLOUD_ID,
        r"\bip=(?=[0-9A-Za-z:._-]{0,80}\.)"
        r"(?P<kernel_ip_val>[0-9A-Za-z._-]{0,64}(?::[0-9A-Za-z._-]{0,64}){3,10})",
        value_group="kernel_ip_val",
    ),
    # Wi-Fi PSK in the wpa_supplicant -dd debug hexdump (not a key=value shape): the ascii
    # column holds the passphrase in cleartext. Keep the header as evidence, scrub the whole
    # hex+ascii block. SECRET_VALUE so the replacement is a sentinel-bearing random look-alike
    # (idempotent). The conf-file psk="..." form is already caught by the secret_kv psk stem.
    Rule(
        "wpa_psk",
        Kind.SECRET_VALUE,
        r"PSK \(ASCII passphrase\) - hexdump_ascii\(len=\d+\):"
        r"(?P<psk_val>(?:[ \t]*\r?\n[ \t]+[0-9a-fA-F]{2}(?:[ \t]+[0-9a-fA-F]{2})*"
        r"(?:[ \t]{2,}[^\r\n]{0,80})?){1,32})",
        value_group="psk_val",
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
    # A promoted embedded id (the only REDACTED entry promotion produces) is a hex/id run
    # pulled from a declared wrapper. It folds case: the same key id is logged 1b22.. by one
    # tool and 1B22.. by another, and the case-folding REDACTED key then maps both spellings
    # to one surrogate rather than leaving the differently-cased copy in the clear.
    literals.extend(
        (value, kind, False, kind is Kind.REDACTED) for value, kind in promoted
    )
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
        + DIAGNOSTIC_RULES
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
        if (
            rule.gated
            and shannon_entropy(text[start:end]) < KEYWORD_VALUE_MIN_ENTROPY
            and classify(text[start:end]) is None
        ):
            # A long but low-entropy value behind a bare stem (`token=aaaaaaaaaa`) is
            # ordinary, not a secret -- leave it in place. But a value with a scrubbable
            # shape (a 32-hex blob behind `key=`) must still be scrubbed by that shape:
            # dropping it here would let the keyword rule swallow the span and preempt the
            # HEX/UUID rule that would otherwise catch it.
            continue
        disposition = rule.disposition
        reason = rule.warn_reason
        if rule.validator is not None and not rule.validator(text[start:end]):
            # Failed an offline checksum/format check: downgrade SCRUB -> WARN so it is
            # still surfaced. Validation can only ever downgrade, never suppress. Validate the
            # recorded value span (text[start:end]), the same text that would be scrubbed, so a
            # future validator on a value_group rule checks the value, not its label wrapper.
            disposition = Disposition.WARN
            reason = rule.downgrade_reason
        matches.append(
            Match(
                kind=rule.kind,
                start=start,
                end=end,
                text=text[start:end],
                forced=rule.forced,
                disposition=disposition,
                reason=reason,
            )
        )
    return matches
