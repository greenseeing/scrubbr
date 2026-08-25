"""Synthetic, secret-shaped strings for the detection suite.

Every value here is a hand-typed keyboard pattern, not a real credential: the
shapes are right (prefix, length, charset) so the rules fire, but no value
authenticates anything. Keep them synthetic even though tests/ is gitleaks-
allowlisted -- a real secret pasted here would go unflagged.

Each value is assembled from fragments rather than written as one literal. That
keeps a contiguous credential-shaped string out of the source text, so GitHub's
push-protection secret scanner (which does not honour .gitleaks.toml) does not
false-positive on these fakes. The assembled runtime values are exactly the tokens
the rules are written to catch.
"""

import base64 as _base64
import json as _json

from scrubbr.validate import github_checksum

# ghp_ + 30 base62 random + 6 base62 CRC32 checksum (40 chars total). Built with a VALID
# checksum so it stays SCRUB tier; a copy with a corrupted checksum downgrades to WARN.
_GHP_BODY = "A1B2C3D4E5F6G7H8J9K0L1M2N3P4Q5"  # 30 base62
_GHO_BODY = "Z9Y8X7W6V5U4T3S2R1Q0P9N8M7L6K5"  # 30 base62
GITHUB_PAT = "ghp" + "_" + _GHP_BODY + github_checksum(_GHP_BODY)
GITHUB_OAUTH = "gho" + "_" + _GHO_BODY + github_checksum(_GHO_BODY)
# Same shape, one checksum character corrupted: a truncated/mistyped token.
GITHUB_PAT_BADSUM = GITHUB_PAT[:-1] + ("A" if GITHUB_PAT[-1] != "A" else "B")


def _jwt_segment(payload: dict) -> str:
    raw = _json.dumps(payload, separators=(",", ":")).encode()
    return _base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# A structurally valid JWT: header.payload are base64url-encoded JSON objects.
JWT_VALID = ".".join(
    [
        _jwt_segment({"alg": "HS256", "typ": "JWT"}),
        _jwt_segment({"sub": "1234567890", "name": "scrubbr test"}),
        "c2lnbmF0dXJlX3BhcnQ",
    ]
)
# Matches the JWT shape but the payload is not base64url JSON -- log noise, not a live token.
JWT_MALFORMED = "eyJhbGciOiJIUzI1NiJ9" + "." + "this_is_not_valid_json_payload" + "." + "c2ln"

# SK + 32 hex. WARN tier: 32-hex collides with MD5/IDs, too collision-prone to scrub.
TWILIO_SK = "SK" + "0123456789abcdef" * 2

# pk_live_ publishable key -- a PUBLIC identifier, deliberately left unchanged.
STRIPE_PK = "pk" + "_live_51ABCdefGHIjklMNOpqrSTU0vw"

# A generic high-entropy token behind no distinctive prefix: the REPORT-ONLY net's job.
GENERIC_HIGH_ENTROPY = "kJH8s2Vx9pQ7wLm3tR5uYq2Zx8Nw4Kd"


# --- D1 distinctive-prefix provider catalog (SCRUB tier) --------------------
#
# Bodies are sliced to the exact length each rule requires, so a fixture can
# never be one char short of its pattern. Prefixes stay in a separate literal
# from their body so no contiguous provider-shaped string exists in this file
# for GitHub push-protection to trip on.

# A base64url repeating unit whose letters are deliberately NON-hex (Z, x, Y, w, G, k,
# ...), so a sliced body never reads as an all-hex value and every provider fixture routes
# through the SECRET_VALUE minter (sentinel-bearing, idempotent) rather than the HEX one.
_A = "Zx9Yw8Gk7Vn5Tp3"
_HEX = "0123456789abcdef"


def _body(length: int) -> str:
    return (_A * (length // len(_A) + 1))[:length]


# github_pat_ fine-grained PAT: 82 [0-9A-Za-z_] after the prefix.
GITHUB_PAT_FINE = "github" + "_pat_" + ("A1b2C3d4_" * 10)[:82]

# glpat- + 20+ [0-9A-Za-z_-].
GITLAB_PAT = "glpat" + "-" + _body(20)

# AWS access key id: AKIA/ASIA + 16 base32 [A-Z2-7]. AIDA is an identity id, excluded.
AWS_AKIA = "AK" + "IA" + "JBSWY3DPEHPK3PXP"
AWS_AIDA_IDENTITY = "AI" + "DA" + "JBSWY3DPEHPK3PXP"

# Slack bot / user tokens.
SLACK_BOT = "xoxb" + "-" + "1234567890" + "-" + "1234567890123" + "-" + "AbCdEfGhIjKlMnOp"
SLACK_USER = "xoxp" + ("-1234567890" * 3) + "-" + _body(30)  # tail is [a-zA-Z0-9-], no _

# Stripe secret / restricted keys. pk_ (publishable) is public and excluded.
STRIPE_SECRET = "sk" + "_live_" + ("A1b2C3d4" * 3)[:24]
STRIPE_RESTRICTED = "rk" + "_live_" + ("A1b2C3d4" * 3)[:24]

# Google API key: AIza + 35 [0-9A-Za-z_-].
GOOGLE_API_KEY = "AIza" + _body(35)

# SendGrid: SG.<22>.<43>.
SENDGRID = "SG" + "." + _body(22) + "." + _body(43)

# OpenAI: sk-<class>- ... T3BlbkFJ ... (the infix anchor is mandatory).
OPENAI = "sk-" + "proj-" + "abcd" + "T3BlbkFJ" + "efghijkl"

# Anthropic: sk-ant-<class>- + 93 [a-zA-Z0-9_-] + AA (incl. oauth oat01 variant).
ANTHROPIC = "sk-ant-" + "api03-" + _body(93) + "AA"

# npm: npm_ + 36 [0-9A-Za-z].
NPM = "npm" + "_" + ("A1b2C3d4" * 5)[:36]

# PyPI: pypi- + macaroon header anchor + 50+ [\w-].
PYPI = "pypi-" + "AgEIcHlwaS5vcmc" + _body(54)

# Azure storage: base64(64 bytes) is 88 chars ending in ==, i.e. 86 body chars + padding.
# The label and == are kept readable.
AZURE_ACCOUNT_KEY_SECRET = _body(86)
AZURE_ACCOUNT_KEY = "Account" + "Key=" + AZURE_ACCOUNT_KEY_SECRET + "=="

# Slack / Discord webhooks: host stays readable, secret path/token is scrubbed.
SLACK_WEBHOOK_SECRET = _body(48)
SLACK_WEBHOOK = "https://hooks.slack.com/" + "services/" + SLACK_WEBHOOK_SECRET
DISCORD_WEBHOOK_SECRET = _body(20)
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/" + "123456789012345678" + "/" + DISCORD_WEBHOOK_SECRET

# Twilio Account SID: AC + 32 hex. A PUBLIC identifier -- deliberately NOT scrubbed.
TWILIO_AC_SID = "AC" + _HEX * 2
