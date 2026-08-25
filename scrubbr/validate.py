import json
import zlib
from base64 import urlsafe_b64decode

# GitHub encodes a CRC32 of a token's random body as the trailing 6 base62 characters, so a
# truncated or mistyped token can be told from an intact one. This is GitHub's OWN published
# scheme (CRC32 + base62, leading-zero padded); the exact low-level details -- alphabet
# ordering, whether the prefix is part of the CRC input, digit order -- are NOT authoritatively
# documented, and the one detailed community reconstruction could not be reproduced against
# real tokens. So this validator is used ONLY to DOWNGRADE (SCRUB -> WARN), never to suppress:
# if our variant disagrees with GitHub's on a real token, that token is surfaced as a warn
# row (and blocks --strict), never silently dropped. Applies only to the fixed 30+6 classic
# tokens; a variable-length ghs_ or a fine-grained github_pat_ has no verifiable fixed checksum
# and is left SCRUB.
_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_GITHUB_BODY_LEN = 36
_GITHUB_RANDOM_LEN = 30


def github_checksum(random_body: str) -> str:
    """The 6-char base62 CRC32 GitHub appends after a classic token's random body."""
    value = zlib.crc32(random_body.encode("ascii")) & 0xFFFFFFFF
    out = ""
    while value:
        value, remainder = divmod(value, 62)
        out = _BASE62[remainder] + out
    return out.rjust(6, _BASE62[0])


def valid_github_token(token: str) -> bool:
    """True when a classic GitHub token's trailing CRC32 checks out.

    The github_token rule only ever matches a fixed 30+6 body, so that is the live path. The
    length guard makes the function safe to call directly on any github-shaped token: a
    variable-length ghs_ has no fixed checksum to verify, so it is treated as valid (left
    SCRUB) rather than downgraded. (Such a token is not matched by the fixed-length
    github_token rule anyway; it surfaces via the credential-prefix residual net.)"""
    body = token.split("_", 1)[-1]
    if len(body) != _GITHUB_BODY_LEN:
        return True
    random_body, checksum = body[:_GITHUB_RANDOM_LEN], body[_GITHUB_RANDOM_LEN:]
    return github_checksum(random_body) == checksum


def valid_jwt(token: str) -> bool:
    """True when a JWT parses structurally: three segments whose header and payload are
    base64url-encoded JSON objects (RFC 7519). A malformed one is log noise, not a live token,
    so it downgrades to WARN rather than being scrubbed as a secret."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    for segment in parts[:2]:
        try:
            decoded = urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
            obj = json.loads(decoded)
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return False
        if not isinstance(obj, dict):
            return False
    return True
