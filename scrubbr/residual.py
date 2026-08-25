import re
from bisect import bisect_right
from collections.abc import Sequence

from scrubbr.kinds import Residual
from scrubbr.shapes import SENTINEL, shannon_entropy

MIN_TOKEN_CHARS = 20
# Per-charset thresholds instead of one mixed-alphabet number. Shannon entropy on a short
# sample undershoots its alphabet's true bits/char, and by different amounts per alphabet:
# a random 20-char HEX secret lands below 3.5 ~77% of the time (the old single threshold
# silently missed most short hex secrets), while a random base64 secret lands higher. The
# thresholds are set from the measured miss-rate of RANDOM secrets so a real short secret is
# still surfaced -- a silent false negative is the one thing this net exists to prevent -- at
# the cost of some report-only noise on ordinary hex ids (a 24-hex Mongo ObjectId, say).
MIN_ENTROPY_BITS = 3.5  # the mixed-alphabet fallback (a token with a '.', '-', etc.)
HEX_ENTROPY_BITS = 3.0  # a random hex secret clears this at every length >= 20
BASE64_ENTROPY_BITS = 3.8  # clears random base64 at 24+ chars; 4.5 would silence most secrets

# Structural shapes that read as high-entropy yet are obviously not secrets, excluded before
# the entropy test. Deliberately NOT excluding the git-sha / machine-id / uuid SHAPES: those
# are scrubbed by the HEX/UUID rules in normal operation and only reach this net when the
# reviewer KEEPS them, where excluding by shape would silence a kept MD5/SHA-1-length secret
# and defeat the "a kept value still reappears as a residual" safety net. A kept 32/40-hex
# reappears here (correct); a kept uuid stays quiet on its own (entropy 3.4 < the threshold).
_HEX_ONLY = re.compile(r"[0-9a-fA-F]+")
# base64url alphabet; '/' (base64-standard) never reaches here -- _suspicion drops any token
# containing '/' first -- so only base64url tokens are classified through this branch.
_BASE64_ONLY = re.compile(r"[A-Za-z0-9+=_-]+")
# An id-like field name: `id`/`userid` at the start or `_id` as a segment, each fenced by a
# boundary so an ordinary word merely beginning with or containing those letters
# (identifier, idempotency, a coincidental mid-token `_id`) is NOT wrongly excluded.
_ID_LIKE = re.compile(r"(?:^(?:id|myid|userid)|_id)s?(?![A-Za-z0-9])", re.IGNORECASE)
# Sequential strings have maximal Shannon entropy yet are obviously not secrets.
_SEQUENCES = (
    "0123456789abcdefghijklmnopqrstuvwxyz",
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
)

CREDENTIAL_PREFIXES = (
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "sk-",
    "sk_live_",
    "pk_live_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxs-",
    "AKIA",
    "ASIA",
    "eyJ",
)

TOKEN = re.compile(rf"[A-Za-z0-9_\-./+=]{{{MIN_TOKEN_CHARS},}}")


def find_residuals(
    text: str,
    written: Sequence[tuple[int, int]] = (),
    warnings: Sequence[tuple[str, str]] = (),
) -> list[Residual]:
    """Tokens that look sensitive but matched no SCRUB rule.

    Reported, never rewritten. A scrubber that silently guesses is worse than one that
    says plainly where it is unsure.

    `written` are the spans this tool just produced. Excluding them matters more than it
    looks: aliases are by construction high-entropy, so without this the tool warns about
    its own output on every single run and the warning stops meaning anything.

    `warnings` are (value, reason) pairs the sweep flagged but left in place -- a WARN-tier
    provider match or colon-hex the detector recognised the shape of but could not
    interpret -- each surfaced at every line where the value still appears.
    """
    spans = sorted(written)
    ends = [end for _, end in spans]
    line_starts = _line_starts(text)

    # First seen reason wins for a repeated flagged value.
    reasons: dict[str, str] = {}
    for value, reason in warnings:
        reasons.setdefault(value, reason)

    residuals: list[Residual] = []
    for token in TOKEN.finditer(text):
        if _overlaps(token.span(), spans, ends) or token.group() in reasons:
            # A value the sweep already flagged carries a specific reason; the generic
            # entropy net must not report it a second time.
            continue
        suspicion = _suspicion(token.group())
        if suspicion is not None:
            line = bisect_right(line_starts, token.start())
            residuals.append(Residual(line=line, text=token.group(), reason=suspicion))

    # Colon- and dot-structured values are invisible to TOKEN, so anything the sweep flagged
    # for review is reported by literal search.
    for value, reason in reasons.items():
        for found in re.finditer(re.escape(value), text):
            if _overlaps(found.span(), spans, ends):
                continue
            line = bisect_right(line_starts, found.start())
            residuals.append(Residual(line=line, text=value, reason=reason))
    residuals.sort(key=lambda r: (r.line, r.text))
    return residuals


def _line_starts(text: str) -> list[int]:
    starts = [0]
    for index, char in enumerate(text):
        if char == "\n":
            starts.append(index + 1)
    return starts


def _overlaps(span: tuple[int, int], spans: list[tuple[int, int]], ends: list[int]) -> bool:
    # Written spans never overlap each other, so sorting by start also sorts by end and a
    # single bisect finds the only candidate that can intersect this token.
    start, end = span
    index = bisect_right(ends, start)
    return index < len(spans) and spans[index][0] < end


def _suspicion(token: str) -> str | None:
    if SENTINEL in token:
        # scrubbr's own synthetic surrogate, not a leak; keeps a re-scrub from warning
        # about the random string it just minted for a secret.
        return None
    if token.startswith(CREDENTIAL_PREFIXES):
        return "known credential prefix"
    if "/" in token or token.count(".") > 1:
        return None
    if _is_structural(token):
        # A sequential or id-like token reads as high-entropy but is an ordinary diagnostic
        # value -- exclude it before the entropy test so the net stays readable.
        return None
    if shannon_entropy(token) > _entropy_threshold(token):
        return "high entropy"
    return None


def _entropy_threshold(token: str) -> float:
    if _HEX_ONLY.fullmatch(token):
        return HEX_ENTROPY_BITS
    if _BASE64_ONLY.fullmatch(token):
        return BASE64_ENTROPY_BITS
    return MIN_ENTROPY_BITS


def _is_structural(token: str) -> bool:
    if _ID_LIKE.search(token):
        return True
    low = token.lower()
    return any(low in seq or low in seq[::-1] for seq in _SEQUENCES)
