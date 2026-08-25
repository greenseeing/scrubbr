import re
from bisect import bisect_right
from collections.abc import Sequence

from scrubbr.kinds import Residual
from scrubbr.shapes import SENTINEL, shannon_entropy

MIN_TOKEN_CHARS = 20
MIN_ENTROPY_BITS = 3.5

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
    if shannon_entropy(token) > MIN_ENTROPY_BITS:
        return "high entropy"
    return None
