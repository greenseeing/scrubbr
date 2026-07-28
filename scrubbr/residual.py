import math
import re
from bisect import bisect_right
from collections import Counter
from collections.abc import Sequence

from scrubbr.kinds import Residual

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


def shannon_entropy(value: str) -> float:
    counts = Counter(value)
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def find_residuals(
    text: str,
    written: Sequence[tuple[int, int]] = (),
    unresolved: Sequence[str] = (),
) -> list[Residual]:
    """Tokens that look sensitive but matched no rule.

    Reported, never rewritten. A scrubber that silently guesses is worse than one that
    says plainly where it is unsure.

    `written` are the spans this tool just produced. Excluding them matters more than it
    looks: aliases are by construction high-entropy, so without this the tool warns about
    its own output on every single run and the warning stops meaning anything.
    """
    spans = sorted(written)
    ends = [end for _, end in spans]
    line_starts = _line_starts(text)

    residuals: list[Residual] = []
    for token in TOKEN.finditer(text):
        if _overlaps(token.span(), spans, ends):
            continue
        reason = _suspicion(token.group())
        if reason is not None:
            line = bisect_right(line_starts, token.start())
            residuals.append(Residual(line=line, text=token.group(), reason=reason))

    # Colon- and dot-structured values are invisible to TOKEN, so anything the detector
    # recognised the shape of but could not interpret is reported by literal search.
    for value in dict.fromkeys(unresolved):
        for found in re.finditer(re.escape(value), text):
            if _overlaps(found.span(), spans, ends):
                continue
            line = bisect_right(line_starts, found.start())
            residuals.append(Residual(line=line, text=value, reason="unrecognized structure"))
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
    if token.startswith(CREDENTIAL_PREFIXES):
        return "known credential prefix"
    if "/" in token or token.count(".") > 1:
        return None
    if shannon_entropy(token) > MIN_ENTROPY_BITS:
        return "high entropy"
    return None
