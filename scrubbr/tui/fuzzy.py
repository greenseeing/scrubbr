import re
from collections.abc import Sequence

from textual.fuzzy import Matcher

from scrubbr.kinds import Residual

MIN_TOKEN_CHARS = 3
MAX_OPTIONS = 50
# Subsequence scoring costs ~2 µs per candidate; past this it would stall every keystroke.
MAX_FUZZY_POOL = 25_000
_TRIM = ".,;:!?'\"()[]{}<>="
# One identifier within a whitespace token: a run of letters/digits that may carry an
# internal '-' or '_' (so a kebab/snake id stays whole) but not at its edges. The hard
# delimiters between identifiers -- '=', '/', '.', ':', '@' -- are what a plain split misses.
_WORD = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?")


def candidates(text: str, residuals: Sequence[Residual]) -> list[str]:
    """What a reviewer might want to scrub: residual warnings first, then every token.

    A compound token -- a path, a `--flag=value`, a dotted name -- is broken into its
    identifiers rather than offered whole: picking the glued `--name=<kid>.pem` would scrub
    that one occurrence and leave every bare copy of the embedded id exposed, a silent
    partial leak. Offering the parts surfaces the id the reviewer actually means.

    Unbounded on purpose: a capped pool silently hides exactly the token the reviewer
    is searching for once the file is large enough.
    """
    seen = dict.fromkeys(residual.text for residual in residuals)
    for token in text.split():
        words = _WORD.findall(token)
        parts = words if len(words) > 1 else [token.strip(_TRIM)]
        for part in parts:
            if len(part) >= MIN_TOKEN_CHARS:
                seen.setdefault(part, None)
    return list(seen)


def options_for(query: str, text: str, pool: Sequence[str]) -> list[tuple[str, str]]:
    """(label, value) choices for a query: the exact occurrence first, then matches.

    Substring hits lead (in pool order, so residuals stay first) because they are cheap
    enough to scan an unbounded pool on every keystroke; the fuzzy matcher only runs
    when they leave room to fill and the pool is small enough to score interactively.
    """
    if not query:
        return [(value, value) for value in pool[:MAX_OPTIONS]]
    options: list[tuple[str, str]] = []
    occurrences = text.count(query)
    if occurrences:
        plural = "s" if occurrences > 1 else ""
        options.append((f'scrub "{query}" everywhere ({occurrences} occurrence{plural})', query))
    folded = query.lower()
    contained = [value for value in pool if value != query and folded in value.lower()]
    options.extend((value, value) for value in contained[:MAX_OPTIONS])
    if len(options) < MAX_OPTIONS and len(pool) <= MAX_FUZZY_POOL:
        matcher = Matcher(query)
        shown = set(contained)
        scored = sorted(
            (
                (matcher.match(value), value)
                for value in pool
                if value != query and value not in shown
            ),
            key=lambda pair: (-pair[0], pair[1]),
        )
        options.extend((value, value) for score, value in scored if score > 0)
    return options[:MAX_OPTIONS]
