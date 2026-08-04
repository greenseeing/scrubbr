from collections.abc import Sequence

from textual.fuzzy import Matcher

from scrubbr.kinds import Residual

MIN_TOKEN_CHARS = 3
MAX_OPTIONS = 50
# Subsequence scoring costs ~2 µs per candidate; past this it would stall every keystroke.
MAX_FUZZY_POOL = 25_000
_TRIM = ".,;:!?'\"()[]{}<>="


def candidates(text: str, residuals: Sequence[Residual]) -> list[str]:
    """What a reviewer might want to scrub: residual warnings first, then every token.

    Unbounded on purpose: a capped pool silently hides exactly the token the reviewer
    is searching for once the file is large enough.
    """
    seen = dict.fromkeys(residual.text for residual in residuals)
    for token in text.split():
        trimmed = token.strip(_TRIM)
        if len(trimmed) >= MIN_TOKEN_CHARS:
            seen.setdefault(trimmed, None)
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
