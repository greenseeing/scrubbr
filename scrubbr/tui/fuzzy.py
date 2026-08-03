from collections.abc import Sequence

from textual.fuzzy import Matcher

from scrubbr.kinds import Residual

MIN_TOKEN_CHARS = 3
MAX_CANDIDATES = 5000
MAX_OPTIONS = 50
_TRIM = ".,;:!?'\"()[]{}<>="


def candidates(text: str, residuals: Sequence[Residual]) -> list[str]:
    """What a reviewer might want to scrub: residual warnings first, then every token."""
    seen = dict.fromkeys(residual.text for residual in residuals)
    for token in text.split():
        trimmed = token.strip(_TRIM)
        if len(trimmed) >= MIN_TOKEN_CHARS:
            seen.setdefault(trimmed, None)
        if len(seen) >= MAX_CANDIDATES:
            break
    return list(seen)


def options_for(query: str, text: str, pool: Sequence[str]) -> list[tuple[str, str]]:
    """(label, value) choices for a query: the exact occurrence first, then fuzzy matches."""
    if not query:
        return [(value, value) for value in pool[:MAX_OPTIONS]]
    options: list[tuple[str, str]] = []
    occurrences = text.count(query)
    if occurrences:
        plural = "s" if occurrences > 1 else ""
        options.append((f'scrub "{query}" everywhere ({occurrences} occurrence{plural})', query))
    matcher = Matcher(query)
    scored = sorted(
        ((matcher.match(value), value) for value in pool),
        key=lambda pair: (-pair[0], pair[1]),
    )
    options.extend((value, value) for score, value in scored if score > 0 and value != query)
    return options[:MAX_OPTIONS]
