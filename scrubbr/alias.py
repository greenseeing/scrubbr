import random

from scrubbr.kinds import Kind
from scrubbr.shapes import mint, normalize, render


class AliasBook:
    """The only thing that may mint an alias.

    Callers ask for the alias of a value and cannot obtain an inconsistent answer, which
    is what makes "one value, one replacement" a structural guarantee rather than a
    convention every call site has to remember.
    """

    def __init__(self, rng: random.Random | None = None) -> None:
        # SystemRandom is the CSPRNG secrets is built on; a seeded Random makes the
        # output reproducible, which tests and correlated multi-document runs need.
        self._rng = rng if rng is not None else random.SystemRandom()
        self._canonical: dict[tuple[Kind, str], str] = {}
        self._issued: dict[Kind, int] = {}

    def alias_for(self, kind: Kind, text: str) -> str:
        canonical = self.canonical_alias(kind, normalize(kind, text))
        return render(kind, canonical, text)

    def canonical_alias(self, kind: Kind, normalized: str) -> str:
        key = (kind, normalized)
        existing = self._canonical.get(key)
        if existing is not None:
            return existing
        minted = mint(kind, normalized, self._rng, self._next(kind))
        self._canonical[key] = minted
        return minted

    def _next(self, kind: Kind) -> int:
        index = self._issued.get(kind, 0)
        self._issued[kind] = index + 1
        return index
