from collections.abc import Mapping
from dataclasses import dataclass, field, replace

from scrubbr.alias import AliasBook
from scrubbr.identity import LocalIdentity
from scrubbr.kinds import Kind
from scrubbr.scrub import ScrubResult, scrub


@dataclass(frozen=True)
class Decisions:
    """What the reviewer changed: findings to keep, text to add, aliases to impose."""

    keep: frozenset[tuple[Kind, str]] = field(default_factory=frozenset)
    additions: tuple[str, ...] = ()
    overrides: Mapping[tuple[Kind, str], str] = field(default_factory=dict)


@dataclass(frozen=True)
class ReviewRequest:
    """Everything an interactive review needs, importable without importing the TUI."""

    text: str
    result: ScrubResult
    identity: LocalIdentity
    book: AliasBook
    # The file offered when stdout is an interactive terminal; None means emit to stdout.
    default_output: str | None = None


@dataclass(frozen=True)
class ReviewOutcome:
    confirmed: bool
    result: ScrubResult
    decisions: Decisions
    destination: str | None = None


def apply_decisions(
    text: str, identity: LocalIdentity, decisions: Decisions, book: AliasBook
) -> ScrubResult:
    """Re-scrub with the reviewer's changes applied.

    Additions ride the --also machinery: forced past the keep-allowlists, found at every
    occurrence, shape-classified for their alias. Sharing the caller's book is what keeps
    every already-minted alias stable across recomputes.
    """
    fresh = tuple(value for value in decisions.additions if value not in identity.extra)
    amended = replace(identity, extra=identity.extra + fresh)
    return scrub(text, amended, book, keep=decisions.keep, overrides=decisions.overrides)
