import difflib
import os
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from io import FileIO, TextIOWrapper
from typing import Protocol, TypeGuard

from scrubbr.kinds import Residual

CONTEXT_LINES = 0
DUMB_TERMS = frozenset({"", "dumb"})
_STANDARD_FDS = (0, 1, 2)


class NoTerminal(Exception):
    """Raised when there is no controlling terminal to hold the review on."""


class Terminal(Protocol):
    def write(self, text: str) -> int: ...

    def flush(self) -> None: ...

    def readline(self) -> str: ...

    def close(self) -> None: ...


class ScreenTerminal(Terminal, Protocol):
    def fileno(self) -> int: ...


def supports_tui(terminal: Terminal) -> TypeGuard[ScreenTerminal]:
    """Whether this terminal can hold a full-screen review rather than a line prompt."""
    if os.environ.get("TERM", "") in DUMB_TERMS:
        return False
    fileno = getattr(terminal, "fileno", None)
    if fileno is None:
        return False
    try:
        return os.isatty(fileno())
    except (OSError, ValueError):
        return False


@contextmanager
def tty_stdio(terminal: ScreenTerminal) -> Iterator[None]:
    """Point fds 0-2 at the review terminal for the duration.

    stdout is the pipe the scrubbed text must stay on and stdin may be a consumed one,
    but a full-screen app reads keys from and renders on whichever standard fds its
    driver picked. Swapping all three keeps the choice of driver irrelevant — and keeps
    escape codes out of a redirected stderr.
    """
    sys.stdout.flush()
    sys.stderr.flush()
    fd = terminal.fileno()
    saved = {n: os.dup(n) for n in _STANDARD_FDS}
    try:
        for n in _STANDARD_FDS:
            os.dup2(fd, n)
        yield
    finally:
        for n, kept in saved.items():
            os.dup2(kept, n)
            os.close(kept)


class _StdioTerminal:
    """Review terminal for shells that are interactive but expose no /dev/tty device."""

    def write(self, text: str) -> int:
        return sys.stderr.write(text)

    def flush(self) -> None:
        sys.stderr.flush()

    def readline(self) -> str:
        return sys.stdin.readline()

    def close(self) -> None:
        return None


def open_terminal() -> Terminal:
    """The interactive review's terminal: /dev/tty, so stdio stays free for the pipe."""
    try:
        # Not open(): update mode wraps the fd in BufferedRandom, which refuses any
        # non-seekable file -- and every pty replica is one, so on a real terminal the
        # plain open() always fell through to the stdio fallback.
        return TextIOWrapper(FileIO("/dev/tty", "r+"), encoding="utf-8", line_buffering=True)
    except OSError as error:
        # Sandboxed and non-Unix terminals can lack the device while stdin and stderr
        # are still real terminals. A human is present, so the review can run on stdio;
        # stdout stays untouched for the scrubbed text. Piped runs have a non-tty stdin
        # and still refuse.
        if sys.stdin.isatty() and sys.stderr.isatty():
            return _StdioTerminal()
        raise NoTerminal from error


def confirm(
    original: str,
    scrubbed: str,
    residuals: Sequence[Residual],
    terminal: Terminal,
    *,
    destination: str | None = None,
) -> bool:
    """Show the change on the given terminal and wait for a decision.

    The caller owns the terminal: opening /dev/tty (or failing to) is its decision,
    which is also what lets a test hold the review on a fake one.
    """
    diff = render_diff(original, scrubbed)
    terminal.write(f"{diff}\n" if diff else "no changes\n")
    warning = render_residuals(residuals)
    if warning:
        terminal.write(f"\n{warning}\n")
    question = (
        "emit scrubbed text" if destination is None else f"write scrubbed text to {destination}"
    )
    terminal.write(f"\n{question}? [y/N] ")
    terminal.flush()
    answer = terminal.readline().strip().lower()
    return answer in {"y", "yes"}


def render_diff(original: str, scrubbed: str, context: int = CONTEXT_LINES) -> str:
    lines = difflib.unified_diff(
        original.splitlines(),
        scrubbed.splitlines(),
        fromfile="original",
        tofile="scrubbed",
        n=context,
        lineterm="",
    )
    return "\n".join(lines)


def render_residuals(residuals: Sequence[Residual]) -> str:
    if not residuals:
        return ""
    rows = [f"  line {r.line}: {r.text[:60]}  ({r.reason})" for r in residuals]
    return "\n".join([f"{len(residuals)} unscrubbed strings look sensitive:", *rows])
