import difflib
import sys
from collections.abc import Sequence
from typing import Protocol

from scrubbr.kinds import Residual

CONTEXT_LINES = 0


class NoTerminal(Exception):
    """Raised when there is no controlling terminal to hold the review on."""


class Terminal(Protocol):
    def write(self, text: str) -> int: ...

    def flush(self) -> None: ...

    def readline(self) -> str: ...

    def close(self) -> None: ...


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
        return open("/dev/tty", "r+", encoding="utf-8")
    except OSError as error:
        # Sandboxed and non-Unix terminals can lack the device while stdin and stderr
        # are still real terminals. A human is present, so the review can run on stdio;
        # stdout stays untouched for the scrubbed text. Piped runs have a non-tty stdin
        # and still refuse.
        if sys.stdin.isatty() and sys.stderr.isatty():
            return _StdioTerminal()
        raise NoTerminal from error


def confirm(
    original: str, scrubbed: str, residuals: Sequence[Residual], terminal: Terminal
) -> bool:
    """Show the change on the given terminal and wait for a decision.

    The caller owns the terminal: opening /dev/tty (or failing to) is its decision,
    which is also what lets a test hold the review on a fake one.
    """
    diff = _render_diff(original, scrubbed)
    terminal.write(f"{diff}\n" if diff else "no changes\n")
    warning = _render_residuals(residuals)
    if warning:
        terminal.write(f"\n{warning}\n")
    terminal.write("\nemit scrubbed text? [y/N] ")
    terminal.flush()
    answer = terminal.readline().strip().lower()
    return answer in {"y", "yes"}


def _render_diff(original: str, scrubbed: str) -> str:
    lines = difflib.unified_diff(
        original.splitlines(),
        scrubbed.splitlines(),
        fromfile="original",
        tofile="scrubbed",
        n=CONTEXT_LINES,
        lineterm="",
    )
    return "\n".join(lines)


def _render_residuals(residuals: Sequence[Residual]) -> str:
    if not residuals:
        return ""
    rows = [f"  line {r.line}: {r.text[:60]}  ({r.reason})" for r in residuals]
    return "\n".join([f"{len(residuals)} unscrubbed strings look sensitive:", *rows])
