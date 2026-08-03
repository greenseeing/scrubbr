import argparse
import io
import os
import shutil
import sys
from collections import Counter
from collections.abc import Callable
from dataclasses import replace
from importlib.metadata import version
from pathlib import Path

import structlog

from scrubbr.alias import AliasBook
from scrubbr.decisions import ReviewOutcome, ReviewRequest
from scrubbr.identity import LocalIdentity
from scrubbr.report import clip, render_report
from scrubbr.review import (
    NoTerminal,
    ScreenTerminal,
    Terminal,
    confirm,
    open_terminal,
    supports_tui,
)
from scrubbr.scrub import ScrubResult, scrub

RunApp = Callable[[ReviewRequest, ScreenTerminal], ReviewOutcome]


def _configure_logging() -> None:
    renderer = (
        structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
        if sys.stderr.isatty()
        else structlog.processors.JSONRenderer()
    )
    structlog.configure(
        processors=[structlog.processors.add_log_level, renderer],
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    )


def _parse(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scrubbr",
        description="Sanitize Linux diagnostics before pasting them into an LLM.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {version('scrubbr')}",
    )
    parser.add_argument(
        "infile",
        nargs="?",
        # Kernel and firmware strings in dmesg are not always valid UTF-8, and crashing on
        # a decode error would lose whatever the caller piped in.
        type=lambda path: argparse.FileType("r", encoding="utf-8", errors="replace")(path),
        default=None,
        help="file to read; defaults to stdin",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write the scrubbed text to FILE instead of stdout",
    )
    parser.add_argument(
        "-y",
        "--no-review",
        action="store_true",
        help="skip the interactive review",
    )
    parser.add_argument(
        "--plain",
        action="store_true",
        help="review with the line-mode y/N prompt instead of the full-screen review",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="also report each replaced value with its count and alias"
        " (prints the original values to stderr)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="refuse to emit anything while unscrubbed suspicious strings remain",
    )
    parser.add_argument(
        "--no-identity",
        action="store_true",
        help="do not seed the scanner with this machine's hostname, user and machine-id",
    )
    parser.add_argument(
        "--also",
        action="append",
        default=[],
        metavar="TEXT",
        help="scrub this value too; repeatable. IPs are always replaced (even private or"
        " loopback), long hex, UUIDs and emails keep their shape; anything else becomes"
        " [REDACTED]",
    )
    return parser.parse_args(argv)


def _report(log: structlog.stdlib.BoundLogger, result: ScrubResult, verbose: bool) -> None:
    if sys.stderr.isatty():
        sys.stderr.write("\n".join(render_report(result, verbose, _stderr_width())) + "\n")
        return
    log.info(
        "scrubbed",
        **{kind.value: count for kind, count in sorted(result.counts.items())},
        replacements=len(result.findings),
    )
    if verbose:
        occurrences = Counter((f.kind, f.text, f.alias) for f in result.findings)
        for (kind, text, alias), count in sorted(occurrences.items()):
            log.info("replaced", kind=kind.value, text=clip(text), count=count, alias=clip(alias))
    for residual in result.residuals:
        log.warning("unscrubbed", line=residual.line, reason=residual.reason, text=residual.text)


def _stderr_width() -> int:
    try:
        return os.get_terminal_size(sys.stderr.fileno()).columns
    except (OSError, ValueError):
        # shutil probes stdout, which is routinely a pipe here (`scrubbr | wl-copy`), so
        # stderr's own fd is tried first; shutil still honours $COLUMNS before its 80.
        return shutil.get_terminal_size().columns


def main(
    argv: list[str] | None = None,
    open_tty: Callable[[], Terminal] = open_terminal,
    run_app: RunApp | None = None,
) -> int:
    args = _parse(argv)
    _configure_logging()
    log = structlog.get_logger()

    if args.infile is None:
        if isinstance(sys.stdin, io.TextIOWrapper):
            sys.stdin.reconfigure(errors="replace")
        args.infile = sys.stdin
    text = args.infile.read()
    base = LocalIdentity() if args.no_identity else LocalIdentity.local()
    identity = replace(base, extra=base.extra + tuple(args.also))
    # One book for the whole run, so an interactive recompute can never re-mint aliases.
    book = AliasBook()
    result = scrub(text, identity, book)
    _report(log, result, args.verbose)

    if args.strict and result.residuals:
        log.error("refusing to emit", reason="strict mode with unscrubbed strings")
        return 2

    if not args.no_review:
        try:
            tty = open_tty()
        except NoTerminal:
            # Failing open here would emit unreviewed text precisely when the safety gate
            # could not run. Skipping review has to be a decision the caller makes.
            log.error("refusing to emit", reason="no terminal for review; pass -y to skip it")
            return 3
        try:
            if run_app is not None and not args.plain and supports_tui(tty):
                outcome = run_app(
                    ReviewRequest(text=text, result=result, identity=identity, book=book), tty
                )
                confirmed, result = outcome.confirmed, outcome.result
            else:
                confirmed = confirm(text, result.text, result.residuals, tty)
        finally:
            tty.close()
        if not confirmed:
            log.error("discarded", reason="not confirmed at review")
            return 1

    if args.output is not None:
        try:
            # Opened only after the review passes: opening at parse time would leave an
            # empty or truncated file behind on every refused run.
            Path(args.output).write_text(result.text, encoding="utf-8")
        except OSError as error:
            log.error("could not write", path=args.output, error=str(error))
            return 4
        log.info("written", path=args.output)
    else:
        sys.stdout.write(result.text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
