import argparse
import io
import sys
from collections.abc import Callable
from dataclasses import replace

import structlog

from scrubbr.identity import LocalIdentity
from scrubbr.review import NoTerminal, Terminal, confirm, open_terminal
from scrubbr.scrub import ScrubResult, scrub


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
        "infile",
        nargs="?",
        # Kernel and firmware strings in dmesg are not always valid UTF-8, and crashing on
        # a decode error would lose whatever the caller piped in.
        type=lambda path: argparse.FileType("r", encoding="utf-8", errors="replace")(path),
        default=None,
        help="file to read; defaults to stdin",
    )
    parser.add_argument(
        "-y",
        "--no-review",
        action="store_true",
        help="skip the interactive review",
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
        help="scrub this literal string too; repeatable, for names only you know",
    )
    return parser.parse_args(argv)


def _report(log: structlog.stdlib.BoundLogger, result: ScrubResult) -> None:
    log.info(
        "scrubbed",
        **{kind.value: count for kind, count in sorted(result.counts.items())},
        replacements=len(result.findings),
    )
    for residual in result.residuals:
        log.warning("unscrubbed", line=residual.line, reason=residual.reason, text=residual.text)


def main(
    argv: list[str] | None = None, open_tty: Callable[[], Terminal] = open_terminal
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
    result = scrub(text, identity)
    _report(log, result)

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
            confirmed = confirm(text, result.text, result.residuals, tty)
        finally:
            tty.close()
        if not confirmed:
            log.error("discarded", reason="not confirmed at review")
            return 1

    sys.stdout.write(result.text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
