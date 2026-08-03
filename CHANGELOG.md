# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `open_terminal()` now successfully opens `/dev/tty` on real terminals: bypasses the seek probe that fails on ptys by using `TextIOWrapper(FileIO(...))` instead of plain `open()`.

### Added

- `scrub()` accepts keyword-only `keep` and `overrides` parameters to allow callers to accept,
  reject, or modify individual findings after shape reclassification. Added `decision_key()`
  helper to construct unique keys for findings.
- Keeping a labelled secret now un-promotes its bare occurrences to prevent inconsistent masking.
- A decisions layer (Decisions/ReviewRequest/ReviewOutcome dataclasses) with apply_decisions()
  to re-scrub with reviewer changes applied, routing new text through --also machinery while
  maintaining alias stability via a shared AliasBook.
- Full-screen review app infrastructure: `ScreenTerminal` protocol, `supports_tui()` TypeGuard,
  `tty_stdio()` context manager for redirecting stdio to the review terminal, and an injectable
  `run_app` parameter on `main()` to route capable terminals to a full-screen review app.
  Added `--plain` flag to force line-mode review when a full-screen app is available.
- Full-screen review is now the default on capable terminals (`ReviewApp`), showing findings in
  an interactive DataTable with live re-scrubbing. Pressing y opens a colored full-diff screen
  (unified diff with 2 context lines); use `--plain` to force the classic line-mode y/N prompt.
  Made `render_diff()` and `render_residuals()` public in review.py for reuse.
- Review screen now supports fuzzy-finding extra text via the finder ("a" key, with candidates
  drawn from residuals and input tokens, fuzzy-ranked and sorted with exact matches first), and
  promoting residual warnings to scrubbed additions via space key on a warning row.
- Review screen now allows choosing a replacement for each finding: the minted alias, [REDACTED], or custom text (r key; re-picking the minted alias clears the override).

### Changed

- `main()` now creates a single `AliasBook` per run and passes it to `scrub()`, ensuring
  interactive recomputes never mint new aliases for existing findings.
- Confirmed reviews with amendments log one "amended" event with kept/added/replaced counts.
- Rule matching now reads Match.lastgroup instead of probing every named group per match: 8% faster on worst-case-dense 2 MB logs (2.754s → 2.539s). Case matching in value replacement also optimized: one C-level string comparison replaces the per-character generator, which dominated the replacement path's profile.


## [0.2.0] - 2026-07-31

First release published to PyPI. Earlier copies installed from git also called themselves `0.1.0`
while missing most of the options below, so that version number was retired rather than reused.

### Added

- Scrub a file or piped stdin, replacing usernames, hostnames, IPs, MACs, UUIDs, emails, SSIDs,
  keys and other identifying strings with harmless look-alikes. The same value always maps to the
  same replacement, so the log still reads coherently.
- Interactive review gate showing every proposed change before anything is emitted. scrubbr
  refuses to emit rather than skip the gate when no terminal is available; `-y/--no-review` makes
  skipping it an explicit choice.
- `-o/--output` to write the scrubbed text to a file, leaving the original untouched.
- `-v/--verbose` to list each replaced value with its occurrence count and alias.
- `--strict` to exit non-zero rather than emit while suspicious strings remain unscrubbed.
- `--no-identity` to skip seeding the scanner with the local hostname, user and machine-id.
- `--also` to scrub extra values, repeatable, with the type of each value autodetected so IPs,
  hex strings, UUIDs and emails keep their shape instead of all being aliased as hosts.
- `--version`.
- Width-aware tables for the stderr report when running on a terminal, JSON log lines otherwise.
- Fallback to a stdio-backed terminal when `/dev/tty` cannot be opened.

[Unreleased]: https://github.com/greenseeing/scrubbr/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/greenseeing/scrubbr/releases/tag/v0.2.0
