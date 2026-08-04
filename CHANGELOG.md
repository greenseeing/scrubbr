# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- When standard output is an interactive terminal and no `-o` is given, the cleaned text
  is written to `NAME.scrubbed.EXT` next to the input (`scrubbed.txt` for piped input)
  instead of being dumped onto the screen. The diff screen shows the destination and `e`
  edits it; the `--plain` prompt names it (`write scrubbed text to …? [y/N]`).

### Changed

- An interactive terminal never receives the scrubbed text on stdout; pipes and
  redirections are byte-for-byte unchanged, as is `-o`.

## [0.3.0] - 2026-08-03

The review is now a full-screen interface. Piped and scripted use (`-y`, non-interactive
runs, exit codes, stdout purity) is unchanged; `--plain` keeps the classic prompt.

### Added

- Full-screen interactive review, the default on capable terminals: a table of every
  distinct value with its category, occurrence count and replacement. `space` keeps or
  scrubs the selected value, `a` fuzzy-finds additional text to scrub (any token from the
  input, or an exact pasted string), `r` chooses the replacement — the minted alias,
  `[REDACTED]`, or custom text — `y` shows a colored full diff before anything is
  emitted, and `q` aborts. Every change re-runs the scrubber with aliases held stable.
- Suspicious-but-unrecognised strings appear in the review as `warn` rows; one `space`
  promotes one to a real replacement everywhere it occurs.
- `--plain` to review with the classic line-mode y/N prompt.
- For embedders: `scrub()` accepts keyword-only `keep` and `overrides`, and a decisions
  layer (`Decisions`, `apply_decisions()`) re-scrubs with reviewer changes while a shared
  `AliasBook` keeps every already-minted alias stable. `render_diff()` and
  `render_residuals()` are public. Keeping a labelled secret also un-promotes its bare
  occurrences.

### Fixed

- The review now genuinely opens `/dev/tty`: `open("/dev/tty", "r+")` fails on every
  pty-backed terminal (update mode demands a seekable stream), so the review had always
  silently fallen back to stdio.

### Changed

- `textual` is now a runtime dependency.
- One `AliasBook` per run: interactive recomputes can never re-mint an existing alias.
- A confirmed review with amendments logs one `amended` event with kept/added/replaced
  counts.
- Detection is ~8% faster on worst-case-dense logs (2 MB: 2.754s → 2.539s): the matched
  rule is read from `Match.lastgroup` instead of probing every named group, and case
  matching no longer walks values character by character.

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

[Unreleased]: https://github.com/greenseeing/scrubbr/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/greenseeing/scrubbr/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/greenseeing/scrubbr/releases/tag/v0.2.0
