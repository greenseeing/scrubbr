# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A catalog of distinctive-prefix provider credentials is now scrubbed on sight: AWS access
  keys (`AKIA…`/`ASIA…`), GitHub classic and fine-grained tokens, GitLab, Slack bot/user
  tokens and webhooks, Discord webhooks, Stripe secret/restricted keys, Google API keys,
  SendGrid, OpenAI (`…T3BlbkFJ…`), Anthropic (incl. `oat01` OAuth), npm, PyPI and Azure
  storage `AccountKey=`. Each becomes a shape-preserving random look-alike, never a readable
  or deterministic alias. Public look-alikes are left alone by design — Stripe publishable
  keys (`pk_…`) and the AWS `AGPA/AIDA/AROA/AIPA` identity ids get no rule. For the URL- and
  label-shaped ones (webhooks, Azure) the readable host or `AccountKey=` label survives and
  only the credential portion is rewritten. Every pattern is bounded against catastrophic
  backtracking.
- Detection now sorts every match into one of three dispositions. **Scrub**: a credential
  with a distinctive prefix is actively removed — a GitHub token (`ghp_…`) becomes a random,
  shape-preserving look-alike, never a readable or reversible alias. **Warn**: a shape too
  collision-prone to rewrite safely — a Twilio API key (`SK` + 32 hex, indistinguishable from
  an MD5) — is shown in the review as a warn row with a line number rather than rewritten.
  Left alone: a public identifier that merely shares a shape, such as a Stripe publishable
  key (`pk_…`). `--strict` still refuses to emit while any warn row remains.
- `--also-host`, `--also-person` and `--also-project` type a declared name so its surrogate
  reads as its kind — `host-a`, `person-b`, `project-c` — instead of a generic `redacted-*`.
  A bare `--also` value with no hint stays `redacted-*`; casing collapses to one surrogate.

### Changed

- A `--also` name — anything scrubbr redacts that has no shape of its own — now becomes a
  distinguishable numbered surrogate (`redacted-a`, `redacted-b`, …) instead of the single
  `[REDACTED]` constant. Two declared names stay distinct and one name keeps the same
  surrogate at every occurrence, so `redacted-a could not reach redacted-b` stays
  followable. The same name written in different cases maps to one surrogate.
- Re-running scrubbr on an already-scrubbed file no longer keeps rewriting it: a minted
  readable surrogate (`redacted-a`, `host-b`), a scrubbed email and a documentation IP are
  all fixed points, and the random look-alike minted for a secret now carries a marker so a
  second pass never re-scrubs it or re-flags it as high entropy. Declaring a name that
  collides with a surrogate stem (`--also redacted`) is a fixed point too. (Shape-only
  surrogates — a random MAC, UUID or hex string — are still re-randomised on a re-scrub, as
  they always were.)

### Fixed

- The docs no longer imply a shared random seed reproduces the readable numbered aliases
  across runs. A seed reproduces the random shape replacements; the numbered surrogates are
  assigned in order of first appearance and reproduce only across a shared alias book.
- A large diagnostic can no longer wedge the scanner: the email rule bounded its local part
  (RFC 5321's 64-octet limit), removing quadratic backtracking on a long run of
  address-shaped characters that no other rule consumed.
- The IPv4 documentation-address pool (762 addresses) now warns when it overflows instead of
  silently wrapping two distinct source addresses onto one alias.

## [0.4.0] - 2026-08-04

Interactive runs now end in a file next to the input instead of a terminal full of
scrubbed text; pipes, redirections and `-o` are unchanged.

### Added

- When standard output is an interactive terminal and no `-o` is given, the cleaned text
  is written to `NAME.scrubbed.EXT` next to the input (`scrubbed.txt` for piped input)
  instead of being dumped onto the screen. The diff screen shows the destination and `e`
  edits it; the `--plain` prompt names it (`write scrubbed text to …? [y/N]`).

### Changed

- An interactive terminal never receives the scrubbed text on stdout; pipes and
  redirections are byte-for-byte unchanged, as is `-o`.

### Fixed

- The fuzzy finder (`a`) now sees every token in the file. The candidate pool was
  silently capped at the first 5000 distinct tokens, so anything deeper in a long log —
  a serial number, say — could never be found. Matching is now substring-first, which
  keeps every keystroke instant even on very large files.

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

[Unreleased]: https://github.com/greenseeing/scrubbr/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/greenseeing/scrubbr/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/greenseeing/scrubbr/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/greenseeing/scrubbr/releases/tag/v0.2.0
