# PRD: Broader secret detection & distinguishable redaction surrogates

*Derived from a research-and-documentation session. Full prior-art analysis:
[`docs/research/prior-art-secret-detection-and-pseudonymization.md`](docs/research/prior-art-secret-detection-and-pseudonymization.md).*

## Problem Statement

I paste Linux diagnostics into an LLM chat, and I rely on scrubbr to strip out
anything that identifies me or leaks a secret first. Two things let me down.

First, scrubbr misses secrets it should catch. It only actively removes a handful
of shapes (PEM, crypt hashes, JWTs) and values sitting behind ten hard-coded
keywords. A real journal or `dmesg` dump is full of things it walks straight past:
a GitHub or AWS or Slack token pasted into a script it was debugging, a
`Bearer` token in an HTTP trace, a `DATABASE_URL` with the password inline, my
machine-id, my hardware serial numbers, an SSH host-key fingerprint, my Wi-Fi PSK
in a `wpa_supplicant` debug hexdump. Some of these it only *warns* about instead
of removing; many it does not notice at all. Because scrubbr's own rule is that
"a silent false negative is a vulnerability," each of these is a bug.

Second, when scrubbr does redact something it can't otherwise shape — a server
name, a project codename, a colleague's name I passed with `--also` — it turns
every one of them into the exact same `[REDACTED]`. So a log that said
`prod-db-07 could not reach vault-02 as alice` becomes
`[REDACTED] could not reach [REDACTED] as [REDACTED]`, and the assistant (and I)
can no longer tell the three apart or follow which is which. scrubbr already makes
hostnames readable and distinct (`host-a`, `host-b`); the values I explicitly
flagged as most sensitive are the ones it flattens into mush.

## Solution

scrubbr gains a **three-tier detection model** and a **distinguishable-surrogate
replacement scheme**, both staying pure-offline, deterministic, and regex-based.

- Detection sorts every match into one of three dispositions: **SCRUB** (rewrite
  it), **WARN** (show it in the review as a suspicious-but-unrewritten row), or
  stays **REPORT-ONLY** for the low-confidence entropy net. High-confidence,
  distinctive-prefix credentials (GitHub, AWS, Slack, Stripe, Google, OpenAI,
  Anthropic, npm, PyPI, Azure, and friends) get actively scrubbed with a
  shape-preserving random look-alike. A broader, case-insensitive keyword family
  captures assignment-style secrets, but only rewrites the value when it also
  clears a length-and-entropy gate. Structured contexts — `Authorization` headers,
  `user:pass@host` URLs, database connection strings — get their own captures.
  And the Linux-diagnostic identifiers scrubbr's domain is full of (machine-id,
  boot-id, hardware serials, kernel `ip=`/`cloud-config-url=`, SSH fingerprints,
  Wi-Fi PSK hexdumps) become recognised kinds.

- Replacement stops collapsing everything unshaped into one constant. A redacted
  value becomes a **typed, numbered surrogate** — `redacted-a`, `redacted-b`, or,
  when I hint a role on `--also`, `host-a` / `person-b` / `project-c`. The same
  value always maps to the same surrogate and two different values never share
  one, so correlation is preserved exactly the way it already is for hostnames.
  Each surrogate is self-evidently synthetic, so I can still tell "scrubbr
  replaced this" from "scrubbr missed this" at the review, and re-running scrubbr
  on already-scrubbed text changes nothing.

The interactive review still shows me every proposed change, every warning, and
lets me keep, add, or re-target any of them before a single byte is emitted.

## User Stories

1. As someone pasting logs into an LLM, I want a GitHub token (`ghp_…`) in my log
   to be removed automatically, so that I don't leak a live credential.
2. As the same user, I want an AWS access-key id (`AKIA…`/`ASIA…`) recognised by
   its distinctive prefix and base32 tail, so that it never reaches the chat.
3. As the same user, I want Slack (`xoxb-…`), Stripe (`sk_live_…`), Google
   (`AIza…`), OpenAI (`sk-…T3BlbkFJ…`), Anthropic (`sk-ant-…`), npm (`npm_…`),
   PyPI (`pypi-…`), and Azure `AccountKey=` secrets scrubbed on sight, so that the
   common providers are covered without my configuring anything.
4. As the same user, I want a provider token replaced with a random look-alike of
   the same shape rather than a readable alias, so that the replacement can never
   act as a confirmation oracle for the real secret.
5. As the same user, I do NOT want a value that merely *looks* like a public
   identifier (a Stripe `pk_…` publishable key, a Twilio `AC…` Account SID)
   scrubbed, so that my logs stay readable and honest about what is actually
   sensitive.
6. As the same user, I want a secret assigned behind any casing or separator of a
   keyword — `apiKey`, `API_KEY`, `api-key`, `access-token`, `refreshToken` — to
   be caught, so that a naming style I didn't anticipate doesn't cause a leak.
7. As the same user, I want the keyword family widened to include `token`,
   `bearer`, `authorization`, `credential`, `oauth`, `dsn`, `connection_string`,
   and `DATABASE_URL`, so that modern secret names are covered.
8. As the same user, I want a bare keyword like `token=` to only trigger a rewrite
   when the value is long and high-entropy, so that `token=0` or `token=next` in a
   log is left alone.
9. As the same user, I want `Authorization: Bearer <token>` and
   `Authorization: Basic <base64>` headers in an HTTP trace scrubbed, so that
   captured request logs are safe to share.
10. As the same user, I want credentials embedded in a URL (`https://user:pass@host`)
    and in a DSN (`postgres://user:pass@…`, `mongodb+srv://…`) removed, so that a
    connection string in a log doesn't expose a password.
11. As the same user, I want my `/etc/machine-id` (32 hex, no dashes) and journald
    `_BOOT_ID`/`INVOCATION_ID` recognised, so that a stable machine fingerprint
    doesn't survive just because it isn't shaped like a UUID.
12. As the same user, I want hardware serial numbers (dmidecode system/board/chassis,
    disk serial/WWN, NVMe EUI, iSCSI IQN) scrubbed, so that my specific hardware
    can't be identified from a diagnostic dump.
13. As the same user, I want cloud metadata (AWS instance-id/account-id/ARNs, GCP
    project ids, Azure subscription/vm ids) scrubbed, so that pasting cloud-init or
    metadata output doesn't reveal my account.
14. As the same user, I want SSH host-key fingerprints (`SHA256:<base64>`)
    recognised, so that an sshd "Accepted publickey" line doesn't fingerprint my
    host.
15. As the same user, I want my Wi-Fi PSK caught even in the `wpa_supplicant`
    debug hexdump form (`PSK (ASCII passphrase) - hexdump_ascii(len=N): …`), which
    is not a `key=value` shape, so that verbose Wi-Fi logs are safe.
16. As the same user, I want anything that looks sensitive but that scrubbr is not
    confident enough to rewrite (a high-entropy blob, a 32-hex value that might be
    a hash or might be a secret) shown to me as a warning with a line number, so
    that nothing leaves silently.
17. As the same user, I do NOT want ordinary high-entropy diagnostic values — git
    SHAs, UUIDs, image digests, boot ids, base64 kernel data — rewritten, so that
    the log stays diagnosable.
18. As someone using `--also prod-db-07 --also vault-02`, I want each declared name
    replaced with a *distinct* surrogate, so that I can still tell the two machines
    apart in the scrubbed log.
19. As the same user, I want the *same* declared name replaced with the *same*
    surrogate at every occurrence, so that "A could not reach B" stays followable.
20. As the same user, I want `ProjectX` and `projectx` treated as one value, so
    that a casing difference doesn't split one name into two surrogates.
21. As the same user, I want to hint that a declared value is a host, a person, or
    a project (e.g. `--also-host prod-db-07`), so that its surrogate reads as
    `host-a` / `person-b` / `project-c` instead of a generic `redacted-*`.
22. As the same user, I want every surrogate to be obviously synthetic, so that at
    the review I can always distinguish a value scrubbr replaced from one it
    missed.
23. As the same user, I want to re-run scrubbr on an already-scrubbed file and get
    the same file back, so that sanitising twice is safe and surrogates are never
    re-scrubbed or re-warned.
24. As the same user, I want the surrogate scheme never to mint a value that
    coincides with a real credential shape or re-triggers detection, so that a
    replacement can't itself look like a secret.
25. As a privacy-conscious user, I want the value→surrogate mapping to stay in
    memory for the run and not be written to disk by default, so that there is no
    plaintext reverse-lookup table left behind.
26. As a careful reviewer, I want each proposed change tagged with its disposition
    tier (scrub / warn), so that I understand why scrubbr is or isn't rewriting a
    given value.
27. As a reviewer, I want to keep, add (`a`), or re-target (`r`) any finding as I
    can today, so that the new detection breadth never removes my final say.
28. As a scripting user, I want `--strict` to still refuse to emit while
    warn-tier suspicious strings remain, so that automated pipelines can gate on a
    clean result.
29. As a contributor, I want the secret patterns and keyword stems organised so
    they are easy to review and extend, so that adding a new provider is a small,
    auditable change.
30. As a maintainer, I want ported third-party regexes to run without catastrophic
    backtracking on a large dump, so that scrubbr can't be wedged by a pathological
    input.
31. As the same maintainer, I want the corrected (not the raw survey) regexes
    used, so that we don't scrub public identifiers or miss real secrets on day
    one.
32. As a user on an unusual log, I want a 32-hex value that could be an MD5 hash or
    a Twilio key handled by the WARN tier rather than silently rewritten, so that
    ambiguous shapes are surfaced, not guessed.
33. As a user, I want checksum/format validation (GitHub CRC32, JWT parse, Luhn)
    to only ever *downgrade* a match to a warning, never suppress it, so that a
    truncated token in a log is still flagged.
34. As a user, I want the documentation corrected so it no longer claims a shared
    seed reproduces readable surrogate labels across runs (it only reproduces
    random shape replacements), so that I don't rely on a guarantee that isn't
    true.

## Implementation Decisions

**Detection disposition model.** Introduce an explicit three-way disposition —
SCRUB, WARN, REPORT-ONLY — as a first-class attribute of a detection rule (and
therefore of the `Match` it produces), rather than today's implicit split where
structural/contextual rules always scrub and `residual.py` always reports. A rule
carries its disposition; the sweep in `scrub` routes SCRUB matches to the
`AliasBook`, and WARN matches into the residual/warning channel that already
feeds the review's `warn` rows. The gating criterion for allowing SCRUB is Nosey
Parker's: a shape may auto-rewrite only when it is *well-specified and
distinctive* (fixed prefix plus validated length/charset), or when a keyword
co-occurs with a value that clears a length+entropy gate.

**Provider-token rules.** Add a family of distinctive-prefix credential rules to
the structural rule set, using the **red-team-corrected** catalog (Appendix A.1 of
the research brief), not the raw survey regexes. These classify to a
secret-bearing kind whose replacement is a **shape-preserving random string** (the
existing `SECRET_VALUE` minting behaviour), never a readable or deterministic
alias — a deterministic alias of a real secret is a confirmation oracle. Public
identifiers that merely share a shape (Stripe `pk_`, Twilio `AC`) are explicitly
excluded. Collision-prone shapes (bare 32-hex Twilio `SK`) go to WARN, not SCRUB.

**Keyword capture.** Replace the fixed 10-word list with affix-wildcarded stems
(the detect-secrets `\w*`-affix approach) so one stem matches camelCase, kebab,
and SCREAMING variants, and widen the stem set (`token, bearer, authorization,
credential(s), oauth, refresh_token, dsn, connection_string, DATABASE_URL`, …).
The value capture must require a non-empty value and, for generic/bare stems,
gate the rewrite on value length (≥10) AND entropy (≥3.5); only then does it enter
SCRUB. This preserves the existing two-pass "promotion" so a value found behind a
keyword is also scrubbed where it later appears bare.

**Structured-context rules.** Add contextual rules for `Authorization: Bearer` /
`Authorization: Basic`, URL userinfo (`scheme://user:pass@host`), and DSN/URI
connection strings, capturing the credential portion.

**Linux-diagnostic kinds.** Add recognised kinds/rules for the domain's
identifiers: machine-id (32-hex, no dashes — a distinct shape from the dashed
UUID), boot-id/invocation-id, dmidecode and disk serials / WWN / NVMe EUI / iSCSI
IQN, kernel-cmdline `ip=` and `cloud-config-url=`, cloud instance/account/ARN
ids, SSH `SHA256:` fingerprints, and the `wpa_supplicant` debug PSK hexdump line.
Each is assigned SCRUB or WARN by the distinctiveness criterion.

**Entropy net (residual).** Split the single mixed-alphabet threshold into
per-charset thresholds (hex ~3.0, base64 ~4.5) after classifying the token's
charset, and add structural pre-exclusions (UUID, git-SHA, sequential strings,
id-like names, machine-id) before entropy fires. The entropy net stays
**WARN/REPORT-ONLY** — it never auto-scrubs.

**Replacement — the core fix.** `mint()`'s `REDACTED` branch must consume the
`index` it is already handed and emit a typed counter surrogate
(`redacted-a`, `redacted-b`, …), exactly like the existing `host-a` path;
`normalize()` gains a `REDACTED` case so keying is case-insensitive and
`ProjectX`/`projectx` share one surrogate. This makes `AliasBook`'s existing
"one value → one replacement, distinct values → distinct replacements" guarantee
apply to redacted names for free. Counter surrogates are collision-free and
non-reversible by construction.

**Surrogate typing via `--also` role hints.** Extend the `--also` mechanism with
optional role hints (e.g. host/person/project) that set the surrogate's kind so a
declared value reads as `host-a` / `person-b` / `project-c` instead of a generic
`redacted-*`. Absent a hint, values default to `redacted-*`.

**Self-advertising sentinel.** Surrogates carry a reserved, obviously-synthetic
marker (the same principle as the existing RFC 5737 / `example.invalid`
conventions) so they are provably fake, cannot re-trigger a detector, cannot
satisfy a provider checksum, and make re-runs idempotent. The exact form is an
open decision (see Further Notes).

**Bounded pools and mapping lifetime.** Bound the IPv4 documentation alias pool so
it warns/expands rather than silently wrapping. Keep the `AliasBook` mapping
in-memory per run by default; treat any persisted mapping as sensitive.

**Regex safety.** Any pattern ported from an RE2-based tool must run without
catastrophic backtracking under Python `re` — use bounded quantifiers (as the PEM
rule already does), atomic grouping, or the `regex` module. Rule precedence for
new overlaps (32-hex MD5 vs Twilio SK; UUID vs entropy; fingerprint vs hex) is
resolved within the existing alternation-order model.

## Testing Decisions

**A good test asserts external behaviour, not internals.** It drives real input
text through the public `scrub()` seam and asserts on the returned `ScrubResult`
(its `text`, `findings`, `residuals`, `counts`) — never on which rule fired or how
a regex is written. Determinism comes from a seeded `AliasBook(random.Random(n))`,
and no test mocks anything; fixtures are synthetic secret-shaped strings kept out
of the gitleaks allowlist by design.

**Seam.** Use the single existing high seam — `scrub(text, identity, book, keep=,
overrides=) -> ScrubResult` — for essentially all assertions. `detect()`,
`find_residuals()`, and `AliasBook` are lower seams available for focused unit
tests where a behaviour is hard to reach from the top (e.g. a property test on
surrogate collision-freeness), but the default and the prior art is the top seam.

**Modules tested.** `scrubbr/scrub.py` (end-to-end dispositions and nothing-leaks
invariants), `scrubbr/shapes.py` (surrogate minting/normalising), `scrubbr/detect.py`
(new rules, via `scrub()` output), `scrubbr/residual.py` (warn-tier and
per-charset entropy). Prior art already in the suite: `tests/test_scrub.py`
classes `TestNothingLeaks`, `TestResidualRisk`, `TestExtraLiterals`,
`TestReviewDecisions`, `TestConsistency`, `TestDeterministicAliasing`.

**New invariants to assert.**
- No sample provider token (each shape in the corrected catalog) survives in
  `result.text`.
- A public identifier that shares a shape (Stripe `pk_`, Twilio `AC`) is NOT
  rewritten.
- Two distinct `--also` names yield two distinct surrogates; one name yields one
  surrogate at every occurrence (correlation), and it is not the original.
- `ProjectX` and `projectx` collapse to a single surrogate.
- A surrogate is recognisably synthetic (carries the sentinel) and re-scrubbing
  `result.text` is a fixed point — no new findings, no new residuals.
- The entropy tier is warn-only: git SHAs, UUIDs, machine-data base64 appear in
  `residuals` (or are excluded) but are never rewritten.
- The "silent false negative is a vulnerability" guarantee: a matched-but-uncertain
  value always produces a residual rather than passing silently.
- Keyword captures fire across casing/separator variants and only rewrite bare
  generic stems when the value clears the length+entropy gate.
- A ReDoS regression fixture (a long adversarial run) completes within a sane time
  bound.

## Out of Scope

- **Live/network verification** of whether a detected secret is active — scrubbr
  is offline by definition.
- **Realistic (Faker-style) look-alike** replacements — a realistic fake is
  indistinguishable from a miss and defeats the human review gate.
- **Format-preserving encryption, cryptographic tokenization, and any keyed or
  reversible scheme** — key management is a non-goal; small-domain FPE is fragile.
- **Reversible round-trip re-insertion** of real values into the LLM's response
  (no persisted vault).
- **ML/NER free-text PII** (names embedded in prose, Bluetooth device aliases,
  GECOS full names) beyond what a positional/keyword context can catch — the
  no-ML, pure-regex constraint stands; these may at most be warn-tier.
- **Non-Linux log formats** and non-diagnostic corpora.
- **A declarative external rule file** — desirable but deferred (see Further Notes);
  detection stays in reviewed pure-Python for now.

## Further Notes

- **Sequencing.** The replacement-axis fix (P0: `mint()`/`normalize()` for
  `REDACTED`) is small, self-contained, and independently shippable ahead of the
  detection work; the three-tier model (P0) is the prerequisite for every new
  detection rule. Full prioritised roadmap (20 items) is in the research brief.
- **Open decisions the PRD deliberately leaves to implementation.**
  (1) The exact surrogate label scheme (`redacted-a` vs `REDACTED_1` vs typed
  `person-a`) and sentinel form (rare-Unicode marker vs an ASCII convention),
  balancing LLM-tokenizer friendliness, readability, and the risk that a label
  coincides with a real literal. (2) Whether to gate SCRUB-tier promotion of
  provider tokens behind validation on a scrubbr-specific fixture corpus first.
  (3) Rule-precedence policy for the new overlaps. (4) Whether a declarative
  TOML/YAML rule file is worth moving detection out of reviewed Python.
- **No benchmark exists** for secret detection on journald/dmesg corpora; every
  cited precision/recall number comes from source-code repos with different base
  rates. Building a small, synthetic Linux-diagnostic fixture corpus to tune
  thresholds and SCRUB-tier promotions is recommended before shipping active
  scrubbing of the broader patterns.
- **The closest maintained offline peer, `protectai/llm-guard`, was archived
  2026-07-09 with no successor** — scrubbr fills a real and currently-vacant niche
  (offline, Linux-diagnostics-specific, human-reviewed, deterministic look-alikes).
- **Publishing note.** This PRD would normally be filed to the project issue
  tracker with the `ready-for-agent` label; there is no `gh`/tracker access in
  this environment, so it is delivered as `PRD.md` in the repo root.
