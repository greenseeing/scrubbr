# Prior art: secret detection & pseudonymous replacement

*Research brief for improving scrubbr along two axes: (1) broaden and sharpen
secret/sensitive detection, and (2) replace the single collapsing `[REDACTED]`
constant with distinguishable, consistent surrogates.*

> **How this was produced.** A 12-agent research workflow (6 `deep-researcher` +
> 2 `docs-researcher` survey passes, 3 `peripheral-vision` adversarial red-team
> passes, 1 synthesis pass), followed by a targeted terminology backfill. Where
> the red-team refuted or nuanced a survey claim, this brief defers to the
> red-team and flags the correction. Every recommendation respects scrubbr's hard
> constraints: **offline, keyless, deterministic, pure-regex, "a silent false
> negative is a vulnerability," and "must not wreck log readability."** Sources
> are listed at the end. Confidence is medium-high; numeric rule counts are
> approximate and single-vendor benchmark figures are treated as directional.

---

## Executive summary

scrubbr's two weak spots — a thin 10-word keyword list plus warn-only
provider-token handling on the **detection** axis, and a single collapsing
`[REDACTED]` constant on the **replacement** axis — are both fixable with pure
offline regex plus a change to machinery scrubbr already owns.

The prior art strongly validates the direction. Every mature scanner (gitleaks,
detect-secrets, Nosey Parker, TruffleHog) converges on the same offline-portable
stack: **distinctive-prefix regexes, keyword pre-filters, and per-charset entropy
as a *secondary* AND-gate.** Nosey Parker's rule-authoring guidance supplies the
exact criterion scrubbr needs — a format is safe to **auto-rewrite** only when it
is *well-specified AND distinctive* (fixed prefix + validated length/charset);
everything else must be context-gated or warn-only.

The single most important reframing, surfaced by the red-team, is the
**scanner-vs-rewriter mismatch**: gitleaks/detect-secrets tolerate 46–54%
precision because a human triages every hit, whereas scrubbr *silently rewrites*.
Their regexes therefore cannot be imported into an active-scrub tier verbatim —
several surveyed patterns were refuted outright (see [Red-team corrections](#red-team-corrections)).

On the **replacement** axis the fix is nearly free: scrubbr's `AliasBook` already
implements the exact Presidio/scrubadub counter pattern for every `Kind` except
`REDACTED`, whose `mint()` throws away the index it is handed
(`scrubbr/shapes.py:132-133`).

---

## How scrubbr works today

*(Verified against the repository this session.)*

- **Detection, actively scrubbed:** PEM blocks, crypt/openssl hashes (`$6$…`),
  JWTs (`eyJ…`), plus MAC, UUID, IPv4/6, email, SSID, disk-id, cert fingerprint,
  hostname/username/machine-id. Keyword capture uses a fixed 10-word list
  (`psk, password, passwd, secret, api_key, apikey, access_token, auth_token,
  client_secret, private_key`) with a single `keyword = value` regex whose value
  is a run of non-space/quote/comma/semicolon chars.
- **Detection, report-only** (`scrubbr/residual.py`, "Reported, never
  rewritten"): `MIN_TOKEN_CHARS = 20`, `MIN_ENTROPY_BITS = 3.5`,
  `TOKEN = [A-Za-z0-9_\-./+=]{20,}`, a 17-entry `CREDENTIAL_PREFIXES` list, and
  one crude structural exclusion (`"/" in token or token.count(".") > 1`).
  Provider tokens are **warned, never scrubbed**. No charset-specific threshold,
  no UUID/SHA pre-exclusion, no keyword-proximity signal.
- **Replacement:** `shapes.mint()` mints shape-preserving aliases per kind (valid
  locally-administered MAC; version/variant-preserving UUID; RFC 5737
  documentation IPv4; same-length/case hex). Named kinds get readable counter
  aliases (`host-a`, `user-a`, `network-a`) via `_letters(index)`.
  `Kind.SECRET_VALUE` gets a random same-length alphanumeric/hex string.
  **`Kind.REDACTED` (`shapes.py:132-133`) hardcodes `return "[REDACTED]"` and
  discards the `index` argument** — the single point of collapse. `AliasBook`
  (`scrubbr/alias.py`) keys `_canonical` on `(Kind, normalized_text)` and tracks
  a per-kind counter via `_next()`; `normalize()` (`shapes.py:75-84`) has **no
  `REDACTED` case**, so that key is currently case-sensitive.
- **Human gate:** an interactive TUI diff before emit, so "report but do not
  rewrite" is an acceptable fallback for low-confidence detections.

---

## Prior art by tool

| Tool | Architecture | Offline? | Pseudonymizes? | Lesson for scrubbr |
|---|---|---|---|---|
| **gitleaks** | ~150–250 curated regex rules + keyword pre-filter + per-rule entropy AND-gate; v8.28 composite `[[rules.required]]` proximity rules | Yes (RE2) | No | Authoritative corrected regexes; entropy is never a standalone trigger. **RE2 patterns can ReDoS in Python `re`.** |
| **detect-secrets** | 26–27 plugins: RegexBased + HighEntropyStrings + KeywordDetector | Yes | No | Affix-wildcarded keywords (`api_?key` + `\w*`); per-charset entropy (Base64 4.5 / Hex 3.0); `is_potential_uuid` structural filters; `# pragma: allowlist secret`. |
| **Nosey Parker** | ~90 rules, capture-group discipline, ML denoiser | Yes (Hyperscan) | No | **The distinctive-vs-non-distinctive criterion** that should gate scrubbr's SCRUB tier. |
| **TruffleHog** | 700–800+ detectors, live verification | Verification needs network; `--no-verification` disables | No | verified/unverified/unknown as permanent first-class state → validates a permanent warn tier. |
| **Semgrep Secrets / GitGuardian** | dataflow + cloud ML denoise/relabel | No (cloud) | No | keyword→scan-nearby and broad-catch-then-relabel patterns are transferable *in spirit only*. |
| **Presidio** | PII NER + operators (replace/redact/mask/hash/encrypt/custom) | Yes (local) | **Via custom InstanceCounterAnonymizer** | The canonical `{TYPE:{value:<TYPE_N>}}` counter pattern scrubbr already mirrors. No secret detection out of the box. |
| **scrubadub** | dict-backed `Lookup` counter; `FilthReplacer` `{{TYPE-N}}` | Yes | **Yes, natively** | `table[key]=len(table)`, key `(type, text.lower())` — structurally identical to `AliasBook`. |
| **Google DLP / AWS Comprehend / Nightfall** | crypto tokenization or bare-type labels | No (cloud/keys) | Crypto only | **Ruled out:** key management forbidden; bare labels are the failure mode scrubbr is fixing; the rare-Unicode-prefix sentinel idea is worth borrowing. |
| **protectai/llm-guard** | closest offline analog: regex + optional ML + Vault round-trip | Yes | Yes | **Archived 2026-07-09, no successor** — scrubbr fills a real vacancy but has no maintained peer. |

---

## Axis 1 — Detection

### Findings

1. **Distinctiveness, not "is it a secret," is the safe active-scrub criterion.**
   Nosey Parker distinguishes distinctive-prefix formats (AWS `AKIA` + base32,
   safe with regex alone) from UUID-shaped non-distinctive formats (regex alone
   unsafe). This is the gating criterion scrubbr should key its tiers on.
2. **Entropy is necessary-but-leaky and must stay warn-only.** All surveyed tools
   feed entropy hits into human/CI review, never auto-rewrite. UUIDs, git SHAs,
   image digests, boot/invocation IDs, DHCP DUIDs, and TPM/EFI base64 all exceed
   3.5 bits in ordinary Linux logs — active-scrubbing them would destroy
   diagnosability. scrubbr's "reported, never rewritten" policy is already
   correct and should stay.
3. **scrubbr's single 3.5-bit threshold over a mixed alphabet is miscalibrated** —
   ~87.5% of hex's 4.0 bits/char ceiling (too strict for hex) and ~58% of the
   mixed ceiling (too loose for base64). Splitting into hex ~3.0 / base64 ~4.5
   *after* classifying the charset is the established fix.
4. **Affix-wildcarded keywords close the camelCase/kebab/SCREAMING gap** with pure
   offline regex; scrubbr's value-capture regex also under-captures (allows an
   empty match, stops at quotes) versus detect-secrets' non-empty requirement.
5. **Linux diagnostics carry a large missed-identifier class** with no keyword
   trigger and no matching shape rule (`/etc/machine-id` 32-hex-no-dash,
   `_BOOT_ID`, dmidecode serials, `/proc/cmdline ip=` / `cloud-config-url=`, SSH
   `SHA256:` fingerprints, wpa_supplicant debug PSK hexdumps) — silent false
   negatives under scrubbr's own policy. See [Appendix A.4](#a4--linux-diagnostic-identifiers-domain-specific).

### Recommendations (red-team-corrected)

- **P0 — Three-tier result model (SCRUB / WARN / REPORT-ONLY) keyed on
  distinctiveness.** Make scrubbr's existing implicit split explicit and
  auditable. *(Nosey Parker, TruffleHog, Semgrep.)*
- **P0 — Promote validated distinctive-prefix tokens to SCRUB** with the
  *corrected* regexes in [Appendix A.1](#a1--corrected-distinctive-prefix-token-catalog-scrub-tier).
  *(gitleaks, Nosey Parker, GitHub token blog.)*
- **P0 — Affix-wildcarded keyword capture, value length+entropy-gated before any
  rewrite;** bare stems (`key/token/session/cert/connection/dsn`) never enter
  SCRUB ungated. *(detect-secrets KeywordDetector, gitleaks generic-api-key.)*
- **P1 — Structural pre-exclusion (UUID / git-SHA / machine-id) + keyword-adjacency
  gate before entropy fires.** *(detect-secrets `is_potential_uuid`, gitleaks
  v8.28 composite rules, Basak et al.)*
- **P1 — Per-charset entropy thresholds (hex ~3.0 / base64 ~4.5), warn-only.**
  *(detect-secrets, TruffleHog.)*
- **P1 — Per-context capture** for `Authorization: Bearer/Basic`, URL userinfo,
  and DSNs. *(gitleaks, detect-secrets BasicAuth, RFC 6750/3986.)*
- **P1 — Cover Linux-diagnostic identifiers** (machine-id, boot-id, dmidecode
  serials, cmdline `ip=` / `cloud-config-url=`, SSH fingerprints, wpa debug PSK).
  *(systemd.journal-fields(7), machine-id(5), kernel/cloud-init docs, ssh-keygen(1).)*
- **P1 — Port RE2 patterns through a Python-ReDoS-safe path** (atomic groups or
  the `regex` module) — RE2 has no catastrophic backtracking, Python `re` does.
  *(gitleaks RE2 note.)*
- **P2 — Offline checksum/format validation that only DOWNGRADES to warn, never
  suppresses** (logs truncate tokens; suppression would violate "silent false
  negative is a vulnerability"). *(GitHub base62+CRC32, detect-secrets JWT parse,
  Luhn.)*
- **P2 — Inline-suppression comments + local allowlist file.** *(gitleaks
  `# gitleaks:allow`, detect-secrets `# pragma: allowlist secret`, git-secrets
  `.gitallowed`.)*
- **P2 — BPE token-efficiency as a warn-tier experiment only.** *(Betterleaks /
  Aikido — mechanism only; the tool itself is not offline, and the recall figure
  is an unreviewed vendor claim.)*

---

## Axis 2 — Replacement

### The concrete scheme

Replace the `[REDACTED]` constant with **typed, distinguishable, consistent
counter surrogates** minted through the existing `AliasBook`:

- **Consistency & correlation.** `AliasBook._canonical[(kind, normalized)]`
  already guarantees "one value → one replacement." Making `mint()`'s `REDACTED`
  branch consume `index` yields `redacted-a`, `redacted-b`, … (matching the
  `host-a` convention). With a `--also` role hint, values can type as
  `person-a`, `host-b`, `project-a`.
- **Collision.** Counter labels are **collision-free by construction** (each new
  value takes the next index) — strictly safer than the shape-random kinds, which
  can birthday-collide. Separately, bound the IPv4 pool so it does not silently
  wrap at 762 addresses.
- **Reversibility.** Counter labels are **non-reversible by construction** (the
  label carries zero bits of the original). The only reversibility vector is the
  persisted `_canonical` mapping — inherent to all consistent pseudonymization;
  keep it in-memory per run by default.
- **Self-advertising sentinel.** Embed a reserved sentinel (analogous to
  RFC 5737 / `example.invalid`) so surrogates are provably fake, idempotent on
  re-run, and cannot re-trigger the detector or accidentally satisfy a provider
  checksum. See [Appendix B](#appendix-b--pseudonymization-terminology--techniques)
  for why this matters.

### Findings

1. **`AliasBook` already IS the Presidio/scrubadub pattern.** Presidio's
   `InstanceCounterAnonymizer` (`{TYPE:{value:<TYPE_N>}}`) and scrubadub's
   `Lookup` (`table[key]=len(table)`, key `(type, text.lower())`) are the same
   dict-keyed-on-(type,text) counter as `_canonical`/`_next`. The only bug is
   `mint()` discarding the index for `REDACTED`.
2. **No scanner in the detection genre pseudonymizes** — the replacement axis has
   no scanner feature to copy; the move is to extend scrubbr's *own* counter
   machinery uniformly to `REDACTED`.
3. **Realistic look-alikes are the wrong call for a review-gated tool.** A Faker
   look-alike is indistinguishable from a *miss* — it defeats the human review
   gate, whose whole job is to let a reader tell "replaced" from "leaked."
   Self-evidently-synthetic typed labels are safer here even though a chat model
   reads either fluently.
4. **Faker, FPE/crypto tokenization, and deterministic aliasing of genuine
   secrets are all ruled out** (key management forbidden; small-domain FPE
   fragile; a deterministic surrogate for a secret is a confirmation oracle). See
   [Appendix B](#appendix-b--pseudonymization-terminology--techniques).

### Recommendations

- **P0 — Fix `mint()` `REDACTED` to consume `index`** → typed counter surrogate.
  *(Presidio, scrubadub.)*
- **P0 — Add a `REDACTED` case to `normalize()`** (case-insensitive) so
  `ProjectX` / `projectx` do not re-fragment into two surrogates.
  *(scrubadub `(type, text.lower())` keying.)*
- **P1 — `--also` role/kind hint** so declared names type as person / host /
  project instead of a generic `redacted-*`. *(Presidio entity_mapping, scrubadub
  type-scoped counters.)*
- **P1 — Non-colliding self-advertising sentinel** in surrogates.
  *(Google DLP rare-Unicode prefix; scrubbr's own synthetic ranges.)*
- **P1 — Bound the IPv4 alias pool** (warn / expand on overflow). *(scrubbr
  internal-coherence requirement.)*
- **P1 — Keep `Kind.SECRET_VALUE` on random same-length replacement** —
  deterministic aliasing of a real secret is a confirmation oracle. *(red-team
  threat model.)*
- **P2 — No Faker look-alikes** (documented non-goal): a realistic fake is
  indistinguishable from a miss and defeats the review gate.
- **P2 — No FPE / crypto tokenization** (documented non-goal): key management is
  forbidden; small-domain FPE is fragile.
- **P2 — Keep the mapping in-memory by default;** any persisted `AliasBook` is a
  plaintext reverse-lookup crown-jewel. Correct the docs: a shared *seed* alone
  does **not** reproduce order-dependent counter labels (only RNG-driven shape
  kinds are seed-reproducible).

---

## Red-team corrections

**Detection artifacts that must NOT ship as originally surveyed:**

- **Stripe:** drop `pk_` — `pk_live` / `pk_test` are *publishable* (public) keys.
  Use `(sk|rk)_(test|live|prod)_[a-zA-Z0-9]{10,99}`.
- **Slack:** hyphens, not underscores —
  `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`,
  `xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}`.
- **Twilio:** drop `AC…` (Account SID is a **public identifier**, not a secret;
  `AC` + 32-hex misfires on MD5-length hex). Keep `SK[0-9a-fA-F]{32}` in **WARN
  only** — 32-hex collides with hashes/IDs ubiquitous in logs.
- **OpenAI:** restore the `T3BlbkFJ` infix anchor —
  `sk-(proj|svcacct|admin)-…T3BlbkFJ…`; prefix + length alone is loose/FP-prone.
- **PyPI:** anchor on the macaroon header `pypi-AgEIcHlwaS5vcmc[\w-]{50,}` —
  `pypi-…{10,}` misfires on any `pypi-` log string.
- **npm:** exactly `npm_[A-Za-z0-9]{36}` (fixed length), not `npm_…{32,}`.
- **AWS:** the 16-char tail is **base32 `[A-Z2-7]`**, not "alphanumeric" /
  `[A-Z0-9]` (0/1/8/9 never appear). `AGPA/AIDA/AROA/AIPA` are identity IDs, not
  access keys — keep them out of a credential tier. Also: the prefix catches the
  *less* sensitive half — the real 40-char AWS **secret** access key has no prefix
  and is catchable only by keyword+entropy.
- **Bare keywords** (`key/token/api/auth/session/cert/connection/dsn`) only ever
  with a value length-gate (≥10) **and** entropy-gate (≥3.5); gitleaks only
  tolerates them because `generic-api-key` enforces both, and detect-secrets
  avoids them entirely.
- **Checksum validation must only downgrade to warn, never suppress** — logs
  truncate tokens, and suppression would violate "silent false negative is a
  vulnerability."
- **Single-vendor numbers are directional only.** The "28k vs 7k false positives"
  and "98.6% vs 70.4% recall" figures are single-source vendor blog claims — keep
  the qualitative direction, drop the number. The gitleaks 46% precision figure
  bounds generic-rule risk, not scrubbr's expected precision (no benchmark
  measures secret detection on journald/dmesg).

**Replacement corrections:**

- The one-line `mint()` fix is **necessary but not sufficient** — `normalize()`
  needs a `REDACTED` case or case variants re-fragment into distinct surrogates.
- **"Consistent across runs if a seeded `AliasBook` is shared" is inaccurate for
  counter labels** — indices are order-of-first-appearance dependent, not
  content-derived; only RNG-driven shape kinds are seed-reproducible. (Fixing
  scrubbr's own docs is part of this.)
- **Do not call DLP's FFX-FPE "broken"** — the Durak–Vaudenay cryptanalysis broke
  FF3 (prompting FF3-1), not FF1/FFX; the correct framing is *small-domain
  fragility*.

**Missed factors the red-team added:**

- **Scanner-vs-rewriter mismatch** — recalibrate confidence tiers around
  rewrite-safety, not scan-recall.
- **Prefix detection catches the LESS sensitive half** — the catalog over-weights
  prefixes; keyword+entropy is what catches the prefixless 40-char secrets.
- **Python ReDoS** on RE2-ported nested quantifiers over large dumps.
- **Rule precedence/overlap** with existing kinds (32-hex MD5 vs Twilio SK; UUID
  vs entropy; fingerprints are hex) is unspecified.
- **Alert fatigue defeats the human gate** — pre-exclusions and allowlists are
  load-bearing, not niceties.
- **OAuth/server token variants** matter for scrubbr's exact corpus
  (`sk-ant-oat01-`, `gho_/ghu_/ghs_/ghr_`, `xoxe-/xoxa-`).
- **Two-axis self-collision** — random `SECRET_VALUE` surrogates can trip the
  residual entropy scanner on re-run; the sentinel and the written-span exclusion
  must cover this.
- **Human-review-gate degradation** — any valid-but-unmarked replacement weakens
  the reviewer's ability to tell "replaced" from "missed" → argues for a visible
  sentinel.

---

## Prioritized roadmap

| # | Axis | Recommendation | Effort | Priority |
|---|---|---|---|---|
| 1 | Replacement | Fix `mint()` `REDACTED` to consume `index` (typed counter surrogate) | S | P0 |
| 2 | Replacement | Add `REDACTED` case to `normalize()` (case-insensitive keying) | S | P0 |
| 3 | Detection | Three-tier model (SCRUB / WARN / REPORT-ONLY) keyed on distinctiveness | M | P0 |
| 4 | Detection | Promote validated distinctive-prefix tokens to SCRUB (corrected regexes) | M | P0 |
| 5 | Detection | Affix-wildcarded keyword capture, value length+entropy-gated | M | P0 |
| 6 | Replacement | `--also` role/kind hint → typed surrogates | M | P1 |
| 7 | Detection | Structural pre-exclusion + keyword-adjacency gate before entropy | M | P1 |
| 8 | Detection | Per-charset entropy thresholds (hex ~3.0 / base64 ~4.5), warn-only | M | P1 |
| 9 | Detection | Per-context capture (headers, URL userinfo, DSNs) | M | P1 |
| 10 | Detection | Cover Linux-diagnostic identifiers (machine-id, boot-id, serials, cmdline, SSH fp) | L | P1 |
| 11 | Detection | Python-ReDoS-safe regex engine / atomic groups | S | P1 |
| 12 | Replacement | Non-colliding self-advertising sentinel | M | P1 |
| 13 | Replacement | Bound IPv4 alias pool (warn / expand on overflow) | S | P1 |
| 14 | Replacement | Keep `SECRET_VALUE` random (no deterministic aliasing of secrets) | S | P1 |
| 15 | Detection | Offline checksum / Luhn validation, downgrade-only | M | P2 |
| 16 | Detection | Inline-suppression comments + local allowlist | S | P2 |
| 17 | Detection | BPE token-efficiency warn-tier experiment | L | P2 |
| 18 | Replacement | No Faker look-alikes (documented non-goal) | S | P2 |
| 19 | Replacement | No FPE / crypto tokenization (documented non-goal) | S | P2 |
| 20 | Replacement | In-memory mapping default; persistence = crown-jewel | S | P2 |

---

## Open questions

1. **No benchmark exists for secret detection on Linux diagnostic logs.** All
   cited numbers come from source-code / git-repo corpora with different base
   rates; SCRUB-tier promotions and imported thresholds must be re-tuned on a
   scrubbr-specific corpus before shipping active-scrub.
2. **Label scheme** (`redacted-a` vs `REDACTED_1` vs typed `person-a`) and
   **sentinel form** (rare-Unicode vs ASCII) need a decision balancing LLM
   tokenizer friendliness, log readability, and reversal-ambiguity if a label
   coincides with a real literal.
3. **Rule precedence** between new secret rules and existing kinds (32-hex MD5 vs
   Twilio SK; UUID vs entropy; fingerprints are hex) is unspecified — an
   arbitration policy is an open design question.
4. **Two-axis self-collision** — does `find_residuals`' written-span exclusion
   fully cover multi-pass / re-run, or is sentinel-based exclusion also needed?
5. **Free-text PII** (Bluetooth Alias, GECOS names) — positional-context +
   warn-only, or out of scope, given the no-ML constraint?
6. **Declarative rule file** (TOML/YAML) for prefixes/keywords — lowers the
   contribution barrier, but moves detection out of reviewed pure-Python code.
7. **Round-trip re-insertion** — a permanent non-goal given the no-vault
   constraint? The closest maintained offline peer (llm-guard) was archived
   2026-07-09 with no successor.

---

## Appendix A — Concrete reference artifacts

> These are implementation-ready specifics extracted from the survey. **The
> token catalog below is the RED-TEAM-CORRECTED set** — several raw survey
> regexes (Stripe `pk_`, Twilio `AC`, loose npm/PyPI) were overruled and are
> **not** reproduced here. Patterns are given in Python-`re` syntax; anything
> ported from gitleaks (RE2) must be checked for catastrophic backtracking first.

### A.1 — Corrected distinctive-prefix token catalog (SCRUB tier)

High-confidence, near-zero-collision, safe to auto-rewrite with a shape-preserving
random replacement:

| Provider | Pattern | Notes |
|---|---|---|
| AWS access key id | `\b(AKIA\|ASIA)[A-Z2-7]{16}\b` | tail is **base32**, not alphanumeric. Exclude `AGPA/AIDA/AROA/AIPA` (identity IDs). |
| GitHub PAT/OAuth | `\b(ghp\|gho\|ghu\|ghs\|ghr)_[0-9A-Za-z]{36}\b`, `github_pat_[0-9A-Za-z_]{82}` | base62 + trailing CRC32 checksum available for downgrade-validation. |
| GitLab PAT | `glpat-[0-9A-Za-z_-]{20,}` | `gloas-` (OAuth) unconfirmed — verify before adding. |
| Slack | `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`, `xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}` | hyphens; gitleaks default is broader `xox[baprs]-…`. |
| Stripe secret/restricted | `(sk\|rk)_(test\|live\|prod)_[a-zA-Z0-9]{10,99}` | **`pk_` dropped — publishable/public.** |
| Google API key | `\bAIza[0-9A-Za-z_-]{35}\b` | |
| SendGrid | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` | |
| OpenAI | `sk-(proj\|svcacct\|admin)-[A-Za-z0-9_-]*T3BlbkFJ[A-Za-z0-9_-]*` | **`T3BlbkFJ` infix anchor required.** |
| Anthropic | `sk-ant-(api03\|oat01)-[a-zA-Z0-9_-]{93}AA` | include OAuth `oat01` variant. |
| npm | `npm_[A-Za-z0-9]{36}` | **fixed length 36.** |
| PyPI | `pypi-AgEIcHlwaS5vcmc[\w-]{50,}` | **macaroon header anchor.** |
| Azure storage | `AccountKey=[A-Za-z0-9+/]{88}==` | |
| Slack webhook | `https://hooks\.slack\.com/(?:services\|workflows\|triggers)/[A-Za-z0-9+/]{43,56}` | URL-shaped. |
| Discord webhook | `https://discord\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_-]{10,}` | URL-shaped. |
| JWT | `eyJ[0-9A-Za-z_-]{7,}\.[0-9A-Za-z_-]{7,}\.[0-9A-Za-z_-]{10,}={0,2}` | already covered by scrubbr. |
| Private key PEM | `(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY-----[\s\S]{64,}?-----END…` | already covered by scrubbr. |

**WARN-only (too collision-prone to auto-scrub):**
`SK[0-9a-fA-F]{32}` (Twilio API key — 32-hex collides with MD5/IDs).

### A.2 — Keyword capture (GATED tier)

- **detect-secrets `KeywordDetector` denylist** (with `AFFIX_REGEX = \w*`, so one
  stem matches `api_key` / `apikey` / `API_KEY` / `apiKey`):
  `api_?key, auth_?key, service_?key, account_?key, db_?key, database_?key,
  priv_?key, private_?key, client_?key, db_?pass, database_?pass, key_?pass,
  password, passwd, pwd, secret, contraseña, contrasena`.
- **gitleaks `generic-api-key` keywords:** `access, api, auth, key, credential,
  creds, passwd, password, secret, token`; captured value length 10–150 chars;
  per-rule `entropy = 3.5`.
- **Value-capture discipline:** require a non-empty value; a bare stem
  (`key/token/session/cert/connection/dsn`) enters SCRUB only with a **value
  length-gate (≥10) AND entropy-gate (≥3.5)** — never on the keyword alone.
- **scrubbr's current 10-word list is missing:** `bearer, authorization, token
  (bare), credential(s), oauth, refresh_token, dsn, connection_string /
  DATABASE_URL`, and all camelCase/kebab/SCREAMING variants.
- **Structured contexts worth dedicated rules:** `Authorization: Bearer <t>` and
  `Authorization: Basic <b64>` (RFC 6750/7617), URL userinfo
  `scheme://user:pass@host` (RFC 3986), and DSN/URI schemes `postgres://`,
  `mysql://`, `mongodb(+srv)://`, `redis://`, `amqp://` with `user:pass@`.

### A.3 — Entropy thresholds (WARN tier)

- **Charset ceilings:** hex `log2(16) = 4.0` bits/char; base64 `log2(64) = 6.0`
  bits/char. Classic thresholds sit at ~75% of ceiling.
- **detect-secrets defaults:** `Base64HighEntropyString limit = 4.5`,
  `HexHighEntropyString limit = 3.0`; hex all-digit compensation
  `entropy -= 1.2 / log2(len)`.
- **Original TruffleHog:** `b64 > 4.5`, `hex > 3.0`, min length 20.
- **gitleaks per-rule examples:** `generic-api-key = 3.5`, `1password = 3.8`,
  `artifactory = 4.5`, `adobe-client-id = 2`.
- **Structural pre-exclusions** (borrow from detect-secrets `filters/heuristic`):
  `is_potential_uuid` (`[a-f0-9]{8}-…-[a-f0-9]{12}`), `is_sequential_string`,
  `is_likely_id_string` (`(^(id|myid|userid)|_id)s?[^a-z0-9]`),
  `is_lock_file`, `is_not_alphanumeric_string`.
- **English-word filter:** minimum word length 4–5 (NDSS 2019 Meli et al. used 5;
  detect-secrets #240 arrived at 4) to drop dictionary-word false positives.
- **BPE token-efficiency (experimental):** `len(string) / len(BPE tokens)` with
  `cl100k_base`; Aikido threshold 2.5 (2.1 for <12 chars). Warn-tier only; the
  tokenizer vocab would have to be bundled to stay offline.

### A.4 — Linux-diagnostic identifiers (domain-specific)

Silent false negatives today — no keyword trigger and no matching shape rule:

| Source | Pattern / context | Identifying? |
|---|---|---|
| `/etc/machine-id`, dbus machine-id | exactly 32 lowercase hex, **no dashes** (distinct from dashed UUID) | high |
| journald trusted fields | `_BOOT_ID=`, `_SYSTEMD_INVOCATION_ID=` / `INVOCATION_ID=` = 32-hex; `_MACHINE_ID=`; `_AUDIT_LOGINUID=`, `_AUDIT_SESSION=` | high |
| dmidecode / sysfs | `Serial Number:` (DMI types 1/2/3); `/sys/class/dmi/id/{product,board,chassis}_serial`, `product_uuid` | high |
| `/proc/cmdline` | `root=UUID=<dashed-uuid>` (→ existing UUID kind); `ip=<client>:<server>:<gw>:<mask>:<hostname>:<dev>…` (kernel/dracut); `cloud-config-url=<url>` | high |
| disk identity | `lsblk -o SERIAL,WWN`; smartctl `LU WWN Device Id: 5 …` (NAA); NVMe `eui.<16-hex>`; iSCSI IQN `iqn.yyyy-mm.<rev-domain>:<name>`; LUKS UUID | high |
| cloud metadata | AWS `i-[0-9a-f]{8,17}`, 12-digit account id, ARNs `arn:aws:…:<12-digit>:…`; GCP project-id / numeric-project-id; Azure IMDS `subscriptionId`/`vmId` (UUIDs) | high |
| SSH | host-key fingerprint `SHA256:<43-char base64, no padding>` (ssh-keygen `-lf`, sshd "Accepted publickey") | medium |
| containers/k8s | Docker container id 64-hex (or 12-hex short); image digest `sha256:<64-hex>`; k8s service-account JWT (`eyJ…`, already matched if bare) | medium |
| Wi-Fi | `psk="…"` (wpa_supplicant.conf, `.nmconnection`); `wpa_passphrase` leftover `#psk="…"`; **debug hexdump** `PSK (ASCII passphrase) - hexdump_ascii(len=N): …` (non-`key=value` shape); nearby-BSSID lists (geolocation) | high |
| Bluetooth | BD_ADDR (existing MAC shape); device Name/Alias free-text (often an owner's first name, e.g. "John's AirPods") | medium |
| network id | DHCPv6 DUID-LLT hex string; nmcli nearby-AP BSSID list | medium |
| geolocation | geoclue `Latitude:`/`Longitude:`/`Accuracy:`; NMEA `$GPGGA`/`$GPRMC` | high |
| mobile | ModemManager IMEI (15-digit, Luhn), ICCID (19–22 digit, `89…`, Luhn), MSISDN/own-number | high |
| accounts | GECOS 5th `/etc/passwd` field: `full name, room, office phone, home phone, …` | high |

---

## Appendix B — Pseudonymization terminology & techniques

*Backfilled by a targeted research pass (see provenance note). Fills the one
survey facet that returned a stub.*

### B.1 — Definitions

| Term | Definition | Source |
|---|---|---|
| **Anonymization** | Rendering data so the subject "is not or no longer identifiable"; the result falls entirely outside data-protection scope. Only the *end state* is defined, not a process. | GDPR Recital 26 |
| **Pseudonymisation** | Processing so data "can no longer be attributed to a specific data subject without the use of additional information," which is kept separate and safeguarded. | GDPR Art. 4(5); ISO 25237 |
| **De-identification** | Umbrella category: removing the association between identifying attributes and the subject. Pseudonymization, masking, and tokenization are *species* of it. | ISO/IEC 20889 §3.6–3.7; NISTIR 8053 |
| **Tokenization** | Substituting a value with a meaningless reference token that maps back only via a securely held vault. Not separately codified in GDPR/ISO 20889/NIST — ISO folds it into "creation of pseudonyms." | Industry consensus |
| **Masking** | Obscuring part or all of a value (truncation, char substitution). NIST's closest formal term is "obscured data." ISO 20889 files it under suppression. | NIST CSRC Glossary; ISO 20889 §9.3.2 |
| **Redaction** | Full removal/suppression of a value's content — the strongest suppression, no structured substitution. **This is scrubbr's current `[REDACTED]` behaviour.** | practitioner term; NIST SP 800-188 |

**Regulatory nuance that bears on scrubbr's design:** pseudonymised data *remains
personal data* under GDPR because it is still linkable via the retained mapping.
Only true anonymization removes it from scope. Any deterministic, reversible-in-
principle mapping (hash table, HMAC, FPE) keeps the sanitized log in the same
regulatory category as the original *unless the mapping/key is destroyed*. This is
an argument for scrubbr keeping its `AliasBook` mapping in-memory and per-run —
and for surrogates that carry **no recoverable information** about the original.

### B.2 — Format-preserving encryption (ruled out)

FF1 and FF3/FF3-1 (NIST SP 800-38G) are AES-based Feistel modes that encrypt a
value into ciphertext of the *same format and length*. They buy schema
compatibility, not freedom from key custody: both use a secret AES key plus a
non-secret tweak, so they are keyed and reversible — exactly the burden an
offline, keyless tool avoids.

**Corrected attribution** (the survey and the original prompt garbled this):

- **Bellare, Hoang, Tessaro (CCS 2016)** — a *generic* message-recovery attack on
  Feistel-based FPE affecting **both FF1 and FF3** at very small domains; not
  practical at recommended sizes.
- **Durak & Vaudenay (CRYPTO 2017)** — a *dedicated, practical total break of
  **FF3 specifically*** (bad tweak domain-separation / slide attack). **Does not
  apply to FF1.** This is what forced NIST to revise FF3 → **FF3-1** (tweak 64→56
  bits).
- **Amon, Dunkelman, Keller, Ronen, Shamir (EUROCRYPT 2021)** — improved attacks
  on **FF3/FF3-1** (not FF1), incl. a related-domain class.
- Net: **Durak–Vaudenay broke FF3, prompting FF3-1; FF1 was never practically
  broken** — but both share a generic small-domain fragility, which is why NIST
  now mandates a domain size ≥1,000,000 for either. The 2025 SP 800-38G Rev. 1
  draft proposes dropping FF3 entirely.

There is no real paper named "Amon-Bellare-Hoang"; that was a conflation of two
distinct works, cited correctly above.

### B.3 — Deterministic keyed HMAC (ruled out)

`surrogate = HMAC(key, value)` gives consistency without a lookup table, but:

1. **Reversibility on key leak** — deterministic and keyed, so a compromised key
   makes every surrogate in every past log reversible in bulk.
2. **Dictionary / guesswork attacks** — an attacker with a small set of plausible
   plaintexts (a phone number, a known hostname) can precompute and match to
   *confirm* a guess, with no cryptanalytic break. The UK ICO / ENISA
   pseudonymisation guidance names three classes: brute-force, **dictionary
   search**, and **guesswork** (exploiting real-world frequency skew). *(This is
   what the rest of this brief informally calls the "confirmation oracle"; the
   phrase is not a term of art — it maps onto ICO/ENISA's dictionary/guesswork
   categories.)*

A properly *keyed* HMAC mitigates dictionary attacks — but a key baked into a
distributed offline binary is not genuinely secret, so HMAC reintroduces the very
key-custody problem scrubbr rejects. **Ruled out.** This is also the direct reason
`Kind.SECRET_VALUE` must stay a *random* (not deterministic) replacement: a
deterministic surrogate for a real secret is precisely a guessing oracle.

### B.4 — Typed surrogates without a key (the chosen direction)

Two key-free patterns preserve correlation (same input → same output):

- **Counter-indexed typed labels** (`PERSON_1`, `HOST_2`, `name-a`) — a bijective
  map from each unique value to a label drawn from a type-scoped namespace.
  **Collision-free by construction**, self-evidently synthetic, and carrying zero
  recoverable bits of the original. This is what Presidio (custom
  `InstanceCounterAnonymizer`) and scrubadub (`Lookup`) do, and what scrubbr's
  `AliasBook` already does for `host-a`/`user-a`.
- **Seeded-random realistic look-alikes** (Faker-style) — realistic fakes,
  consistent via a persisted map or per-value seeded RNG.

**The trade-off is decisive for scrubbr:** a realistic look-alike is, by design,
indistinguishable from real data — so a reviewer cannot tell whether
`192.168.4.201` in the output is a synthetic stand-in or a *leak that slipped
through*. Typed counter labels can never collide with, or be mistaken for, a real
value. For a tool whose safety rests on a human review gate, self-evidently
synthetic labels win.

### B.5 — Pitfalls of consistent replacement

- **Surrogate collisions** — Faker-style generators draw from the real value
  space and can map two distinct inputs to one output unless tracked; a bijective
  counter map eliminates this.
- **Fake mistaken for real** — the whole liability of realistic surrogates under a
  review gate (B.4).
- **Length/structure leak** — format-preserving schemes intentionally leak the
  value's shape (a redacted 16-digit number is still 16 digits), narrowing an
  attacker's guess space. scrubbr's shape-preserving kinds already accept this
  trade deliberately.
- **Reversibility on seed/mapping leak** — any keyed or seed-derived scheme is
  only as strong as its secret; ICO flags mapping/key compromise as the
  highest-impact failure.
- **Order-of-appearance counter labels are not reproducible from a seed alone** —
  a first-seen counter is a function of *processing order and prior state*, not of
  the value's content. Two runs over the same data in different order will not
  reliably assign the same label to the same value. Only **content-derived**
  indices or a **persisted map** give cross-run reproducibility. *(This confirms
  the red-team's correction to scrubbr's docs: a shared seed reproduces the
  RNG-driven shape kinds, but not the readable counter labels.)*

### B.6 — Recommendation for scrubbr

Typed, namespace-scoped **counter labels** backed by the existing per-run
`AliasBook` map — **not** FPE (key custody + domain-size fragility), **not** raw
HMAC (keyed reversibility / dictionary attack), **not** Faker look-alikes (defeat
the review gate). If cross-*run* reproducibility is ever wanted, derive the index
deterministically from the value's content under a fixed non-secret seed (or
persist the map) rather than relying on encounter order — the label still carries
no recoverable information, so there is nothing to confirm against even if the
seed is known.

**Appendix B sources:** GDPR Art. 4(5) & Recital 26 (`gdpr-info.eu`); ISO/IEC
20889:2018 §3.6–3.7; ISO 25237:2017; NISTIR 8053; NIST SP 800-122 / 800-188; NIST
SP 800-38G & Rev. 1 draft (`csrc.nist.gov`); NIST "Recent Cryptanalysis of FF3"
(2017); Durak & Vaudenay, ePrint 2017/521; Bellare-Hoang-Tessaro, ePrint 2016/794;
Amon et al., ePrint 2021/335; ICO Pseudonymisation guidance & ENISA "Pseudonymisation
techniques and best practices" (2019); Microsoft Presidio anonymizer docs;
SurrogateShield, arXiv:2606.29567.

---

## Sources

- gitleaks default config: `raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml`; composite rules `github.com/gitleaks/gitleaks/releases/tag/v8.28.0`
- detect-secrets: `github.com/Yelp/detect-secrets` — `plugins/keyword.py`, `plugins/high_entropy_strings.py`, `plugins/jwt.py`, `filters/heuristic.py`, `docs/design.md`
- Nosey Parker RULES.md: `github.com/praetorian-inc/noseyparker/blob/main/docs/RULES.md`
- TruffleHog: `github.com/trufflesecurity/trufflehog`; `trufflesecurity.com/blog/how-trufflehog-verifies-secrets`
- Semgrep Secrets: `semgrep.dev/docs/semgrep-secrets/conceptual-overview`, `.../generic-secrets`
- GitGuardian: `docs.gitguardian.com/secrets-detection/secrets-detection-engine/machine_learning`; `github.com/GitGuardian/ggshield`
- git-secrets: `github.com/awslabs/git-secrets/blob/master/README.rst`
- GitHub token formats (CRC32/base62): `github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/`
- AWS access-key format: `awsteele.com/blog/2020/09/26/aws-access-key-format.html`; `docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html`
- Basak et al., "A Comparative Study of Software Secrets Reporting by Secret Detection Tools" (818 repos, 9 tools): `arxiv.org/abs/2307.00714`
- Betterleaks / Token Efficiency: `bleepingcomputer.com/news/security/…`; `aikido.dev/blog/token-efficiency-secrets-scan`, `aikido.dev/blog/betterleaks-gitleaks-successor`
- Presidio: `microsoft.github.io/presidio/samples/python/pseudonymization/`; anonymizer operators `presidio.dataprivacystack.org/anonymizer/`; supported entities `microsoft.github.io/presidio/supported_entities/`
- scrubadub: `raw.githubusercontent.com/LeapBeyond/scrubadub/master/scrubadub/utils.py`; `scrubadub.readthedocs.io/.../post_processors/filth_replacer.html`
- Google Cloud DLP transforms: `docs.cloud.google.com/sensitive-data-protection/docs/transformations-reference`, `.../pseudonymization`
- AWS Comprehend / Nightfall: `help.nightfall.ai/developer-api/key-concepts/scanning_features/redaction`
- NIST SP 800-38G FF3 cryptanalysis: `csrc.nist.gov/News/2017/Recent-Cryptanalysis-of-FF3`; `eprint.iacr.org/2017/521`
- SurrogateShield: `arxiv.org/abs/2606.29567` (single-author preprint — cite directionally)
- protectai/llm-guard (archived 2026-07-09): `github.com/protectai/llm-guard`
- Linux diagnostics: `freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html`, `.../machine-id.html`; `docs.kernel.org/admin-guide/nfs/nfsroot.html`; `docs.cloud-init.io/.../kernel-command-line.html`; `man.openbsd.org/ssh-keygen.1`
- scrubbr source (verified this session): `scrubbr/shapes.py`, `scrubbr/residual.py`, `scrubbr/alias.py`, `scrubbr/detect.py`, `scrubbr/scrub.py`
