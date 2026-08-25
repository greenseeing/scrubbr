import time

from secret_fixtures import (
    GITHUB_OAUTH,
    GITHUB_PAT,
    STRIPE_PK,
    TWILIO_SK,
)

from scrubbr import Kind, LocalIdentity, scrub
from scrubbr.kinds import Disposition


class TestScrubTier:
    def test_a_github_pat_does_not_survive_in_the_output(self) -> None:
        result = scrub(f"token {GITHUB_PAT} used")
        assert GITHUB_PAT not in result.text

    def test_a_github_oauth_token_does_not_survive_either(self) -> None:
        assert GITHUB_OAUTH not in scrub(f"auth {GITHUB_OAUTH}").text

    def test_a_scrubbed_github_pat_is_a_scrub_disposition_finding(self) -> None:
        result = scrub(f"token {GITHUB_PAT}")
        pat = next(f for f in result.findings if f.text == GITHUB_PAT)
        assert pat.disposition is Disposition.SCRUB

    def test_the_github_pat_replacement_is_random_not_a_readable_counter(self) -> None:
        # A deterministic alias of a real secret is a confirmation oracle; the SCRUB
        # tier gives secret-bearing kinds a shape-preserving random string instead.
        result = scrub(f"token {GITHUB_PAT}")
        pat = next(f for f in result.findings if f.text == GITHUB_PAT)
        assert not pat.alias.startswith("redacted-")
        assert len(pat.alias) == len(GITHUB_PAT)


class TestWarnTier:
    def test_a_twilio_sk_key_is_not_rewritten(self) -> None:
        assert TWILIO_SK in scrub(f"key {TWILIO_SK} loaded").text

    def test_a_twilio_sk_key_is_reported_as_a_warn_row_with_a_line_number(self) -> None:
        result = scrub(f"line one\nkey {TWILIO_SK} here\n")
        warned = [r for r in result.residuals if TWILIO_SK in r.text]
        assert warned, "a WARN-tier match must surface as a residual row"
        assert warned[0].line == 2

    def test_a_twilio_sk_key_produces_no_scrub_finding(self) -> None:
        result = scrub(f"key {TWILIO_SK}")
        assert not [f for f in result.findings if TWILIO_SK in f.text]

    def test_strict_still_refuses_while_a_warn_tier_string_remains(self) -> None:
        result = scrub(f"key {TWILIO_SK}")
        # --strict gates on residuals; a WARN row lands there, so strict must see it.
        assert result.residuals


class TestExplicitScrubOverridesWarn:
    def test_a_promoted_secret_is_scrubbed_at_every_occurrence_not_left_warned(self) -> None:
        # The same value confirmed a secret behind a keyword must be scrubbed everywhere,
        # not scrubbed at the keyword and left verbatim where a WARN rule catches it bare.
        result = scrub(f"secret={TWILIO_SK} set\nlater the raw {TWILIO_SK} again\n")
        assert TWILIO_SK not in result.text

    def test_declaring_a_warn_value_forces_it_to_scrub(self) -> None:
        result = scrub(f"key {TWILIO_SK} loaded", LocalIdentity(extra=(TWILIO_SK,)))
        assert TWILIO_SK not in result.text

    def test_a_review_override_scrubs_a_warn_value(self) -> None:
        result = scrub(
            f"key {TWILIO_SK} loaded",
            overrides={(Kind.SECRET_VALUE, TWILIO_SK.lower()): "[SK]"},
        )
        assert TWILIO_SK not in result.text
        assert "[SK]" in result.text


class TestPublicIdentifierExcluded:
    def test_a_stripe_publishable_key_is_left_unchanged(self) -> None:
        assert STRIPE_PK in scrub(f"pub {STRIPE_PK}").text

    def test_a_stripe_publishable_key_is_never_a_scrub_finding(self) -> None:
        result = scrub(f"pub {STRIPE_PK}")
        assert not [f for f in result.findings if STRIPE_PK in f.text]


class TestDispositionModel:
    def test_every_finding_carries_a_disposition(self) -> None:
        result = scrub(
            f"hw aa:bb:cc:dd:ee:ff token {GITHUB_PAT}",
            identity=LocalIdentity(),
        )
        assert result.findings
        assert all(isinstance(f.disposition, Disposition) for f in result.findings)

    def test_ordinary_structural_matches_stay_scrub_tier(self) -> None:
        result = scrub("hw aa:bb:cc:dd:ee:ff")
        mac = next(f for f in result.findings if f.kind is Kind.MAC)
        assert mac.disposition is Disposition.SCRUB


class TestReDoS:
    def test_a_long_adversarial_input_completes_within_a_sane_time_bound(self) -> None:
        # Distinctive-prefix rules use bounded quantifiers; a pathological run must not
        # wedge the scanner in catastrophic backtracking.
        adversarial = (
            "ghp_" * 20_000
            + "SK" + "a" * 100_000
            + "-----BEGIN X-----\n" + "A" * 100_000
            + "\n" + "aa:" * 50_000
        )
        start = time.monotonic()
        scrub(adversarial)
        assert time.monotonic() - start < 5.0
