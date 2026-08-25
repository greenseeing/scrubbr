import time

import pytest
from secret_fixtures import GENERIC_HIGH_ENTROPY

from scrubbr import Kind, scrub
from scrubbr.kinds import Disposition

SECRET = "SuperSecretValue123abc"  # non-empty, no quotes/space/comma/semicolon


class TestCasingAndSeparatorVariants:
    # One stem must catch snake_case, kebab-case, camelCase and SCREAMING spellings.
    @pytest.mark.parametrize(
        "keyword",
        ["api_key", "apikey", "API_KEY", "apiKey", "api-key", "access-token", "refreshToken"],
    )
    def test_a_secret_behind_any_spelling_of_a_stem_is_scrubbed(self, keyword: str) -> None:
        result = scrub(f"{keyword}={SECRET}")
        assert SECRET not in result.text, f"{keyword} did not fire"
        assert any(f.text == SECRET and f.disposition is Disposition.SCRUB for f in result.findings)


class TestWidenedStems:
    @pytest.mark.parametrize(
        "keyword",
        ["bearer", "authorization", "credential", "credentials", "oauth",
         "connection_string", "DATABASE_URL", "connection-string"],
    )
    def test_a_widened_strong_stem_fires(self, keyword: str) -> None:
        assert SECRET not in scrub(f"{keyword}={SECRET}").text, f"{keyword} did not fire"

    @pytest.mark.parametrize("keyword", ["key", "token", "session", "cert", "connection", "dsn"])
    def test_a_widened_generic_stem_fires_on_a_high_entropy_value(self, keyword: str) -> None:
        assert GENERIC_HIGH_ENTROPY not in scrub(f"{keyword}={GENERIC_HIGH_ENTROPY}").text


class TestStemBoundaryRejectsSuffixCollisions:
    # A stem must begin at a segment boundary: an ordinary word that merely ENDS in a stem
    # (monkey -> key, concert -> cert) must never fire. This pins the fixed-width lookbehind
    # against a regression back to a variable-width \w* affix, which matched these.
    @pytest.mark.parametrize(
        "text",
        [
            f"monkey={GENERIC_HIGH_ENTROPY}",
            f"hockey={GENERIC_HIGH_ENTROPY}",
            f"concert={GENERIC_HIGH_ENTROPY}",
            f"possession={GENERIC_HIGH_ENTROPY}",
            f"disconnection={GENERIC_HIGH_ENTROPY}",
        ],
    )
    def test_a_word_that_merely_ends_in_a_stem_is_not_scrubbed(self, text: str) -> None:
        assert scrub(text).text == text


class TestGatedValueWithAScrubbableShapeStillScrubs:
    # A low-entropy value behind a generic stem is normally left alone -- but if it has a
    # scrubbable shape (hex/uuid/email) it must still be scrubbed by that shape, or the
    # keyword rule would swallow the span and preempt the HEX/UUID/EMAIL rule.
    def test_a_low_entropy_hex_value_behind_key_is_still_scrubbed(self) -> None:
        value = "deadbeef" * 4  # 32 hex, entropy well under the 3.5 gate
        assert value not in scrub(f"key={value}").text

    def test_a_uuid_value_behind_session_is_still_scrubbed(self) -> None:
        value = "550e8400-e29b-41d4-a716-446655440000"
        result = scrub(f"session={value}")
        assert value not in result.text
        assert Kind.UUID in {f.kind for f in result.findings}

    def test_an_email_value_behind_a_generic_stem_uses_the_email_pool(self) -> None:
        out = scrub("connection=bob@example.com and later bob@example.com").text
        assert "bob@example.com" not in out
        assert out.count("person-a@example.invalid") == 2


class TestGenericStemGate:
    @pytest.mark.parametrize("text", ["token=0", "token=next", "session=idle", "key=off"])
    def test_a_bare_generic_stem_with_a_short_or_low_value_is_left_alone(self, text: str) -> None:
        result = scrub(text)
        assert result.text == text, "a low-value generic stem must not be rewritten"
        assert result.findings == []

    def test_a_bare_generic_stem_with_a_long_low_entropy_value_is_left_alone(self) -> None:
        # Clears the length gate (>=10) but not the entropy gate: still left alone.
        text = "token=aaaaaaaaaaaa"
        assert scrub(text).text == text

    def test_a_bare_generic_stem_with_a_long_high_entropy_value_is_scrubbed(self) -> None:
        result = scrub(f"token={GENERIC_HIGH_ENTROPY}")
        assert GENERIC_HIGH_ENTROPY not in result.text
        assert any(f.text == GENERIC_HIGH_ENTROPY for f in result.findings)


class TestStrongStemHasNoGate:
    def test_a_strong_stem_scrubs_even_a_short_low_entropy_value(self) -> None:
        # `password=1234` is a real leak even though the value is short and low-entropy;
        # the length/entropy gate applies only to the ambiguous bare generic stems.
        result = scrub("password=hunter2")
        assert "hunter2" not in result.text
        assert result.findings


class TestSeparatorPrefixedKeys:
    # A stem sitting after a separator (the common env-var / config shape) is still caught,
    # because '_' and '-' are not [A-Za-z0-9] and so satisfy the stem boundary.
    @pytest.mark.parametrize(
        "keyword",
        ["DB_PASSWORD", "MYAPP_API_KEY", "AWS_SECRET_ACCESS_KEY", "app-client-secret"],
    )
    def test_a_separator_prefixed_key_is_caught(self, keyword: str) -> None:
        assert SECRET not in scrub(f"{keyword}={SECRET}").text, f"{keyword} did not fire"


class TestTwoPassPromotion:
    def test_a_value_found_behind_a_keyword_is_scrubbed_where_it_reappears_bare(self) -> None:
        out = scrub("apiKey=hunter2fortressXY\nlogin failed for hunter2fortressXY\n").text
        assert "hunter2fortressXY" not in out, "the bare second occurrence leaked"


class TestKeywordCaptureDoesNotBacktrack:
    def test_a_long_unconsumed_word_run_completes_quickly(self) -> None:
        # The worst case: a long letter/hex run that no larger rule swallows (here the
        # leading 'z' blocks the HEX rule's non-alnum lookbehind), so the scanner walks
        # every position. The stem boundary is a fixed-width lookbehind -- O(1) per
        # position -- so this stays linear rather than O(n * stems * affix).
        adversarial = "z" + "b" * 500_000 + " key=" + GENERIC_HIGH_ENTROPY
        start = time.monotonic()
        scrub(adversarial)
        assert time.monotonic() - start < 5.0


class TestExistingKeywordBehaviourIsPreserved:
    def test_psk_is_still_captured(self) -> None:
        value = "9f" * 32
        assert value not in scrub(f"psk = {value}").text

    def test_a_labelled_secret_that_is_an_email_shares_the_email_pool(self) -> None:
        out = scrub("password=alice@example.com\ncontact alice@example.com\n").text
        assert "alice@example.com" not in out
        assert out.count("person-a@example.invalid") == 2

    def test_a_kind_secret_value_finding_is_produced(self) -> None:
        result = scrub(f"client_secret={SECRET}")
        assert any(f.kind is Kind.SECRET_VALUE for f in result.findings)
