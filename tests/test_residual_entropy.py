from secret_fixtures import GENERIC_HIGH_ENTROPY

from scrubbr import Kind, scrub
from scrubbr.residual import find_residuals

# Hex token, entropy 3.32: above the hex ~3.0 threshold but below the old single 3.5, so
# per-charset classification is what makes it a residual now.
HEX_BAND = "aabbccddeeff00112233"
# base64 token, entropy 3.72: below the base64 ~3.8 threshold, so it stays quiet where the
# old single 3.5 would have reported it as noise.
BASE64_BAND = "Ab1Ab2Cd3Cd4Ef5Ef6Gh"
# A realistic 24-char (18-byte) base64url secret -- must still be reported (4.5 would silence
# it, which is the failure mode per-charset thresholds must avoid).
BASE64_SECRET = "kJH8s2Vx9pQ7wLm3tR5uYq2Z"

UUID = "550e8400-e29b-41d4-a716-446655440000"
SEQUENTIAL = "0123456789abcdefghijklmnopqrstuv"  # 32 chars, a prefix of base36
KERNEL_BASE64 = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQ0567"  # entropy 4.63, > the base64 threshold


def _reasons(text: str) -> list[str]:
    return [r.reason for r in find_residuals(text)]


class TestPerCharsetThresholds:
    def test_a_hex_token_is_judged_against_the_lower_hex_threshold(self) -> None:
        # 3.32 clears the hex ~3.0 threshold, so it is surfaced.
        assert _reasons(f"key {HEX_BAND} end"), "a moderate-entropy hex token must be flagged"

    def test_a_base64_token_below_the_base64_threshold_is_not_reported(self) -> None:
        # 3.72 is below the base64 ~3.8 threshold, so it is not reported as noise.
        assert not _reasons(f"key {BASE64_BAND} end"), "a mid-entropy base64 token is not a secret"

    def test_a_short_random_base64_secret_is_still_reported(self) -> None:
        # The threshold must not be set so high (e.g. 4.5) that short real secrets go silent.
        assert _reasons(f"tok {BASE64_SECRET} end"), "a real 24-char base64 secret must be flagged"

    def test_a_high_entropy_base64_blob_is_still_reported(self) -> None:
        assert _reasons(f"blob {KERNEL_BASE64} end")


class TestStructuralPreExclusions:
    def test_a_sequential_string_is_excluded_before_entropy(self) -> None:
        # Sequential strings have maximal Shannon entropy but are obviously not secrets.
        assert not find_residuals(SEQUENTIAL)

    def test_an_id_like_token_is_excluded_before_entropy(self) -> None:
        assert not find_residuals("userid_" + GENERIC_HIGH_ENTROPY)
        assert not find_residuals("session_ids_" + GENERIC_HIGH_ENTROPY)
        # ... while the same high-entropy value without the id prefix is still reported.
        assert find_residuals(GENERIC_HIGH_ENTROPY)

    def test_id_like_does_not_over_exclude_ordinary_words(self) -> None:
        # A token that merely BEGINS with the letters "id" (identifier, idempotency) or that
        # contains "_id" only by coincidence must NOT be silenced.
        assert find_residuals("identifier" + GENERIC_HIGH_ENTROPY)
        assert find_residuals("idempotencyKey" + GENERIC_HIGH_ENTROPY)
        assert find_residuals(GENERIC_HIGH_ENTROPY + "_idX9qWmN")

    def test_a_uuid_stays_quiet_on_its_own_low_entropy(self) -> None:
        assert not _reasons(f"session {UUID} opened")


class TestKeptFixedLengthSecretsStillReappear:
    # A kept secret must reappear as a residual -- the safety net must not be defeated for
    # the MD5 (32-hex) / SHA-1 (40-hex) lengths, which are extremely common secret shapes.
    def test_a_kept_32_hex_secret_reappears_as_a_residual(self) -> None:
        value = "9f86d081884c7d659a2feaa0c55ad015"  # 32 lowercase hex
        result = scrub(f"psk = {value}\n", keep=frozenset({(Kind.HEX, value)}))
        assert result.text == f"psk = {value}\n"
        assert any(r.text == value for r in result.residuals)

    def test_a_kept_40_hex_secret_reappears_as_a_residual(self) -> None:
        value = "3b0c44298fc1c149afbf4c8996fb92427ae41e42"  # 40 lowercase hex
        result = scrub(f"psk = {value}\n", keep=frozenset({(Kind.HEX, value)}))
        assert any(r.text == value for r in result.residuals)


class TestDiagnosticsAreReportedNotRewritten:
    def test_a_kernel_blob_the_scrub_rules_miss_is_reported_not_rewritten(self) -> None:
        # The entropy tier is report-only: a high-entropy base64 blob that no SCRUB rule
        # catches appears as a residual, never as a finding.
        result = scrub(f"data {KERNEL_BASE64} tail")
        assert KERNEL_BASE64 in result.text, "the entropy net must never rewrite"
        assert not any(f.text == KERNEL_BASE64 for f in result.findings)
        assert any(r.text == KERNEL_BASE64 for r in result.residuals)

    def test_a_matched_but_uncertain_value_still_yields_a_residual(self) -> None:
        result = scrub(f"token {GENERIC_HIGH_ENTROPY}")
        assert GENERIC_HIGH_ENTROPY in result.text
        assert any(r.text == GENERIC_HIGH_ENTROPY for r in result.residuals)
