from secret_fixtures import (
    GITHUB_PAT,
    GITHUB_PAT_BADSUM,
    JWT_MALFORMED,
    JWT_VALID,
)

from scrubbr import scrub
from scrubbr.kinds import Disposition
from scrubbr.validate import github_checksum, valid_github_token, valid_jwt


class TestGithubChecksumDowngrade:
    def test_a_valid_checksum_token_stays_scrub(self) -> None:
        result = scrub(f"token {GITHUB_PAT} used")
        assert GITHUB_PAT not in result.text
        assert any(f.text == GITHUB_PAT and f.disposition is Disposition.SCRUB for f in result.findings)

    def test_a_failing_checksum_token_is_downgraded_to_warn_not_dropped(self) -> None:
        result = scrub(f"token {GITHUB_PAT_BADSUM} used")
        # WARN: left in place (not rewritten) but surfaced as a residual, never suppressed.
        assert GITHUB_PAT_BADSUM in result.text, "a failing token must not be silently dropped"
        assert not any(f.text == GITHUB_PAT_BADSUM for f in result.findings)
        assert any(r.text == GITHUB_PAT_BADSUM for r in result.residuals)


class TestKeywordContextOutranksTheChecksum:
    def test_a_failing_token_behind_a_keyword_is_scrubbed_not_downgraded(self) -> None:
        # A keyword/header context is a STRONGER signal than the checksum: a bad-checksum
        # token behind GITHUB_TOKEN= / Bearer is confidently a secret, so it is scrubbed
        # outright (the safe direction). The WARN downgrade is for the bare, less-certain form.
        for text in (
            f"GITHUB_TOKEN={GITHUB_PAT_BADSUM}",
            f"Authorization: Bearer {GITHUB_PAT_BADSUM}",
        ):
            assert GITHUB_PAT_BADSUM not in scrub(text).text, text


class TestJwtStructuralDowngrade:
    def test_a_valid_jwt_stays_scrub(self) -> None:
        result = scrub(f"auth {JWT_VALID}")
        assert JWT_VALID not in result.text
        assert any(f.disposition is Disposition.SCRUB for f in result.findings)

    def test_a_malformed_jwt_is_downgraded_to_warn_not_dropped(self) -> None:
        result = scrub(f"auth {JWT_MALFORMED}")
        assert JWT_MALFORMED in result.text, "a malformed jwt must be surfaced, not silently passed"
        assert not any(f.text == JWT_MALFORMED for f in result.findings)
        assert any(r.text == JWT_MALFORMED for r in result.residuals)


class TestValidationNeverSuppresses:
    def test_every_failing_match_still_appears_as_a_residual(self) -> None:
        result = scrub(f"a {GITHUB_PAT_BADSUM} b {JWT_MALFORMED} c")
        residual_text = " ".join(r.text for r in result.residuals)
        assert GITHUB_PAT_BADSUM in residual_text
        assert JWT_MALFORMED in residual_text


class TestValidators:
    def test_github_checksum_round_trips(self) -> None:
        body = "abc123DEF456ghi789JKL012mno345"  # 30 base62
        token = "ghp_" + body + github_checksum(body)
        assert valid_github_token(token)
        corrupted = token[:-1] + ("Z" if token[-1] != "Z" else "Y")
        assert not valid_github_token(corrupted)

    def test_a_variable_length_token_with_no_fixed_checksum_stays_valid(self) -> None:
        # A ghs_ token can be longer than 36 chars; with no fixed checksum to verify it is
        # left SCRUB rather than downgraded.
        assert valid_github_token("ghs_" + "a" * 200)

    def test_valid_jwt_accepts_a_real_shape_and_rejects_garbage(self) -> None:
        assert valid_jwt(JWT_VALID)
        assert not valid_jwt(JWT_MALFORMED)
        assert not valid_jwt("eyJ.only.twoparts.extra")
        assert not valid_jwt("notajwt")
