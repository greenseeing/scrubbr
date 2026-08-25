import time

import pytest
from secret_fixtures import (  # _body: exact-length non-hex body builder
    ANTHROPIC,
    AWS_AIDA_IDENTITY,
    AWS_AKIA,
    AZURE_ACCOUNT_KEY,
    AZURE_ACCOUNT_KEY_SECRET,
    DISCORD_WEBHOOK,
    DISCORD_WEBHOOK_SECRET,
    GITHUB_PAT_FINE,
    GITLAB_PAT,
    GOOGLE_API_KEY,
    NPM,
    OPENAI,
    PYPI,
    SENDGRID,
    SLACK_BOT,
    SLACK_USER,
    SLACK_WEBHOOK,
    SLACK_WEBHOOK_SECRET,
    STRIPE_PK,
    STRIPE_RESTRICTED,
    STRIPE_SECRET,
    _body,
)

from scrubbr import Kind, scrub
from scrubbr.kinds import Disposition

# (label, text-embedding the fixture, the secret substring that must not survive).
# For whole-token rules the secret is the token; for the label/URL rules only the
# credential portion is scrubbed while the readable prefix is kept.
SCRUB_CASES = [
    ("github_pat_fine", f"tok {GITHUB_PAT_FINE} end", GITHUB_PAT_FINE),
    ("gitlab_pat", f"tok {GITLAB_PAT} end", GITLAB_PAT),
    ("aws_akia", f"key {AWS_AKIA} end", AWS_AKIA),
    ("slack_bot", f"tok {SLACK_BOT} end", SLACK_BOT),
    ("slack_user", f"tok {SLACK_USER} end", SLACK_USER),
    ("stripe_secret", f"tok {STRIPE_SECRET} end", STRIPE_SECRET),
    ("stripe_restricted", f"tok {STRIPE_RESTRICTED} end", STRIPE_RESTRICTED),
    ("google_api_key", f"key {GOOGLE_API_KEY} end", GOOGLE_API_KEY),
    ("sendgrid", f"tok {SENDGRID} end", SENDGRID),
    ("openai", f"tok {OPENAI} end", OPENAI),
    ("anthropic", f"tok {ANTHROPIC} end", ANTHROPIC),
    ("npm", f"tok {NPM} end", NPM),
    ("pypi", f"tok {PYPI} end", PYPI),
    ("azure_storage", f"conn {AZURE_ACCOUNT_KEY} end", AZURE_ACCOUNT_KEY_SECRET),
    ("slack_webhook", f"post {SLACK_WEBHOOK} end", SLACK_WEBHOOK_SECRET),
    ("discord_webhook", f"post {DISCORD_WEBHOOK} end", DISCORD_WEBHOOK_SECRET),
]


class TestProviderTokensDoNotSurvive:
    @pytest.mark.parametrize("label,text,secret", SCRUB_CASES, ids=[c[0] for c in SCRUB_CASES])
    def test_the_secret_portion_is_removed_from_the_output(
        self, label: str, text: str, secret: str
    ) -> None:
        assert secret not in scrub(text).text, f"{label} leaked its secret"


class TestProviderReplacementsAreRandomLookAlikes:
    @pytest.mark.parametrize("label,text,secret", SCRUB_CASES, ids=[c[0] for c in SCRUB_CASES])
    def test_a_scrubbed_token_becomes_a_same_length_random_string(
        self, label: str, text: str, secret: str
    ) -> None:
        result = scrub(text)
        finding = next(f for f in result.findings if f.text == secret)
        assert finding.disposition is Disposition.SCRUB
        assert finding.kind is Kind.SECRET_VALUE
        # A deterministic/readable alias of a real secret would be a confirmation oracle.
        assert len(finding.alias) == len(secret)
        assert not finding.alias.startswith(("redacted-", "host-", "person-", "project-"))
        assert finding.alias != secret


class TestReadableStructureIsKept:
    def test_the_azure_label_and_padding_survive(self) -> None:
        out = scrub(f"conn {AZURE_ACCOUNT_KEY} end").text
        assert "AccountKey=" in out
        assert out.rstrip().endswith("== end")
        assert AZURE_ACCOUNT_KEY_SECRET not in out

    def test_the_webhook_host_survives(self) -> None:
        out = scrub(f"post {SLACK_WEBHOOK} end").text
        assert "https://hooks.slack.com/services/" in out
        assert SLACK_WEBHOOK_SECRET not in out


class TestPublicLookAlikesAreLeftAlone:
    # Stripe pk_ and the AWS AGPA/AIDA/AROA/AIPA identity ids merely SHARE a prefix-shape
    # with a secret; the catalog gives them no rule, so honest logs stay honest. (Twilio's
    # AC Account SID is 34 contiguous hex and is handled by the generic HEX rule, not by
    # the provider catalog, so it is not asserted here.)
    def test_a_stripe_publishable_key_and_an_aws_identity_id_survive(self) -> None:
        for public in (STRIPE_PK, AWS_AIDA_IDENTITY):
            out = scrub(f"id {public} end").text
            assert public in out, f"{public} is a public identifier and must survive"

    def test_no_finding_is_raised_for_a_public_identifier(self) -> None:
        result = scrub(f"id {STRIPE_PK} and {AWS_AIDA_IDENTITY}")
        leaked = [f for f in result.findings if f.text in (STRIPE_PK, AWS_AIDA_IDENTITY)]
        assert not leaked


class TestTokensEndingInAHyphenStillScrub:
    # A trailing \b after a charset that contains '-' fails at a '-', which used to leak the
    # whole token. These tokens end in '-' and must still be removed.
    @pytest.mark.parametrize(
        "token",
        [
            "glpat-" + _body(19) + "-",  # 20-char body ending in '-'
            "AIza" + _body(34) + "-",  # 35-char body ending in '-'
            "SG." + _body(22) + "." + _body(42) + "-",  # last segment 43, ending in '-'
        ],
        ids=["gitlab", "google", "sendgrid"],
    )
    def test_a_token_ending_in_a_hyphen_does_not_survive(self, token: str) -> None:
        assert token not in scrub(f"key {token} rest").text


class TestReScrubIsAFixedPoint:
    @pytest.mark.parametrize("label,text,secret", SCRUB_CASES, ids=[c[0] for c in SCRUB_CASES])
    def test_scrubbing_the_output_again_changes_nothing(
        self, label: str, text: str, secret: str
    ) -> None:
        once = scrub(text).text
        twice = scrub(once).text
        assert twice == once, f"{label} was not idempotent"


class TestProviderRulesDoNotBacktrack:
    def test_a_pathological_input_of_the_new_prefixes_completes_quickly(self) -> None:
        adversarial = (
            "sk-proj-" + "a" * 100_000
            + "AIza" + "b" * 100_000
            + "glpat-" + "c" * 100_000
            + "AccountKey=" + "d" * 100_000
            + "pypi-AgEIcHlwaS5vcmc" + "e" * 100_000
        )
        start = time.monotonic()
        scrub(adversarial)
        assert time.monotonic() - start < 5.0
