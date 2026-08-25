import time

import pytest

from scrubbr import scrub
from scrubbr.kinds import Disposition

BEARER = "eyJhbGc.iOiJIUzI1.NiIsInR5cCngg"  # JWT-ish bearer token
BASIC = "dXNlcm5hbWU6c3VwZXJzZWNyZXRwYXNzd29yZA=="  # base64 user:pass
PASSWORD = "s3cr3tPassw0rdXY"


class TestAuthorizationHeader:
    def test_a_bearer_token_is_scrubbed_and_the_header_stays_readable(self) -> None:
        out = scrub(f"GET / HTTP/1.1\nAuthorization: Bearer {BEARER}\n").text
        assert BEARER not in out, "the bearer token leaked"
        assert "Authorization: Bearer " in out, "the header label must stay readable"

    def test_a_basic_credential_is_scrubbed(self) -> None:
        out = scrub(f"Authorization: Basic {BASIC}\n").text
        assert BASIC not in out
        assert "Authorization: Basic " in out

    def test_the_bearer_token_is_a_scrub_finding(self) -> None:
        result = scrub(f"Authorization: Bearer {BEARER}")
        assert any(f.disposition is Disposition.SCRUB and BEARER in f.text for f in result.findings)

    def test_a_colon_bearing_value_is_scrubbed_whole_not_truncated(self) -> None:
        # An `id:secret`-shaped value must not be truncated at the ':' leaving the tail.
        token = "clientid123:secretpart456"
        out = scrub(f"Authorization: Bearer {token}").text
        assert "secretpart456" not in out, "the value was truncated at the colon"
        assert token not in out

    def test_a_json_quoted_authorization_header_is_scrubbed(self) -> None:
        # structlog / JSON logs quote both the key and the value -- the shape this tool's own
        # stack produces.
        token = "abc.def.ghi12345"
        out = scrub(f'"Authorization": "Bearer {token}"').text
        assert token not in out
        assert '"Authorization": "Bearer ' in out


class TestUrlUserinfo:
    def test_the_password_in_a_url_is_removed_and_the_host_stays(self) -> None:
        out = scrub(f"fetching https://appuser:{PASSWORD}@dashboard.example.com/status").text
        assert PASSWORD not in out, "the url password leaked"
        assert "https://" in out
        assert "@dashboard.example.com/status" in out, "host and path must stay readable"

    def test_a_password_only_userinfo_is_handled(self) -> None:
        # redis://:pass@host -- empty username, password after the colon.
        out = scrub(f"cache redis://:{PASSWORD}@cache01.example.com:6379").text
        assert PASSWORD not in out
        assert "redis://" in out
        assert "@cache01.example.com:6379" in out

    def test_a_base64_password_containing_a_slash_is_still_removed(self) -> None:
        # A base64 password contains '/'; excluding '/' from the password class used to make
        # the whole match fail and leak the password verbatim with no warning.
        pw = "AbCd/EfGh12//34ijKlmn=="
        out = scrub(f"conn postgres://u:{pw}@db.example.com/app").text
        assert pw not in out, "a base64 password with '/' leaked"
        assert "@db.example.com/app" in out

    def test_a_password_before_an_ipv6_host_is_removed(self) -> None:
        pw = "s3cr3tPassXY"
        out = scrub(f"db postgres://u:{pw}@[2001:db8::1]:5432/app").text
        assert pw not in out
        assert "[2001:db8::1]:5432/app" in out

    def test_an_ordinary_url_with_no_credentials_is_untouched(self) -> None:
        text = "see https://docs.example.com:8080/guide for details"
        assert scrub(text).text == text


class TestDsnConnectionString:
    @pytest.mark.parametrize(
        "dsn,keep",
        [
            ("postgres://dbadmin:{p}@db.example.com:5432/orders", "db.example.com:5432/orders"),
            ("mysql://root:{p}@10.10.10.10/shopdb", "/shopdb"),
            ("mongodb+srv://svc:{p}@cluster0.example.mongodb.net/app", "cluster0.example.mongodb.net/app"),
            ("amqp://guest:{p}@broker.example.com:5672/vhost", "broker.example.com:5672/vhost"),
        ],
    )
    def test_the_credential_is_removed_and_the_target_stays_readable(
        self, dsn: str, keep: str
    ) -> None:
        out = scrub("DSN " + dsn.format(p=PASSWORD)).text
        assert PASSWORD not in out, f"{dsn} leaked its password"
        assert keep in out, "scheme/host/db name must stay readable"


class TestStructuredContextIsIdempotent:
    def test_re_scrubbing_is_a_fixed_point(self) -> None:
        text = (
            f"Authorization: Bearer {BEARER}\n"
            f"conn postgres://u:{PASSWORD}@db.example.com/app\n"
        )
        once = scrub(text).text
        assert scrub(once).text == once


class TestStructuredContextDoesNotBacktrack:
    def test_a_long_scheme_like_run_completes_quickly(self) -> None:
        adversarial = "a" * 500_000 + "://user:pass@host " + "b" * 500_000
        start = time.monotonic()
        scrub(adversarial)
        assert time.monotonic() - start < 5.0
