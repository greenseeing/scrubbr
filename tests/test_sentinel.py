import ipaddress
import re

import pytest
from secret_fixtures import GITHUB_PAT

from scrubbr import AliasBook, Kind, LocalIdentity, scrub
from scrubbr.shapes import IPV4_POOL_SIZE, SENTINEL, is_synthetic

_COUNTER = re.compile(r"(?:redacted|host|user|network|disk|person|project)-[a-z]+")


def _public_ips(n: int) -> list[str]:
    out: list[str] = []
    b = c = 0
    d = 1
    while len(out) < n:
        ip = f"11.{b}.{c}.{d}"
        if ipaddress.IPv4Address(ip).is_global:
            out.append(ip)
        d += 1
        if d > 254:
            d, c = 1, c + 1
        if c > 254:
            c, b = 0, b + 1
    return out


class TestSentinelIsSynthetic:
    def test_a_scrubbed_secret_surrogate_carries_the_sentinel(self) -> None:
        result = scrub(f"token {GITHUB_PAT}")
        alias = next(f.alias for f in result.findings if f.text == GITHUB_PAT)
        assert SENTINEL in alias
        assert is_synthetic(alias)

    def test_readable_counter_surrogates_are_recognisably_synthetic(self) -> None:
        result = scrub(
            "host prod-db-07 person alice project atlas name svc-01",
            LocalIdentity(
                roles=(
                    ("prod-db-07", Kind.HOSTNAME),
                    ("alice", Kind.PERSON),
                    ("atlas", Kind.PROJECT),
                ),
                extra=("svc-01",),
            ),
        )
        assert result.findings
        for finding in result.findings:
            assert _COUNTER.fullmatch(finding.alias), finding.alias

    def test_is_synthetic_never_masks_a_declared_value(self) -> None:
        # is_synthetic must not keep a value the caller explicitly asked to scrub, even one
        # shaped exactly like a surrogate label -- an intentional --also always wins.
        result = scrub("connect host-abc now", LocalIdentity(extra=("host-abc",)))
        assert "host-abc" not in result.text

    def test_a_real_hostname_shaped_like_a_counter_is_still_scrubbed(self) -> None:
        # A machine legitimately named user-a must not survive because it looks minted.
        result = scrub("login on user-a", LocalIdentity(hostname="user-a"))
        assert "user-a" not in result.text

    @pytest.mark.parametrize(
        "text,identity",
        [
            ("assigned to user-alice today", LocalIdentity(roles=(("alice", Kind.PERSON),))),
            ("deploying megaproject-atlas", LocalIdentity(roles=(("atlas", Kind.PROJECT),))),
            ("login by poweruser-dave", LocalIdentity(username="dave")),
        ],
    )
    def test_a_declared_value_inside_a_surrogate_shaped_compound_is_scrubbed(
        self, text: str, identity: LocalIdentity
    ) -> None:
        # The fixed-point skip is bound to the actual minted alias, so an ordinary compound
        # that merely looks like a surrogate label (user-alice, megaproject-atlas) can never
        # swallow the declared value hiding inside it.
        declared = next(iter(identity.roles), (identity.username,))[0]
        assert declared is not None
        assert declared not in scrub(text, identity).text


class TestFixedPoint:
    @pytest.mark.parametrize(
        "text,identity",
        [
            ("connecting to prod-db-07", LocalIdentity(extra=("prod-db-07",))),
            ("host prod-db-07", LocalIdentity(roles=(("prod-db-07", Kind.HOSTNAME),))),
            ("alice paged bob", LocalIdentity(roles=(("alice", Kind.PERSON), ("bob", Kind.PERSON)))),
            ("mail alice@example.com and bob@example.org", LocalIdentity()),
            ("peer 81.2.69.142", LocalIdentity()),
            ("addr 2a00:1450:4009:80f::200e", LocalIdentity()),
            (f"token {GITHUB_PAT}", LocalIdentity()),
        ],
    )
    def test_a_second_scrub_pass_changes_nothing_and_warns_nothing(
        self, text: str, identity: LocalIdentity
    ) -> None:
        first = scrub(text, identity)
        second = scrub(first.text, identity)
        assert second.text == first.text, "a minted surrogate must not be re-scrubbed"
        assert second.residuals == [], "a minted surrogate must not be re-warned"

    def test_a_secret_surrogate_never_trips_the_residual_scanner(self) -> None:
        first = scrub(f"token {GITHUB_PAT}")
        assert all(GITHUB_PAT not in r.text for r in first.residuals)
        second = scrub(first.text)
        assert not [r for r in second.residuals if r.reason == "high entropy"]


class TestCollisionFreedom:
    def test_many_distinct_names_get_distinct_surrogates(self) -> None:
        names = tuple(f"svc{i:03d}zzz" for i in range(300))
        result = scrub(" ".join(names), LocalIdentity(extra=names))
        aliases = {f.alias for f in result.findings if f.kind is Kind.REDACTED}
        assert len(aliases) == 300, "each distinct name must take its own counter"


class TestIpv4PoolBound:
    def test_the_pool_is_collision_free_up_to_its_bound(self) -> None:
        ips = _public_ips(IPV4_POOL_SIZE)
        result = scrub(" ".join(ips))
        aliases = {f.alias for f in result.findings if f.kind is Kind.IPV4}
        assert len(aliases) == IPV4_POOL_SIZE
        assert not [r for r in result.residuals if "pool" in r.reason]

    def test_the_pool_warns_instead_of_silently_wrapping_on_overflow(self) -> None:
        ips = _public_ips(IPV4_POOL_SIZE + 5)
        result = scrub(" ".join(ips))
        assert [r for r in result.residuals if "pool" in r.reason], (
            "past 762 addresses the pool must warn, not silently reuse an alias"
        )

    def test_the_bound_matches_the_documentation_space(self) -> None:
        # Three RFC 5737 /24s, 254 usable hosts each.
        assert IPV4_POOL_SIZE == 3 * 254
        book = AliasBook()
        seen = {book.alias_for(Kind.IPV4, ip) for ip in _public_ips(IPV4_POOL_SIZE)}
        assert len(seen) == IPV4_POOL_SIZE
