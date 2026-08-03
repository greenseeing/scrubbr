import random
import re

from scrubbr import AliasBook, Kind, LocalIdentity
from scrubbr.decisions import Decisions, apply_decisions
from scrubbr.scrub import NO_IDENTITY, decision_key, scrub


def apply(text: str, decisions: Decisions, identity: LocalIdentity = NO_IDENTITY) -> str:
    return apply_decisions(text, identity, decisions, AliasBook(random.Random(0))).text


class TestAdditions:
    def test_an_addition_is_scrubbed_at_every_occurrence(self) -> None:
        out = apply(
            "deploy to prod-db-07 done; prod-db-07 replied\n",
            Decisions(additions=("prod-db-07",)),
        )
        assert "prod-db-07" not in out
        assert out.count("[REDACTED]") == 2

    def test_an_addition_keeps_its_classified_shape(self) -> None:
        out = apply("peer 10.1.2.3 up\n", Decisions(additions=("10.1.2.3",)))
        assert "10.1.2.3" not in out
        assert re.search(r"(?:203\.0\.113|198\.51\.100|192\.0\.2)\.\d+", out)
        assert "[REDACTED]" not in out

    def test_promoting_a_residual_text_removes_it_from_output_and_residuals(self) -> None:
        token = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
        text = f"tok {token} issued\n"
        before = scrub(text)
        assert any(r.text == token for r in before.residuals)
        after = apply_decisions(
            text, LocalIdentity(), Decisions(additions=(token,)), AliasBook(random.Random(0))
        )
        assert token not in after.text
        assert not any(r.text == token for r in after.residuals)

    def test_an_addition_already_declared_via_also_is_not_doubled(self) -> None:
        identity = LocalIdentity(extra=("prod-db-07",))
        result = apply_decisions(
            "connecting to prod-db-07 now\n",
            identity,
            Decisions(additions=("prod-db-07",)),
            AliasBook(random.Random(0)),
        )
        assert result.counts[Kind.REDACTED] == 1
        assert result.text.count("[REDACTED]") == 1


class TestComposition:
    def test_keep_and_addition_compose(self) -> None:
        out = apply(
            "hw aa:bb:cc:dd:ee:ff on prod-db-07\n",
            Decisions(
                keep=frozenset({decision_key(Kind.MAC, "aa:bb:cc:dd:ee:ff")}),
                additions=("prod-db-07",),
            ),
        )
        assert "aa:bb:cc:dd:ee:ff" in out
        assert "prod-db-07" not in out

    def test_an_override_for_an_addition_replaces_with_the_chosen_text(self) -> None:
        out = apply(
            "connecting to prod-db-07 now\n",
            Decisions(
                additions=("prod-db-07",),
                overrides={decision_key(Kind.REDACTED, "prod-db-07"): "db-host"},
            ),
        )
        assert "prod-db-07" not in out
        assert "db-host" in out
        assert "[REDACTED]" not in out

    def test_empty_decisions_reproduce_the_plain_scrub(self) -> None:
        text = "hw aa:bb:cc:dd:ee:ff peer 81.2.69.142\n"
        identity = LocalIdentity(hostname="dev-thinkpad")
        plain = scrub(text, identity, AliasBook(random.Random(0)))
        decided = apply_decisions(text, identity, Decisions(), AliasBook(random.Random(0)))
        assert decided.text == plain.text


class TestAliasStability:
    def test_aliases_survive_a_recompute_with_new_decisions(self) -> None:
        text = "a aa:bb:cc:dd:ee:ff b 11:22:33:44:55:66\n"
        book = AliasBook(random.Random(0))
        first = apply_decisions(text, LocalIdentity(), Decisions(), book)
        alias = next(f.alias for f in first.findings if f.text == "aa:bb:cc:dd:ee:ff")
        second = apply_decisions(
            text,
            LocalIdentity(),
            Decisions(keep=frozenset({decision_key(Kind.MAC, "11:22:33:44:55:66")})),
            book,
        )
        assert alias in second.text, "a toggle elsewhere must not re-mint this alias"

    def test_toggling_off_and_back_on_restores_the_same_alias(self) -> None:
        text = "hw aa:bb:cc:dd:ee:ff up\n"
        book = AliasBook(random.Random(0))
        key = decision_key(Kind.MAC, "aa:bb:cc:dd:ee:ff")
        first = apply_decisions(text, LocalIdentity(), Decisions(), book)
        kept = apply_decisions(text, LocalIdentity(), Decisions(keep=frozenset({key})), book)
        assert "aa:bb:cc:dd:ee:ff" in kept.text
        restored = apply_decisions(text, LocalIdentity(), Decisions(), book)
        assert restored.text == first.text
