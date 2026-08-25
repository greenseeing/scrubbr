import json
from pathlib import Path

import pytest

from scrubbr import Kind, LocalIdentity, scrub
from scrubbr.cli import main


def _roles(*pairs: tuple[str, Kind]) -> LocalIdentity:
    return LocalIdentity(roles=pairs)


class TestRoleHintKinds:
    def test_a_host_hint_produces_a_host_surrogate(self) -> None:
        result = scrub("connecting to prod-db-07", _roles(("prod-db-07", Kind.HOSTNAME)))
        assert "prod-db-07" not in result.text
        assert "host-a" in result.text

    def test_a_person_hint_produces_a_person_surrogate(self) -> None:
        result = scrub("alice logged in", _roles(("alice", Kind.PERSON)))
        assert "alice" not in result.text
        assert "person-a" in result.text

    def test_a_project_hint_produces_a_project_surrogate(self) -> None:
        result = scrub("atlas shipped", _roles(("atlas", Kind.PROJECT)))
        assert "atlas" not in result.text
        assert "project-a" in result.text

    def test_a_bare_also_value_with_no_hint_stays_redacted(self) -> None:
        result = scrub("connecting to prod-db-07", LocalIdentity(extra=("prod-db-07",)))
        assert "redacted-a" in result.text
        assert "host-" not in result.text


class TestRoleCorrelation:
    def test_same_value_maps_to_one_surrogate_across_a_hinted_kind(self) -> None:
        result = scrub("atlas then atlas again", _roles(("atlas", Kind.PROJECT)))
        assert result.text.count("project-a") == 2

    def test_distinct_values_get_distinct_surrogates_within_a_kind(self) -> None:
        result = scrub(
            "alice paged bob",
            _roles(("alice", Kind.PERSON), ("bob", Kind.PERSON)),
        )
        aliases = {f.alias for f in result.findings if f.kind is Kind.PERSON}
        assert aliases == {"person-a", "person-b"}

    def test_casing_collapses_to_one_surrogate(self) -> None:
        result = scrub("Atlas and atlas and ATLAS", _roles(("Atlas", Kind.PROJECT)))
        assert "Atlas" not in result.text
        assert "atlas" not in result.text.lower().replace("project-a", "")
        assert result.text.count("project-a") == 3

    def test_each_hinted_kind_keeps_its_own_counter(self) -> None:
        result = scrub(
            "host prod-db-07 person alice project atlas",
            _roles(
                ("prod-db-07", Kind.HOSTNAME),
                ("alice", Kind.PERSON),
                ("atlas", Kind.PROJECT),
            ),
        )
        assert "host-a" in result.text
        assert "person-a" in result.text
        assert "project-a" in result.text


class TestRoleCliSeam:
    def test_also_host_flag_produces_a_host_surrogate(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "log.txt"
        path.write_text("connecting to prod-db-07 now\n", encoding="utf-8")
        assert main([str(path), "-y", "--no-identity", "--also-host", "prod-db-07"]) == 0
        out = capsys.readouterr().out
        assert "prod-db-07" not in out
        assert "host-a" in out

    def test_also_person_and_project_flags_type_their_surrogates(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "log.txt"
        path.write_text("alice on atlas\n", encoding="utf-8")
        code = main(
            [str(path), "-y", "--no-identity", "--also-person", "alice", "--also-project", "atlas"]
        )
        assert code == 0
        out = capsys.readouterr().out
        assert "person-a" in out
        assert "project-a" in out

    def test_verbose_reports_the_typed_kind_for_a_host_hint(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "log.txt"
        path.write_text("connecting to prod-db-07 now\n", encoding="utf-8")
        assert main([str(path), "-v", "-y", "--no-identity", "--also-host", "prod-db-07"]) == 0
        events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
        replaced = [e for e in events if e["event"] == "replaced"]
        assert replaced[0]["kind"] == "hostname"
        assert replaced[0]["alias"] == "host-a"
