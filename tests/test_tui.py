import random
from typing import Any

from textual.pilot import Pilot
from textual.widgets import DataTable, Input, OptionList

from scrubbr import AliasBook, Kind, LocalIdentity
from scrubbr.decisions import ReviewRequest
from scrubbr.scrub import decision_key, scrub
from scrubbr.tui.app import ReviewApp, finding_rows
from scrubbr.tui.screens import DiffScreen, FuzzyFindScreen, ReplacementScreen

SAMPLE = "host box hw aa:bb:cc:dd:ee:ff up\npeer aa:bb:cc:dd:ee:ff again\n"


def request_for(text: str, default_output: str | None = None) -> ReviewRequest:
    identity = LocalIdentity()
    book = AliasBook(random.Random(0))
    return ReviewRequest(
        text=text,
        result=scrub(text, identity, book),
        identity=identity,
        book=book,
        default_output=default_output,
    )


async def emit(pilot: Pilot[Any]) -> None:
    """Approve: y opens the diff screen, y again confirms."""
    await pilot.press("y")
    await pilot.pause()
    await pilot.press("y")


def test_finding_rows_group_occurrences_of_one_value() -> None:
    rows = finding_rows(request_for(SAMPLE).result.findings)
    assert len(rows) == 1
    assert rows[0].kind is Kind.MAC
    assert rows[0].count == 2
    assert rows[0].text == "aa:bb:cc:dd:ee:ff"


async def test_the_table_lists_each_distinct_finding() -> None:
    app = ReviewApp(request_for(SAMPLE))
    async with app.run_test():
        table = app.query_one(DataTable)
        assert table.row_count == 1
        status, kind, count, text, alias = table.get_row_at(0)
        assert (status, kind, count) == ("scrub", "mac", "2")
        assert text == "aa:bb:cc:dd:ee:ff"
        assert alias and alias != text


async def test_a_long_value_is_clipped_in_the_table() -> None:
    value = "9f" * 40
    app = ReviewApp(request_for(f"key={value}\n"))
    async with app.run_test():
        table = app.query_one(DataTable)
        assert value not in table.get_row_at(0)[3]
        assert len(table.get_row_at(0)[3]) <= 60


async def test_space_flips_the_status_cell() -> None:
    app = ReviewApp(request_for(SAMPLE))
    async with app.run_test() as pilot:
        table = app.query_one(DataTable)
        assert table.get_row_at(0)[0] == "scrub"
        await pilot.press("space")
        assert table.get_row_at(0)[0] == "keep"
        await pilot.press("space")
        assert table.get_row_at(0)[0] == "scrub"


async def test_keeping_then_accepting_emits_the_original_value() -> None:
    app = ReviewApp(request_for(SAMPLE))
    async with app.run_test() as pilot:
        await pilot.press("space")
        await emit(pilot)
    outcome = app.return_value
    assert outcome is not None
    assert outcome.confirmed is True
    assert "aa:bb:cc:dd:ee:ff" in outcome.result.text
    assert decision_key(Kind.MAC, "aa:bb:cc:dd:ee:ff") in outcome.decisions.keep


async def test_toggling_twice_restores_the_exact_scrubbed_text() -> None:
    request = request_for(SAMPLE)
    app = ReviewApp(request)
    async with app.run_test() as pilot:
        await pilot.press("space", "space")
        await emit(pilot)
    outcome = app.return_value
    assert outcome is not None
    assert outcome.result.text == request.result.text, "the shared book must reuse the alias"
    assert outcome.decisions.keep == frozenset()


async def test_accepting_without_changes_returns_the_unamended_result() -> None:
    request = request_for(SAMPLE)
    app = ReviewApp(request)
    async with app.run_test() as pilot:
        await emit(pilot)
    outcome = app.return_value
    assert outcome is not None
    assert outcome.confirmed is True
    assert outcome.result.text == request.result.text


async def test_y_shows_the_diff_before_emitting() -> None:
    app = ReviewApp(request_for(SAMPLE))
    async with app.run_test() as pilot:
        await pilot.press("y")
        await pilot.pause()
        assert isinstance(app.screen, DiffScreen)
        assert app.return_value is None, "nothing may be emitted before the diff is seen"
        await pilot.press("y")
    outcome = app.return_value
    assert outcome is not None
    assert outcome.confirmed is True


async def test_the_diff_shows_the_prefilled_destination() -> None:
    app = ReviewApp(request_for(SAMPLE, default_output="demo.scrubbed.txt"))
    async with app.run_test() as pilot:
        await pilot.press("y")
        await pilot.pause()
        assert app.screen.query_one("#destination", Input).value == "demo.scrubbed.txt"


async def test_the_diff_has_no_destination_field_without_a_default() -> None:
    app = ReviewApp(request_for(SAMPLE))
    async with app.run_test() as pilot:
        await pilot.press("y")
        await pilot.pause()
        assert not app.screen.query("#destination")


async def test_accepting_returns_the_default_destination() -> None:
    app = ReviewApp(request_for(SAMPLE, default_output="demo.scrubbed.txt"))
    async with app.run_test() as pilot:
        await emit(pilot)
    outcome = app.return_value
    assert outcome is not None
    assert outcome.confirmed is True
    assert outcome.destination == "demo.scrubbed.txt"


async def test_accepting_without_a_default_returns_no_destination() -> None:
    app = ReviewApp(request_for(SAMPLE))
    async with app.run_test() as pilot:
        await emit(pilot)
    outcome = app.return_value
    assert outcome is not None
    assert outcome.destination is None


async def test_editing_the_destination_changes_where_the_text_goes() -> None:
    app = ReviewApp(request_for(SAMPLE, default_output="demo.scrubbed.txt"))
    async with app.run_test() as pilot:
        await pilot.press("y")
        await pilot.pause()
        await pilot.press("e")
        await pilot.press("end", *".bak")
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("y")
    outcome = app.return_value
    assert outcome is not None
    assert outcome.destination == "demo.scrubbed.txt.bak"


async def test_y_types_into_the_destination_while_editing() -> None:
    app = ReviewApp(request_for(SAMPLE, default_output="demo.scrubbed.txt"))
    async with app.run_test() as pilot:
        await pilot.press("y")
        await pilot.pause()
        await pilot.press("e")
        await pilot.press("end", "y")
        await pilot.pause()
        assert app.return_value is None, "keys must edit the path, not confirm"
        assert app.screen.query_one("#destination", Input).value == "demo.scrubbed.txty"


async def test_escape_while_editing_leaves_the_field_not_the_diff() -> None:
    app = ReviewApp(request_for(SAMPLE, default_output="demo.scrubbed.txt"))
    async with app.run_test() as pilot:
        await pilot.press("y")
        await pilot.pause()
        await pilot.press("e")
        await pilot.press("end", *".bak")
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, DiffScreen), "escape must only blur the field"
        await pilot.press("y")
    outcome = app.return_value
    assert outcome is not None
    assert outcome.destination == "demo.scrubbed.txt.bak"


async def test_the_edit_path_key_is_not_offered_without_a_destination() -> None:
    app = ReviewApp(request_for(SAMPLE))
    async with app.run_test() as pilot:
        await pilot.press("y")
        await pilot.pause()
        assert app.screen.check_action("edit_path", ()) is False


async def test_an_emptied_destination_falls_back_to_the_default() -> None:
    app = ReviewApp(request_for(SAMPLE, default_output="demo.scrubbed.txt"))
    async with app.run_test() as pilot:
        await pilot.press("y")
        await pilot.pause()
        await pilot.press("e")
        await pilot.press("end", "ctrl+u")
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("y")
    outcome = app.return_value
    assert outcome is not None
    assert outcome.destination == "demo.scrubbed.txt"


async def test_escape_at_the_diff_returns_to_the_table() -> None:
    app = ReviewApp(request_for(SAMPLE))
    async with app.run_test() as pilot:
        await pilot.press("y")
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, DiffScreen)
        assert app.return_value is None
        await pilot.press("q")
    outcome = app.return_value
    assert outcome is not None
    assert outcome.confirmed is False


async def test_aborting_returns_unconfirmed() -> None:
    app = ReviewApp(request_for(SAMPLE))
    async with app.run_test() as pilot:
        await pilot.press("q")
    outcome = app.return_value
    assert outcome is not None
    assert outcome.confirmed is False


async def test_a_opens_the_finder_and_the_choice_is_scrubbed_everywhere() -> None:
    text = "connecting to proddb07 now; proddb07 replied\n"
    app = ReviewApp(request_for(text))
    async with app.run_test() as pilot:
        await pilot.press("a")
        await pilot.pause()
        assert isinstance(app.screen, FuzzyFindScreen)
        await pilot.press(*"proddb07")
        await pilot.press("enter")
        await pilot.pause()
        await emit(pilot)
    outcome = app.return_value
    assert outcome is not None
    assert outcome.decisions.additions == ("proddb07",)
    assert "proddb07" not in outcome.result.text
    assert outcome.result.text.count("[REDACTED]") == 2


async def test_escape_leaves_the_finder_without_adding() -> None:
    app = ReviewApp(request_for(SAMPLE))
    async with app.run_test() as pilot:
        await pilot.press("a")
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        await emit(pilot)
    outcome = app.return_value
    assert outcome is not None
    assert outcome.decisions.additions == ()


async def test_a_residual_is_listed_as_a_warn_row() -> None:
    token = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    app = ReviewApp(request_for(f"tok {token} issued\n"))
    async with app.run_test():
        table = app.query_one(DataTable)
        assert table.row_count == 1
        status, reason, _count, _text, alias = table.get_row_at(0)
        assert status == "warn"
        assert reason == "known credential prefix"
        assert alias == ""


async def test_r_offers_redacted_and_applies_it_everywhere() -> None:
    app = ReviewApp(request_for(SAMPLE))
    async with app.run_test() as pilot:
        await pilot.press("r")
        await pilot.pause()
        assert isinstance(app.screen, ReplacementScreen)
        await pilot.press("down", "enter")
        await pilot.pause()
        table = app.query_one(DataTable)
        assert table.get_row_at(0)[4] == "[REDACTED]"
        await emit(pilot)
    outcome = app.return_value
    assert outcome is not None
    assert outcome.result.text.count("[REDACTED]") == 2
    assert "aa:bb:cc:dd:ee:ff" not in outcome.result.text
    key = decision_key(Kind.MAC, "aa:bb:cc:dd:ee:ff")
    assert outcome.decisions.overrides == {key: "[REDACTED]"}


async def test_a_custom_replacement_is_typed_and_applied() -> None:
    app = ReviewApp(request_for(SAMPLE))
    async with app.run_test() as pilot:
        await pilot.press("r")
        await pilot.pause()
        await pilot.press("down", "down", "enter")
        await pilot.pause()
        await pilot.press(*"mylaptop")
        await pilot.press("enter")
        await pilot.pause()
        await emit(pilot)
    outcome = app.return_value
    assert outcome is not None
    assert outcome.result.text.count("mylaptop") == 2
    assert "aa:bb:cc:dd:ee:ff" not in outcome.result.text


async def test_choosing_the_minted_alias_back_removes_the_override() -> None:
    request = request_for(SAMPLE)
    app = ReviewApp(request)
    async with app.run_test() as pilot:
        await pilot.press("r")
        await pilot.pause()
        await pilot.press("down", "enter")
        await pilot.pause()
        await pilot.press("r")
        await pilot.pause()
        assert isinstance(app.screen, ReplacementScreen)
        assert app.screen.query_one(OptionList).highlighted == 1, "the active choice leads"
        await pilot.press("up", "enter")
        await pilot.pause()
        await emit(pilot)
    outcome = app.return_value
    assert outcome is not None
    assert outcome.decisions.overrides == {}
    assert outcome.result.text == request.result.text, "the book must restore the minted alias"


async def test_r_on_a_warn_row_does_nothing() -> None:
    token = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    app = ReviewApp(request_for(f"tok {token} issued\n"))
    async with app.run_test() as pilot:
        await pilot.press("r")
        await pilot.pause()
        assert not isinstance(app.screen, ReplacementScreen)


async def test_space_on_a_warn_row_promotes_the_residual() -> None:
    token = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    app = ReviewApp(request_for(f"tok {token} issued\n"))
    async with app.run_test() as pilot:
        await pilot.press("space")
        table = app.query_one(DataTable)
        assert table.get_row_at(0)[0] == "scrub"
        await emit(pilot)
    outcome = app.return_value
    assert outcome is not None
    assert token not in outcome.result.text
    assert outcome.decisions.additions == (token,)
    assert not outcome.result.residuals
