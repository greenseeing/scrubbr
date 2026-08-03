import random

from textual.widgets import DataTable

from scrubbr import AliasBook, Kind, LocalIdentity
from scrubbr.decisions import ReviewRequest
from scrubbr.scrub import decision_key, scrub
from scrubbr.tui.app import ReviewApp, finding_rows
from scrubbr.tui.screens import FuzzyFindScreen

SAMPLE = "host box hw aa:bb:cc:dd:ee:ff up\npeer aa:bb:cc:dd:ee:ff again\n"


def request_for(text: str) -> ReviewRequest:
    identity = LocalIdentity()
    book = AliasBook(random.Random(0))
    return ReviewRequest(
        text=text, result=scrub(text, identity, book), identity=identity, book=book
    )


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
        await pilot.press("space", "y")
    outcome = app.return_value
    assert outcome is not None
    assert outcome.confirmed is True
    assert "aa:bb:cc:dd:ee:ff" in outcome.result.text
    assert decision_key(Kind.MAC, "aa:bb:cc:dd:ee:ff") in outcome.decisions.keep


async def test_toggling_twice_restores_the_exact_scrubbed_text() -> None:
    request = request_for(SAMPLE)
    app = ReviewApp(request)
    async with app.run_test() as pilot:
        await pilot.press("space", "space", "y")
    outcome = app.return_value
    assert outcome is not None
    assert outcome.result.text == request.result.text, "the shared book must reuse the alias"
    assert outcome.decisions.keep == frozenset()


async def test_accepting_without_changes_returns_the_unamended_result() -> None:
    request = request_for(SAMPLE)
    app = ReviewApp(request)
    async with app.run_test() as pilot:
        await pilot.press("y")
    outcome = app.return_value
    assert outcome is not None
    assert outcome.confirmed is True
    assert outcome.result.text == request.result.text


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
        await pilot.press("y")
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
        await pilot.press("y")
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


async def test_space_on_a_warn_row_promotes_the_residual() -> None:
    token = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    app = ReviewApp(request_for(f"tok {token} issued\n"))
    async with app.run_test() as pilot:
        await pilot.press("space")
        table = app.query_one(DataTable)
        assert table.get_row_at(0)[0] == "scrub"
        await pilot.press("y")
    outcome = app.return_value
    assert outcome is not None
    assert token not in outcome.result.text
    assert outcome.decisions.additions == (token,)
    assert not outcome.result.residuals
