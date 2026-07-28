from pathlib import Path
from typing import Never

import pytest

from scrubbr.cli import main
from scrubbr.review import NoTerminal, confirm
from scrubbr.scrub import scrub

SAMPLE = "host box hw aa:bb:cc:dd:ee:ff up\n"


def _no_terminal() -> Never:
    raise NoTerminal


class FakeTerminal:
    """A character device reads and writes independently; StringIO shares one cursor."""

    def __init__(self, answer: str) -> None:
        self._answer = answer
        self.shown = ""

    def write(self, text: str) -> int:
        self.shown += text
        return len(text)

    def flush(self) -> None:
        return None

    def readline(self) -> str:
        return self._answer

    def close(self) -> None:
        return None


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    path = tmp_path / "log.txt"
    path.write_text(SAMPLE, encoding="utf-8")
    return path


def test_scrubbed_text_goes_to_stdout_and_the_report_to_stderr(
    sample_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(sample_file), "-y", "--no-identity"]) == 0
    captured = capsys.readouterr()
    assert "aa:bb:cc:dd:ee:ff" not in captured.out
    assert captured.out.endswith("\n")
    assert "mac" in captured.err


def test_strict_refuses_to_emit_when_something_suspicious_remains(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "log.txt"
    path.write_text("tok ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6\n", encoding="utf-8")
    assert main([str(path), "-y", "--strict", "--no-identity"]) == 2
    assert capsys.readouterr().out == ""


def test_also_scrubs_a_literal_the_tool_could_not_have_guessed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "log.txt"
    path.write_text("connecting to prod-db-07 now\n", encoding="utf-8")
    assert main([str(path), "-y", "--no-identity", "--also", "prod-db-07"]) == 0
    out = capsys.readouterr().out
    assert "prod-db-07" not in out
    assert "host-a" in out


def test_without_a_terminal_it_refuses_rather_than_emitting_unreviewed_text(
    sample_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(sample_file), "--no-identity"], open_tty=_no_terminal) == 3
    assert capsys.readouterr().out == "", "nothing may reach stdout unreviewed"


def test_declining_at_review_emits_nothing(
    sample_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(sample_file), "--no-identity"], open_tty=lambda: FakeTerminal("n\n")) == 1
    assert capsys.readouterr().out == ""


def test_accepting_at_review_emits_the_scrubbed_text(
    sample_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(sample_file), "--no-identity"], open_tty=lambda: FakeTerminal("y\n")) == 0
    out = capsys.readouterr().out
    assert out and "aa:bb:cc:dd:ee:ff" not in out


def test_the_review_shows_the_diff_on_the_terminal_main_gave_it(
    sample_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    terminal = FakeTerminal("n\n")
    main([str(sample_file), "--no-identity"], open_tty=lambda: terminal)
    assert "aa:bb:cc:dd:ee:ff" in terminal.shown, "the review must show what is replaced"
    assert capsys.readouterr().out == ""


def test_confirm_prompts_on_the_terminal_and_honours_the_answer() -> None:
    terminal = FakeTerminal("y\n")
    result = scrub(SAMPLE)
    assert confirm(SAMPLE, result.text, result.residuals, terminal) is True
    assert "emit scrubbed text?" in terminal.shown
    assert "aa:bb:cc:dd:ee:ff" in terminal.shown, "the review must show what is replaced"


def test_confirm_treats_anything_but_yes_as_no() -> None:
    result = scrub(SAMPLE)
    assert confirm(SAMPLE, result.text, result.residuals, FakeTerminal("\n")) is False


def test_the_review_diff_names_both_sides_and_shows_the_change() -> None:
    terminal = FakeTerminal("\n")
    result = scrub(SAMPLE)
    confirm(SAMPLE, result.text, result.residuals, terminal)
    assert "original" in terminal.shown
    assert "scrubbed" in terminal.shown
    assert "-host box hw aa:bb:cc:dd:ee:ff up" in terminal.shown


def test_the_review_warns_about_residuals_on_the_terminal() -> None:
    text = "tok ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6\n"
    result = scrub(text)
    terminal = FakeTerminal("\n")
    confirm(text, result.text, result.residuals, terminal)
    assert "look sensitive" in terminal.shown


def test_the_review_stays_quiet_when_there_is_nothing_to_warn_about() -> None:
    text = "plain words only\n"
    result = scrub(text)
    terminal = FakeTerminal("\n")
    confirm(text, result.text, result.residuals, terminal)
    assert "look sensitive" not in terminal.shown
