import builtins
import json
import sys
from importlib.metadata import version
from pathlib import Path
from typing import Any, Never

import pytest

from scrubbr.cli import _stderr_width, main
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


class FakeStdin:
    def __init__(self, answer: str) -> None:
        self._answer = answer

    def isatty(self) -> bool:
        return True

    def readline(self) -> str:
        return self._answer


@pytest.fixture
def no_dev_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    real_open = builtins.open

    def fake_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if file == "/dev/tty":
            raise OSError("no such device")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)


def test_scrubbed_text_goes_to_stdout_and_the_report_to_stderr(
    sample_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(sample_file), "-y", "--no-identity"]) == 0
    captured = capsys.readouterr()
    assert "aa:bb:cc:dd:ee:ff" not in captured.out
    assert captured.out.endswith("\n")
    assert "mac" in captured.err


def test_version_reports_the_installed_package_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"scrubbr {version('scrubbr')}"


def test_verbose_reports_the_original_text_count_and_alias_for_a_repeated_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "log.txt"
    path.write_text("hw aa:bb:cc:dd:ee:ff and again aa:bb:cc:dd:ee:ff\n", encoding="utf-8")
    assert main([str(path), "-v", "-y", "--no-identity"]) == 0
    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    replaced = [event for event in events if event["event"] == "replaced"]
    assert len(replaced) == 1
    assert replaced[0]["kind"] == "mac"
    assert replaced[0]["text"] == "aa:bb:cc:dd:ee:ff"
    assert replaced[0]["count"] == 2
    assert replaced[0]["alias"] != "aa:bb:cc:dd:ee:ff"


def test_on_a_terminal_the_report_is_a_table_not_json_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "log.txt"
    path.write_text("hw aa:bb:cc:dd:ee:ff and again aa:bb:cc:dd:ee:ff\n", encoding="utf-8")
    monkeypatch.setenv("COLUMNS", "100")
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    assert main([str(path), "-v", "-y", "--no-identity"]) == 0
    err = capsys.readouterr().err
    assert "scrubbed 1 distinct values, 2 replacements" in err
    assert "kind" in err and "count" in err
    assert "aa:bb:cc:dd:ee:ff" in err
    with pytest.raises(json.JSONDecodeError):
        json.loads(err.splitlines()[0])


def test_the_stderr_width_falls_back_when_stderr_is_not_a_real_terminal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("COLUMNS", raising=False)
    assert _stderr_width() == 80


def test_without_verbose_no_replaced_event_is_reported(
    sample_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(sample_file), "-y", "--no-identity"]) == 0
    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert not [event for event in events if event["event"] == "replaced"]


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
    assert "[REDACTED]" in out


def test_also_with_a_private_ip_scrubs_it_while_other_private_ips_survive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "log.txt"
    path.write_text("peers 10.0.0.5 and 10.0.0.6\n", encoding="utf-8")
    assert main([str(path), "-y", "--no-identity", "--also", "10.0.0.5"]) == 0
    out = capsys.readouterr().out
    assert "10.0.0.5" not in out
    assert "10.0.0.6" in out


def test_verbose_reports_the_redacted_kind_for_an_also_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "log.txt"
    path.write_text("connecting to prod-db-07 now\n", encoding="utf-8")
    assert main([str(path), "-v", "-y", "--no-identity", "--also", "prod-db-07"]) == 0
    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    counted = next(event for event in events if event["event"] == "scrubbed")
    assert counted["redacted"] == 1
    replaced = [event for event in events if event["event"] == "replaced"]
    assert len(replaced) == 1
    assert replaced[0]["kind"] == "redacted"
    assert replaced[0]["alias"] == "[REDACTED]"


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


def test_the_output_option_writes_the_scrubbed_text_to_a_file_and_leaves_stdout_empty(
    sample_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out_path = tmp_path / "out.txt"
    assert main([str(sample_file), "-y", "--no-identity", "-o", str(out_path)]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    written = out_path.read_text(encoding="utf-8")
    assert "aa:bb:cc:dd:ee:ff" not in written
    assert "written" in captured.err


def test_declining_at_review_with_the_output_option_leaves_no_file_behind(
    sample_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out_path = tmp_path / "out.txt"
    exit_code = main(
        [str(sample_file), "--no-identity", "-o", str(out_path)],
        open_tty=lambda: FakeTerminal("n\n"),
    )
    assert exit_code == 1
    assert capsys.readouterr().out == ""
    assert not out_path.exists()


def test_strict_refusal_with_the_output_option_leaves_no_file_behind(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "log.txt"
    path.write_text("tok ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6\n", encoding="utf-8")
    out_path = tmp_path / "out.txt"
    assert main([str(path), "-y", "--strict", "--no-identity", "-o", str(out_path)]) == 2
    assert capsys.readouterr().out == ""
    assert not out_path.exists()


def test_an_unwritable_output_path_returns_four_and_emits_nothing(
    sample_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out_path = tmp_path / "missing" / "out.txt"
    assert main([str(sample_file), "-y", "--no-identity", "-o", str(out_path)]) == 4
    assert capsys.readouterr().out == ""


def test_without_dev_tty_but_with_an_interactive_shell_the_review_runs_on_stdio(
    no_dev_tty: None,
    sample_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "stdin", FakeStdin("y\n"))
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    assert main([str(sample_file), "--no-identity"]) == 0
    captured = capsys.readouterr()
    assert "-host box hw" in captured.err
    assert "emit scrubbed text?" in captured.err
    assert captured.out and "aa:bb:cc:dd:ee:ff" not in captured.out


def test_without_dev_tty_but_with_an_interactive_shell_declining_emits_nothing(
    no_dev_tty: None,
    sample_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "stdin", FakeStdin("n\n"))
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    assert main([str(sample_file), "--no-identity"]) == 1
    assert capsys.readouterr().out == ""


def test_without_dev_tty_and_a_non_interactive_stdin_it_still_refuses(
    no_dev_tty: None,
    sample_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert main([str(sample_file), "--no-identity"]) == 3
    assert capsys.readouterr().out == ""
