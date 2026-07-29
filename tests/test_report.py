from collections import Counter

from scrubbr.kinds import Finding, Kind, Residual
from scrubbr.report import _fit, render_report
from scrubbr.scrub import ScrubResult


def _finding(kind: Kind, text: str, alias: str) -> Finding:
    return Finding(kind=kind, start=0, end=len(text), text=text, alias=alias)


def _result(
    findings: tuple[Finding, ...] = (), residuals: tuple[Residual, ...] = ()
) -> ScrubResult:
    distinct = {(finding.kind, finding.text.lower()) for finding in findings}
    counts = Counter(kind for kind, _ in distinct)
    return ScrubResult(
        text="", findings=list(findings), residuals=list(residuals), counts=dict(counts)
    )


MAC = _finding(Kind.MAC, "aa:bb:cc:dd:ee:ff", "6e:12:9f:a4:68:68")
EMAIL = _finding(Kind.EMAIL, "alice@corp.example", "person-a@example.invalid")


def test_the_summary_names_distinct_values_and_total_replacements() -> None:
    lines = render_report(_result((MAC, MAC, EMAIL)), verbose=False, width=80)
    assert lines == [
        "scrubbed 2 distinct values, 3 replacements",
        "  mac 1, email 1",
    ]


def test_verbose_adds_a_table_with_one_row_per_distinct_value() -> None:
    lines = render_report(_result((MAC, MAC, EMAIL)), verbose=True, width=80)
    assert lines == [
        "scrubbed 2 distinct values, 3 replacements",
        "  mac 1, email 1",
        "",
        "kind   count  text                alias",
        "mac        2  aa:bb:cc:dd:ee:ff   6e:12:9f:a4:68:68",
        "email      1  alice@corp.example  person-a@example.invalid",
    ]


def test_rows_are_ordered_by_sensitivity_then_frequency() -> None:
    other_mac = _finding(Kind.MAC, "ff:ee:dd:cc:bb:aa", "12:34:56:78:9a:bc")
    lines = render_report(
        _result((EMAIL, MAC, other_mac, other_mac)), verbose=True, width=80
    )
    rows = lines[4:]
    assert [row.split()[0] for row in rows] == ["mac", "mac", "email"]
    assert "ff:ee:dd:cc:bb:aa" in rows[0], "within a kind the most frequent value comes first"


def test_a_value_longer_than_its_column_keeps_its_head_and_tail() -> None:
    value = "0123456789" * 6 + "abcd"
    finding = _finding(Kind.HEX, value, "e" * 64)
    lines = render_report(_result((finding,)), verbose=True, width=60)
    assert all(len(line) <= 60 for line in lines)
    text_cell = lines[-1].split()[2]
    assert "…" in text_cell
    assert text_cell.startswith(value[:5])
    assert text_cell.endswith(value[-5:])
    assert len(text_cell) < len(value)


def test_truncation_edge_widths() -> None:
    assert _fit("abcdef", 0) == ""
    assert _fit("abcdef", 1) == "…"
    assert _fit("abcdef", 2) == "a…"
    assert _fit("abcdef", 6) == "abcdef"
    for width in range(20):
        assert len(_fit("abcdefghijklmnop", width)) <= width


def test_a_short_alias_leaves_its_slack_to_the_text_column() -> None:
    finding = _finding(Kind.HEX, "f" * 100, "x")
    lines = render_report(_result((finding,)), verbose=True, width=60)
    text_cell = lines[-1].split()[2]
    assert len(text_cell) == 40, "text takes all the width the short alias does not need"


def test_multiline_pem_text_and_alias_render_on_a_single_line() -> None:
    finding = _finding(
        Kind.PEM,
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END RSA PRIVATE KEY-----",
        "\n[scrubbr: redacted, 179 bytes]\n",
    )
    lines = render_report(_result((finding,)), verbose=True, width=100)
    row = lines[-1]
    assert row.startswith("pem")
    assert row.endswith("[scrubbr: redacted, 179 bytes]")
    assert "-----BEGIN RSA" in row
    assert "…" in row


def test_residuals_render_as_a_table_with_right_aligned_line_numbers() -> None:
    residuals = (
        Residual(
            line=7,
            text="ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            reason="known credential prefix",
        ),
        Residual(line=118, text="kJH8s2Vx9pQ7wLm3tR5uYq2Zx8Nw4Kd", reason="high entropy"),
    )
    lines = render_report(_result(residuals=residuals), verbose=False, width=80)
    assert lines == [
        "scrubbed 0 distinct values, 0 replacements",
        "",
        "2 unscrubbed strings look sensitive:",
        "  line  reason                   text",
        "     7  known credential prefix  ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
        "   118  high entropy             kJH8s2Vx9pQ7wLm3tR5uYq2Zx8Nw4Kd",
    ]


def test_a_long_unscrubbed_value_is_truncated_on_screen() -> None:
    residual = Residual(line=3, text="x" * 200, reason="high entropy")
    lines = render_report(_result(residuals=(residual,)), verbose=False, width=60)
    assert all(len(line) <= 60 for line in lines)
    assert "…" in lines[-1]


def test_a_wide_terminal_does_not_widen_what_a_secret_shows() -> None:
    finding = _finding(Kind.HEX, "f" * 100, "x")
    lines = render_report(_result((finding,)), verbose=True, width=300)
    text_cell = lines[-1].split()[2]
    assert len(text_cell) == 60, "the report names values, it does not reproduce them"
    assert "…" in text_cell


def test_findings_and_residuals_sections_are_separated_by_blank_lines() -> None:
    residual = Residual(line=3, text="ghp_A1b2C3d4", reason="known credential prefix")
    lines = render_report(_result((MAC,), (residual,)), verbose=True, width=80)
    assert lines.count("") == 2
    header = next(index for index, line in enumerate(lines) if line.startswith("kind "))
    warning = next(index for index, line in enumerate(lines) if "look sensitive" in line)
    assert header < warning


def test_no_findings_renders_only_the_summary_line() -> None:
    assert render_report(_result(), verbose=True, width=80) == [
        "scrubbed 0 distinct values, 0 replacements"
    ]


def test_a_narrow_width_is_clamped_to_the_floor() -> None:
    result = _result((MAC, EMAIL))
    assert render_report(result, verbose=True, width=10) == render_report(
        result, verbose=True, width=40
    )
