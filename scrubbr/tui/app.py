from collections import Counter
from dataclasses import dataclass, replace
from typing import ClassVar

from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.widgets import DataTable, Footer, Static

from scrubbr.decisions import Decisions, ReviewOutcome, ReviewRequest, apply_decisions
from scrubbr.kinds import Finding, Kind, Residual
from scrubbr.report import KIND_ORDER, clip
from scrubbr.scrub import decision_key
from scrubbr.tui.fuzzy import candidates
from scrubbr.tui.screens import DiffScreen, FuzzyFindScreen, ReplacementScreen

# A row stands for a finding (its decision key) or for a residual (its bare text).
RowRef = tuple[Kind, str] | str


@dataclass(frozen=True)
class FindingRow:
    key: tuple[Kind, str]
    kind: Kind
    count: int
    text: str
    alias: str


@dataclass(frozen=True)
class ResidualRow:
    text: str
    count: int
    reason: str


def residual_rows(residuals: list[Residual]) -> list[ResidualRow]:
    counts: Counter[str] = Counter()
    reasons: dict[str, str] = {}
    for residual in residuals:
        counts[residual.text] += 1
        reasons.setdefault(residual.text, residual.reason)
    return [
        ResidualRow(text=text, count=count, reason=reasons[text])
        for text, count in counts.items()
    ]


def finding_rows(findings: list[Finding]) -> list[FindingRow]:
    counts: Counter[tuple[Kind, str]] = Counter()
    first: dict[tuple[Kind, str], Finding] = {}
    for finding in findings:
        key = decision_key(finding.kind, finding.text)
        counts[key] += 1
        first.setdefault(key, finding)
    rows = [
        FindingRow(
            key=key,
            kind=first[key].kind,
            count=count,
            text=first[key].text,
            alias=first[key].alias,
        )
        for key, count in counts.items()
    ]
    return sorted(rows, key=_row_order)


def _row_order(row: FindingRow) -> tuple[int, int, str]:
    return (KIND_ORDER[row.kind], -row.count, row.text.lower())


class ReviewApp(App[ReviewOutcome]):
    """The full-screen review: what will be scrubbed, and the reviewer's say over it."""

    DEFAULT_CSS = """
    #summary {
        height: 1;
        padding: 0 1;
        background: $panel;
    }
    DataTable {
        height: 1fr;
    }
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("space", "toggle_row", "keep/scrub"),
        Binding("a", "add_text", "add text"),
        Binding("r", "set_replacement", "replacement"),
        Binding("y", "accept", "diff & emit"),
        Binding("d", "accept", "diff", show=False),
        Binding("q", "abort", "abort"),
        Binding("escape", "abort", "abort", show=False),
        Binding("j", "cursor_down", show=False),
        Binding("k", "cursor_up", show=False),
    ]

    def __init__(self, request: ReviewRequest) -> None:
        super().__init__()
        self._request = request
        self._result = request.result
        self._decisions = Decisions()
        # Kept values drop out of the recomputed findings, but their rows must stay on
        # screen or there would be nothing left to toggle back.
        self._known: dict[tuple[Kind, str], FindingRow] = {}
        self._row_keys: list[RowRef] = []

    def compose(self) -> ComposeResult:
        yield Static(id="summary")
        yield DataTable(id="findings")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("status", "kind", "count", "text", "replacement")
        self._refresh_view()
        table.focus()

    def action_toggle_row(self) -> None:
        table = self.query_one(DataTable)
        if not self._row_keys:
            return
        ref = self._row_keys[table.cursor_row]
        if isinstance(ref, str):
            self._add(ref)
            return
        key = ref
        kept = set(self._decisions.keep)
        if key in kept:
            kept.discard(key)
        else:
            kept.add(key)
        self._decisions = replace(self._decisions, keep=frozenset(kept))
        self._recompute()

    def action_add_text(self) -> None:
        pool = candidates(self._request.text, self._result.residuals)

        def applied(value: str | None) -> None:
            if value:
                self._add(value)

        self.push_screen(FuzzyFindScreen(self._request.text, pool), applied)

    def action_set_replacement(self) -> None:
        table = self.query_one(DataTable)
        if not self._row_keys:
            return
        ref = self._row_keys[table.cursor_row]
        if isinstance(ref, str) or ref in self._decisions.keep:
            return
        row = self._known[ref]
        default = self._request.book.alias_for(row.kind, row.text)

        def applied(value: str | None) -> None:
            if value is None:
                return
            overrides = dict(self._decisions.overrides)
            if value == default:
                overrides.pop(ref, None)
            else:
                overrides[ref] = value
            self._decisions = replace(self._decisions, overrides=overrides)
            self._recompute()

        current = self._decisions.overrides.get(ref)
        self.push_screen(ReplacementScreen(row.text, default, current), applied)

    def _add(self, value: str) -> None:
        if value in self._decisions.additions:
            return
        self._decisions = replace(
            self._decisions, additions=(*self._decisions.additions, value)
        )
        self._recompute()

    def action_accept(self) -> None:
        def verdict(confirmed: bool | None) -> None:
            if confirmed:
                self.exit(
                    ReviewOutcome(confirmed=True, result=self._result, decisions=self._decisions)
                )

        self.push_screen(
            DiffScreen(self._request.text, self._result.text, self._result.residuals), verdict
        )

    def action_abort(self) -> None:
        self.exit(
            ReviewOutcome(confirmed=False, result=self._request.result, decisions=self._decisions)
        )

    def action_cursor_down(self) -> None:
        self.query_one(DataTable).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one(DataTable).action_cursor_up()

    def _recompute(self) -> None:
        self._result = apply_decisions(
            self._request.text, self._request.identity, self._decisions, self._request.book
        )
        self._refresh_view()

    def _refresh_view(self) -> None:
        for row in finding_rows(self._result.findings):
            self._known[row.key] = row
        table = self.query_one(DataTable)
        cursor = table.cursor_row
        table.clear()
        self._row_keys = []
        for row in sorted(self._known.values(), key=_row_order):
            kept = row.key in self._decisions.keep
            table.add_row(
                "keep" if kept else "scrub",
                row.kind.value,
                str(row.count),
                clip(row.text),
                "" if kept else clip(row.alias),
            )
            self._row_keys.append(row.key)
        for residual in residual_rows(self._result.residuals):
            table.add_row("warn", residual.reason, str(residual.count), clip(residual.text), "")
            self._row_keys.append(residual.text)
        if self._row_keys:
            table.move_cursor(row=min(cursor, len(self._row_keys) - 1))
        self._update_summary()

    def _update_summary(self) -> None:
        distinct = sum(self._result.counts.values())
        line = f"scrubbed {distinct} distinct values, {len(self._result.findings)} replacements"
        if self._decisions.keep:
            line += f" — {len(self._decisions.keep)} kept"
        self.query_one("#summary", Static).update(line)
