from collections.abc import Sequence
from typing import ClassVar

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Footer, Input, OptionList, Static

from scrubbr.kinds import Residual
from scrubbr.report import clip
from scrubbr.review import render_diff, render_residuals
from scrubbr.tui.fuzzy import options_for

REDACTED_TEXT = "[REDACTED]"
CUSTOM_LABEL = "custom…"
DIFF_CONTEXT = 2


class FuzzyFindScreen(ModalScreen[str | None]):
    """Pick extra text to scrub: type to fuzzy-find a token, or paste an exact string."""

    DEFAULT_CSS = """
    FuzzyFindScreen {
        align: center middle;
    }
    #finder {
        width: 80%;
        height: 80%;
        background: $surface;
        border: round $primary;
    }
    """

    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "cancel", "cancel")]

    def __init__(self, text: str, pool: list[str]) -> None:
        super().__init__()
        self._text = text
        self._pool = pool
        self._values: list[str] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="finder"):
            yield Input(placeholder="text to scrub")
            yield OptionList()

    def on_mount(self) -> None:
        self._show_options("")
        self.query_one(Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        self._show_options(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        chooser = self.query_one(OptionList)
        index = chooser.highlighted if chooser.highlighted is not None else 0
        if index < len(self._values):
            self.dismiss(self._values[index])
        else:
            self.dismiss(None)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(self._values[event.option_index])

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _show_options(self, query: str) -> None:
        options = options_for(query, self._text, self._pool)
        self._values = [value for _, value in options]
        chooser = self.query_one(OptionList)
        chooser.clear_options()
        chooser.add_options([label for label, _ in options])
        if self._values:
            chooser.highlighted = 0


class ReplacementScreen(ModalScreen[str | None]):
    """Choose what a value is replaced with: its minted alias, [REDACTED], or free text.

    Dismisses with the chosen replacement string, or None for no change. Choosing the
    minted alias is how an override is undone; the caller compares and drops it.
    """

    DEFAULT_CSS = """
    ReplacementScreen {
        align: center middle;
    }
    #chooser {
        width: 60%;
        height: auto;
        max-height: 80%;
        background: $surface;
        border: round $primary;
        padding: 1;
    }
    #custom.hidden {
        display: none;
    }
    """

    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "cancel", "cancel")]

    def __init__(self, shown_text: str, default_alias: str, current: str | None) -> None:
        super().__init__()
        self._shown = shown_text
        self._default = default_alias
        self._current = current
        self._values = [default_alias]
        if default_alias != REDACTED_TEXT:
            self._values.append(REDACTED_TEXT)

    def compose(self) -> ComposeResult:
        with Vertical(id="chooser"):
            yield Static(f"replace {clip(self._shown)} with:")
            yield OptionList()
            yield Input(placeholder="custom replacement", id="custom", classes="hidden")

    def on_mount(self) -> None:
        labels = [f"{clip(self._default)}  (minted alias)"]
        if len(self._values) > 1:
            labels.append(REDACTED_TEXT)
        labels.append(CUSTOM_LABEL)
        chooser = self.query_one(OptionList)
        chooser.add_options(labels)
        if self._current in self._values:
            chooser.highlighted = self._values.index(self._current)
        else:
            chooser.highlighted = 0
        if self._current is not None and self._current not in self._values:
            self._reveal_custom(self._current)
        chooser.focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_index < len(self._values):
            self.dismiss(self._values[event.option_index])
        else:
            self._reveal_custom(self._current or "")
            self.query_one(Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        self.dismiss(value or None)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _reveal_custom(self, prefill: str) -> None:
        custom = self.query_one(Input)
        custom.value = prefill
        custom.remove_class("hidden")


class DiffScreen(Screen[bool]):
    """The full diff — the last look before the scrubbed text is emitted."""

    DEFAULT_CSS = """
    DiffScreen VerticalScroll {
        padding: 0 1;
    }
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("y", "confirm", "emit"),
        Binding("enter", "confirm", "emit", show=False),
        Binding("escape", "back", "back"),
        Binding("b", "back", "back", show=False),
    ]

    def __init__(self, original: str, scrubbed: str, residuals: Sequence[Residual]) -> None:
        super().__init__()
        self._original = original
        self._scrubbed = scrubbed
        self._residuals = residuals

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static(self._rendered())
        yield Footer()

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_back(self) -> None:
        self.dismiss(False)

    def _rendered(self) -> Text:
        body = Text()
        diff = render_diff(self._original, self._scrubbed, context=DIFF_CONTEXT)
        if not diff:
            body.append("no changes\n", "dim")
        for line in diff.splitlines():
            body.append(line + "\n", _diff_style(line))
        warning = render_residuals(self._residuals)
        if warning:
            body.append("\n")
            body.append(warning + "\n", "yellow")
        return body


def _diff_style(line: str) -> str:
    if line.startswith("+"):
        return "green"
    if line.startswith("-"):
        return "red"
    if line.startswith("@@"):
        return "dim"
    return ""
