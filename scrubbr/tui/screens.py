from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, OptionList

from scrubbr.tui.fuzzy import options_for


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
