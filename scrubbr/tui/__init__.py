from scrubbr.decisions import Decisions, ReviewOutcome, ReviewRequest
from scrubbr.review import ScreenTerminal, tty_stdio
from scrubbr.tui.app import ReviewApp


def run_review(request: ReviewRequest, terminal: ScreenTerminal) -> ReviewOutcome:
    """Hold the full-screen review on the caller's terminal, never on the stdout pipe."""
    with tty_stdio(terminal):
        outcome = ReviewApp(request).run()
    if outcome is None:
        return ReviewOutcome(confirmed=False, result=request.result, decisions=Decisions())
    return outcome
