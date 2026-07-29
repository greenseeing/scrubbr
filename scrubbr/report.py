import textwrap
from collections import Counter

from scrubbr.kinds import Finding, Kind, Residual
from scrubbr.scrub import ScrubResult

# The report names values, it does not reproduce them: a PEM body is kilobytes across
# many lines, and no terminal width justifies showing more of a secret.
CLIP = 60
# Below this the columns stop being readable anyway; render as if the terminal were this
# wide and let it wrap.
MIN_WIDTH = 40
_GUTTER = "  "
# StrEnum sorts alphabetically; declaration order is the sensitivity order, which is what
# a security report should lead with.
_KIND_ORDER = {kind: index for index, kind in enumerate(Kind)}


def render_report(result: ScrubResult, verbose: bool, width: int) -> list[str]:
    width = max(width, MIN_WIDTH)
    lines = _summary(result, width)
    if verbose and result.findings:
        lines += ["", *_findings_table(result.findings, width)]
    if result.residuals:
        lines += ["", *_residuals_table(result.residuals, width)]
    return lines


def _summary(result: ScrubResult, width: int) -> list[str]:
    distinct = sum(result.counts.values())
    lines = [f"scrubbed {distinct} distinct values, {len(result.findings)} replacements"]
    if result.counts:
        by_kind = ", ".join(
            f"{kind.value} {result.counts[kind]}" for kind in Kind if kind in result.counts
        )
        lines += textwrap.wrap(
            by_kind, width=width, initial_indent=_GUTTER, subsequent_indent=_GUTTER
        )
    return lines


def _findings_table(findings: list[Finding], width: int) -> list[str]:
    occurrences = Counter((f.kind, f.text, f.alias) for f in findings)
    rows = sorted(
        (
            (kind, _flatten(text), count, _flatten(alias))
            for (kind, text, alias), count in occurrences.items()
        ),
        key=lambda row: (_KIND_ORDER[row[0]], -row[2], row[1]),
    )
    kind_w = max(len("kind"), *(len(kind.value) for kind, _, _, _ in rows))
    count_w = max(len("count"), *(len(str(count)) for _, _, count, _ in rows))
    text_w, alias_w = _apportion(
        width - kind_w - count_w - 3 * len(_GUTTER),
        min(CLIP, max(len("text"), *(len(text) for _, text, _, _ in rows))),
        min(CLIP, max(len("alias"), *(len(alias) for _, _, _, alias in rows))),
    )
    template = f"{{:<{kind_w}}}{_GUTTER}{{:>{count_w}}}{_GUTTER}{{:<{text_w}}}{_GUTTER}{{}}"
    header = template.format("kind", "count", _fit("text", text_w), _fit("alias", alias_w))
    lines = [header.rstrip()]
    lines += [
        template.format(kind.value, count, _fit(text, text_w), _fit(alias, alias_w)).rstrip()
        for kind, text, count, alias in rows
    ]
    return lines


def _residuals_table(residuals: list[Residual], width: int) -> list[str]:
    line_w = max(len("line"), *(len(str(residual.line)) for residual in residuals))
    reason_w = max(len("reason"), *(len(residual.reason) for residual in residuals))
    text_w = min(CLIP, width - line_w - reason_w - 3 * len(_GUTTER))
    template = f"{_GUTTER}{{:>{line_w}}}{_GUTTER}{{:<{reason_w}}}{_GUTTER}{{}}"
    lines = [f"{len(residuals)} unscrubbed strings look sensitive:"]
    lines.append(template.format("line", "reason", "text").rstrip())
    lines += [
        template.format(residual.line, residual.reason, _fit(_flatten(residual.text), text_w))
        for residual in residuals
    ]
    return lines


def _apportion(avail: int, text_nat: int, alias_nat: int) -> tuple[int, int]:
    if text_nat + alias_nat <= avail:
        return text_nat, alias_nat
    half = avail // 2
    if text_nat <= half:
        return text_nat, avail - text_nat
    if alias_nat <= half:
        return avail - alias_nat, alias_nat
    return max(avail - half, 0), max(half, 0)


def _fit(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    if width <= 0:
        return ""
    keep = width - 1
    tail = keep // 2
    return value[: keep - tail] + "…" + value[len(value) - tail :]


def _flatten(value: str) -> str:
    return " ".join(value.split())


def clip(value: str) -> str:
    return _flatten(value)[:CLIP]
