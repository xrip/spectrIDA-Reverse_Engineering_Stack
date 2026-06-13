"""Bottom status bar — live info on the left, a rotating ghost quip on the right."""
from __future__ import annotations

from rich.style import Style
from rich.text import Text
from textual.widgets import Static

from spectrida import voice


class StatusBar(Static):
    def __init__(self, **kw):
        super().__init__(id="statusbar", **kw)
        self._info = ""
        self._quip = voice.quip("idle")
        self._progress: tuple[int, int, str] | None = None

    def on_mount(self) -> None:
        self.set_interval(20, self._tick)

    def _tick(self) -> None:
        self._quip = voice.quip("idle")
        self.refresh()

    def set_info(self, info: str) -> None:
        self._info = info
        self.refresh()

    def set_progress(self, done: int, total: int, label: str = "") -> None:
        """Show a progress bar on the left (overrides info until cleared)."""
        self._progress = (done, total, label)
        self.refresh()

    def clear_progress(self) -> None:
        self._progress = None
        self.refresh()

    def _progress_text(self) -> Text:
        done, total, label = self._progress
        width = 16
        filled = int(width * done / total) if total else 0
        bar = "█" * filled + "░" * (width - filled)
        pct = int(100 * done / total) if total else 0
        t = Text()
        t.append("  ", Style(color="#00d4ff"))
        t.append(bar, Style(color="#00d4ff"))
        t.append(f"  {done}/{total} ({pct}%)", Style(color="#94a3b8", bold=True))
        if label:
            t.append(f"  ▸ {label}", Style(color="#64748b"))
        return t

    def render(self) -> Text:
        left = self._progress_text() if self._progress else Text(self._info, Style(color="#64748b"))
        t = Text()
        t.append_text(left)
        w = self.size.width or 80
        pad = max(1, w - left.cell_len - len(self._quip) - 2)
        t.append(" " * pad)
        t.append(self._quip, Style(color="#475569", italic=True))
        return t
