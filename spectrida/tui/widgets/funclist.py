"""A virtualized function list — holds all functions, renders only the visible window."""
from __future__ import annotations

from rich.style import Style
from rich.text import Text
from textual.message import Message
from textual.widget import Widget

from spectrida.tui.widgets.disasm import fmt_size, is_sub


class FuncList(Widget, can_focus=True):
    """Scrollable, keyboard-driven, handles 100k+ rows by only drawing what's visible."""

    class Selected(Message):
        def __init__(self, item: dict) -> None:
            self.item = item
            super().__init__()

    def __init__(self, **kw):
        super().__init__(**kw)
        self._all: list[dict] = []
        self._items: list[dict] = []
        self.cursor = 0
        self.top = 0

    def set_functions(self, funcs: list[dict]) -> None:
        self._all = funcs
        self._items = funcs
        self.cursor = 0
        self.top = 0
        self.refresh()
        self._emit()

    def filter(self, query: str) -> None:
        q = query.strip().lower()
        self._items = self._all if not q else [f for f in self._all if q in f["name"].lower()]
        self.cursor = 0
        self.top = 0
        self.refresh()
        self._emit()

    @property
    def selected(self) -> dict | None:
        return self._items[self.cursor] if self._items else None

    def _emit(self) -> None:
        if self.selected:
            self.post_message(self.Selected(self.selected))

    def _height(self) -> int:
        return max(1, self.size.height)

    def _jump(self, idx: int) -> None:
        """Move cursor to absolute index, centering it in the viewport."""
        self.cursor = max(0, min(len(self._items) - 1, idx))
        h = self._height()
        self.top = max(0, self.cursor - h // 2)
        self.refresh()
        self._emit()

    def seek(self, addr: int) -> None:
        """Move cursor to the function at addr, or the closest by address."""
        if not self._items:
            return
        for i, f in enumerate(self._items):
            if f["start"] == addr:
                self._jump(i)
                return
        best = min(range(len(self._items)), key=lambda i: abs(self._items[i]["start"] - addr))
        self._jump(best)

    def _move(self, delta: int) -> None:
        if not self._items:
            return
        self.cursor = max(0, min(len(self._items) - 1, self.cursor + delta))
        h = self._height()
        if self.cursor < self.top:
            self.top = self.cursor
        elif self.cursor >= self.top + h:
            self.top = self.cursor - h + 1
        self.refresh()
        self._emit()

    def on_key(self, event) -> None:
        k = event.key
        if k in ("up", "k"):           self._move(-1)
        elif k in ("down", "j"):       self._move(1)
        elif k == "pageup":            self._move(-self._height())
        elif k == "pagedown":          self._move(self._height())
        elif k == "home":              self._move(-len(self._items))
        elif k == "end":               self._move(len(self._items))
        else:
            return
        event.stop()

    def on_click(self, event) -> None:
        self.focus()
        row = self.top + int(event.y)
        if 0 <= row < len(self._items):
            self.cursor = row
            self.refresh()
            self._emit()

    def render(self):
        if not self._items:
            return Text("  (no functions here. spooky.)", Style(color="#475569"))
        h = self._height()
        out = Text()
        for idx in range(self.top, min(self.top + h, len(self._items))):
            f = self._items[idx]
            sub = is_sub(f["name"])
            t = Text()
            addr = f"{f['start']:08x}"[-8:]
            t.append(f" {addr} ", Style(color="#374151"))
            t.append(f["name"], Style(color="#4a5568" if sub else "#e2e8f0", bold=not sub))
            sz = fmt_size(f.get("size", 0))
            if sz:
                t.append(f"  {sz}", Style(color="#2d3748"))
            if idx == self.cursor:
                t.stylize(Style(bgcolor="#1f2a3f", color="#00d4ff", bold=True))
            out.append_text(t)
            out.append("\n")
        return out
