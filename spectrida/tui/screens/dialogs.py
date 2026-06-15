"""Modal dialogs — rename + help overlay."""
from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Label, Static

from spectrida import voice


class RenameDialog(ModalScreen[str | None]):
    BINDINGS = [Binding("escape", "dismiss(None)", "cancel")]

    def __init__(self, current: str, suggested: str | None = None):
        super().__init__()
        self._current = current
        self._suggested = suggested

    def compose(self) -> ComposeResult:
        with Vertical(id="rename-dialog"):
            yield Label(" ✎  rename function", id="rename-title")
            yield Input(value=self._suggested or self._current,
                        placeholder="new_function_name", id="rename-input")
            yield Label("↵ confirm   ·   esc cancel", id="dialog-hint")

    @on(Input.Submitted)
    def _submit(self, event: Input.Submitted) -> None:
        self.dismiss(event.value.strip() or None)


class MinXrefsDialog(ModalScreen[int | None]):
    """Ask for the minimum code-xref count a global needs before it's worth
    naming. Returns the chosen int, or None on cancel."""
    BINDINGS = [Binding("escape", "dismiss(None)", "cancel")]

    def __init__(self, default: int = 3):
        super().__init__()
        self._default = default

    def compose(self) -> ComposeResult:
        with Vertical(id="rename-dialog"):
            yield Label(" ◴  name globals — minimum xrefs", id="rename-title")
            yield Input(value=str(self._default), placeholder="3",
                        type="integer", id="minxrefs-input")
            yield Label("only globals referenced at least this many times are named\n"
                        "↵ confirm   ·   esc cancel", id="dialog-hint")

    @on(Input.Submitted)
    def _submit(self, event: Input.Submitted) -> None:
        raw = (event.value or "").strip()
        try:
            n = int(raw)
        except ValueError:
            n = self._default
        self.dismiss(max(1, n))


class HelpScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape,question_mark,q", "dismiss", "close")]

    _KEYS = [
        ("N", "name the selected function (AI)"),
        ("V", "name + type vars/params + return (staged AI, Hex-Rays)"),
        ("R", "rename (pre-fills the AI suggestion)"),
        ("D", "toggle decompiled pseudocode"),
        ("C", "call chain — callers / callees"),
        ("B", "deep-name the WHOLE binary, branch by branch (bottom-up; types named funcs too)"),
        ("U", "find every sub_* branch and deep-name it (bottom-up)"),
        ("T", "deep-name this call branch (bottom-up; re-types already-named funcs)"),
        ("F", "recover structs from field accesses, apply to pointer params"),
        ("G", "name + type generic globals (dword_*, …) from their use sites"),
        ("L", "lint — unify naming across the binary (msg/message, typos, …)"),
        ("A", "audit — change journal + export an IDAPython revert script"),
        ("O", "overview — AI summary of the whole binary"),
        ("[ / ]", "scroll the report pane (mouse wheel works too)"),
        ("/", "fuzzy search"),
        ("ctrl+p", "command palette"),
        ("Q", "quit"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="help-dialog"):
            yield Label(" ?  spectrIDA — keys", id="help-title")
            body = "\n".join(f"  [b cyan]{k:<7}[/]  {d}" for k, d in self._KEYS)
            yield Static(body, id="help-body")
            yield Static(f"\n  [dim]{voice.quip('idle')}[/]")
            yield Label("esc / ? to close", id="dialog-hint")


class OverviewScreen(ModalScreen[None]):
    """Streams the AI binary overview into a scrollable overlay."""
    BINDINGS = [Binding("escape,o,q", "dismiss", "close")]

    def __init__(self, text: str = ""):
        super().__init__()
        self._text = text

    def compose(self) -> ComposeResult:
        with Vertical(id="help-dialog"):
            yield Label(" ◈  binary overview", id="help-title")
            yield Static(self._text or "  analyzing…", id="help-body")
            yield Label("esc to close", id="dialog-hint")

    def update(self, text: str) -> None:
        self.query_one("#help-body", Static).update(text)

