"""The function browser — search, disasm/decompile, AI naming, call-chain, rename, batch."""
from __future__ import annotations

import asyncio
from typing import ClassVar

from rich.style import Style
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Input, Label, Static

from spectrida import voice
from spectrida.core.backend import Backend
from spectrida.tui.screens.dialogs import HelpScreen, OverviewScreen, RenameDialog
from spectrida.tui.widgets.disasm import DisasmPane, is_sub
from spectrida.tui.widgets.funclist import FuncList
from spectrida.tui.widgets.statusbar import StatusBar


def _xref_label(x: dict) -> str:
    """Signature if the neighbour function has a known type (shows params), else
    its name, else its address."""
    return x.get("proto") or x.get("name") or x.get("address", "")


def _var_change(old: str, spec) -> str:
    """Render one variable rename/retype for the model pane: a1→[cyan]player[/]:[magenta]Player *[/]."""
    if isinstance(spec, dict):
        name = spec.get("name", ""); ty = spec.get("type", "")
    else:
        name, ty = spec, ""
    out = f"{old}→[cyan]{name}[/]"
    if ty:
        out += f":[magenta]{ty}[/]"
    return out


class BrowserScreen(Screen):
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("n", "name_func", "Name"),
        Binding("v", "name_vars", "Vars"),
        Binding("r", "rename_func", "Rename"),
        Binding("d", "decompile_func", "Decompile"),
        Binding("c", "chain_func", "Chain"),
        Binding("b", "batch_name", "Batch"),
        Binding("t", "deep_branch", "Deep"),
        Binding("o", "overview", "Overview"),
        Binding("slash", "focus_search", "Search"),
        Binding("question_mark", "help", "Help"),
        Binding("q", "app.quit", "Quit"),
    ]

    def __init__(self, backend: Backend):
        super().__init__()
        self._b = backend
        self._cur: dict | None = None
        self._insns: list[dict] = []
        self._callees: list[str] = []
        self._callers: list[str] = []
        self._suggested: str | None = None
        self._decompiled = False
        self._busy = False

    def compose(self) -> ComposeResult:
        tag = " demo" if self._b.demo else ""
        yield Horizontal(
            Static(f" ◈  spectrIDA  ▸  {self._b.title}{tag}", id="header-title"),
            Static(" ● loading…", id="header-status"),
            id="header",
        )
        with Horizontal(id="browser-body"):
            with Vertical(id="func-panel"):
                yield Input(placeholder=" / search functions…", id="func-search")
                yield Label("", id="func-count")
                yield FuncList(id="func-list")
            with Vertical(id="right-panel"):
                yield Static("  DISASSEMBLY", id="disasm-header")
                yield DisasmPane(id="disasm-pane")
                yield Static("  MODEL", id="model-header")
                with Vertical(id="model-pane"):
                    yield Static("Press [b cyan]N[/] to name this function · [b cyan]V[/] for its variables.", id="model-hint")
                    yield Static("", id="model-spinner")
                    yield Static("", id="model-result")
                    yield Static("", id="model-reason")
        yield StatusBar()

    def _spawn(self, coro):
        t = asyncio.create_task(coro)
        self._tasks = getattr(self, '_tasks', set())
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)
        return t

    def on_mount(self) -> None:
        # defer to post-mount: the worker manager isn't ready during on_mount
        self.call_after_refresh(lambda: self._spawn(self._load()))

    async def _load(self) -> None:
        try:
            await self._b.ensure_open()
            funcs = await self._b.list_functions()
        except Exception as e:
            self.query_one("#header-status", Static).update(f" ✗ {e}")
            self.query_one("#func-count", Label).update(f"  ✗ {voice.quip('error')} — {e}")
            return
        fl = self.query_one("#func-list", FuncList)
        fl.set_functions(funcs)
        fl.focus()  # focus immediately so keyboard works as soon as list appears
        named = sum(1 for f in funcs if not is_sub(f["name"]))
        self.query_one("#func-count", Label).update(f"  {len(funcs):,} funcs · {named:,} named")
        self.query_one("#header-status", Static).update(f" ●  {len(funcs):,} funcs")
        self.query_one(StatusBar).set_info(f"{self._b.title} · {len(funcs):,} functions")

    # ── search ──
    @on(Input.Changed, "#func-search")
    def _on_search(self, e: Input.Changed) -> None:
        self.query_one("#func-list", FuncList).filter(e.value)

    def action_focus_search(self) -> None:
        self.query_one("#func-search", Input).focus()

    # ── selection ──
    @on(FuncList.Selected)
    def _on_select(self, msg: FuncList.Selected) -> None:
        self._cur = msg.item
        self._suggested = None
        self._decompiled = False
        self._clear_model()
        self._spawn(self._load_disasm())

    async def _load_disasm(self) -> None:
        if not self._cur:
            return
        addr = self._cur["start"]
        self.query_one("#disasm-header", Static).update(
            f"  DISASSEMBLY  ▸  [b]{self._cur['name']}[/]  [dim]{addr:#x}[/]")
        self._insns = await self._b.disasm(addr)
        self.query_one(DisasmPane).show_disasm(self._insns)
        # gather call-chain context for naming — prefer full signatures (params)
        # so already-named neighbours give the model real context
        self._callees = [_xref_label(x) for x in await self._b.xrefs_from(addr)]
        self._callers = [_xref_label(x) for x in await self._b.xrefs_to(addr)]

    # ── decompile toggle ──
    def action_decompile_func(self) -> None:
        if not self._cur:
            return
        self._decompiled = not self._decompiled
        self._spawn(self._show_decompile() if self._decompiled else self._reshow_disasm())

    async def _show_decompile(self) -> None:
        self.query_one("#disasm-header", Static).update(f"  PSEUDOCODE  ▸  [b]{self._cur['name']}[/]")
        code = await self._b.decompile(self._cur["start"])
        self.query_one(DisasmPane).show_decompile(code)

    async def _reshow_disasm(self) -> None:
        self.query_one("#disasm-header", Static).update(f"  DISASSEMBLY  ▸  [b]{self._cur['name']}[/]")
        self.query_one(DisasmPane).show_disasm(self._insns)

    # ── call chain ──
    def action_chain_func(self) -> None:
        if not self._cur:
            return
        self._spawn(self._show_chain())

    async def _show_chain(self) -> None:
        addr = self._cur["start"]
        callers = await self._b.xrefs_to(addr)
        callees = await self._b.xrefs_from(addr)
        pane = self.query_one(DisasmPane)
        pane.clear()
        self.query_one("#disasm-header", Static).update(f"  CALL CHAIN  ▸  [b]{self._cur['name']}[/]")
        pane.write(Text("  callers (who calls this):", Style(color="#8b5cf6", bold=True)))
        for c in callers or [{"name": "  (none)"}]:
            pane.write(Text(f"    ← {_xref_label(c)}", Style(color="#fbbf24")))
        pane.write(Text("  callees (what this calls):", Style(color="#8b5cf6", bold=True)))
        for c in callees or [{"name": "  (none)"}]:
            pane.write(Text(f"    → {_xref_label(c)}", Style(color="#00d4ff")))

    # ── AI naming ──
    def action_name_func(self) -> None:
        if not self._cur:
            self.notify("select a function first", severity="warning")
            return
        if self._busy:
            self.notify("still naming — wait a moment", severity="warning")
            return
        self._busy = True
        self._spawn(self._stream_name())

    async def _stream_name(self) -> None:
        try:
            hint = self.query_one("#model-hint", Static)
            spin = self.query_one("#model-spinner", Static)
            res  = self.query_one("#model-result", Static)
            rsn  = self.query_one("#model-reason", Static)
            hint.update("")
            spin.update("  ▸ thinking…")
            res.update("")
            rsn.update("")
            full = ""
            async for tok in self._b.stream_name(
                    self._cur["start"], self._insns, self._callees, self._callers):
                full += tok
                if "REASON:" in full:
                    name_part, _, reason_part = full.partition("REASON:")
                    res.update(
                        f"  ► [b green]{name_part.replace('NAME:', '').strip()}[/]")
                    rsn.update(f"\n  {reason_part.strip()}")
                elif "NAME:" in full:
                    res.update(
                        f"  ► [b green]{full.replace('NAME:', '').strip()}[/]")
            spin.update("")
            from spectrida.core.ollama import extract_name
            self._suggested = extract_name(full)
            if full and not self._suggested:
                res.update(f"  [dim]{full[:300]}[/]")
        except Exception as e:
            try:
                self.query_one("#model-spinner", Static).update("")
                self.query_one("#model-result", Static).update(
                    f"  [red]{voice.quip('error')}[/]  [dim]{e}[/]")
            except Exception:
                self.notify(str(e), severity="error")
        finally:
            self._busy = False

    # ── AI variable / parameter naming ──
    def action_name_vars(self) -> None:
        if not self._cur:
            self.notify("select a function first", severity="warning")
            return
        if self._busy:
            self.notify("still working — wait a moment", severity="warning")
            return
        self._busy = True
        self._spawn(self._name_vars())

    async def _name_vars(self) -> None:
        from spectrida.api import IDADatabase
        spin = self.query_one("#model-spinner", Static)
        res  = self.query_one("#model-result", Static)
        rsn  = self.query_one("#model-reason", Static)
        self.query_one("#model-hint", Static).update("")
        res.update("")
        rsn.update("")
        spin.update("  ▸ naming variables…")
        try:
            db = IDADatabase(self._b)
            result = await db.name_variables(self._cur["start"], rename=True)
            spin.update("")
            mapping = result.get("mapping", {})
            if not mapping:
                res.update("  [dim]no variables to name (needs Hex-Rays, or none found).[/]")
                return
            n = result.get("renamed", 0)
            t = result.get("retyped", 0)
            res.update(f"  [b green]{n}[/] renamed · [b magenta]{t}[/] typed")
            rsn.update("\n  " + "  ".join(_var_change(k, v) for k, v in mapping.items()))
            # auto-show the updated pseudocode
            code = result.get("pseudocode", "")
            if code:
                self._decompiled = True
                self.query_one("#disasm-header", Static).update(
                    f"  PSEUDOCODE  ▸  [b]{self._cur['name']}[/]")
                self.query_one(DisasmPane).show_decompile(code)
        except Exception as e:
            spin.update("")
            res.update(f"  [red]{voice.quip('error')}[/]  [dim]{e}[/]")
        finally:
            self._busy = False

    # ── rename ──
    def action_rename_func(self) -> None:
        if not self._cur:
            return
        self.app.push_screen(
            RenameDialog(self._cur["name"], self._suggested),
            self._after_rename,
        )

    def _after_rename(self, new_name: str | None) -> None:
        if new_name and self._cur:
            self._spawn(self._do_rename(new_name))

    async def _do_rename(self, new_name: str) -> None:
        ok = await self._b.rename(self._cur["start"], new_name)
        if ok:
            self._cur["name"] = new_name       # same dict FuncList holds → mutates in place
            self.query_one("#func-list", FuncList).refresh()
            self._refresh_func_count()
            self.query_one("#disasm-header", Static).update(
                f"  DISASSEMBLY  ▸  [b]{new_name}[/]  [dim]{self._cur['start']:#x}[/]")

    # ── batch naming ──
    def action_batch_name(self) -> None:
        if self._busy:
            return
        self._spawn(self._batch())

    async def _batch(self) -> None:
        self._busy = True
        fl = self.query_one("#func-list", FuncList)
        targets = [f for f in fl._items if is_sub(f["name"])][:25]
        res = self.query_one("#model-result", Static)
        rsn = self.query_one("#model-reason", Static)
        self.query_one("#model-hint", Static).update("")
        try:
            from spectrida.api import IDADatabase
            from spectrida.config import batch_concurrency
            db = IDADatabase(self._b)
            bar = self.query_one(StatusBar)
            by_addr = {f["start"]: f for f in fl._all}
            total = len(targets)
            conc = batch_concurrency()
            state = {"done": 0, "vars": 0, "typed": 0}
            sem = asyncio.Semaphore(conc)
            tag = f"  ×{conc}" if conc > 1 else ""
            self.query_one("#model-spinner", Static).update(f"  ▸ batch{tag or ' '}running…")
            bar.set_progress(0, total, "")

            async def _name_one(f: dict) -> None:
                async with sem:                       # cap parallel LLM calls
                    r = await db.name_all(f["start"], rename=True)
                name = r.get("new_name")
                tgt = by_addr.get(r["address"], f)
                if name:
                    tgt["name"] = name                # same dict FuncList holds → mutates in place
                    fl.refresh()                      # repaint the list immediately
                    self._refresh_func_count()
                state["vars"] += r.get("renamed_vars", 0)
                state["typed"] += r.get("retyped_vars", 0)
                state["done"] += 1
                bar.set_progress(state["done"], total, name or tgt["name"])
                res.update(f"  [green]{state['done']}/{total}[/] named · "
                           f"[cyan]{state['vars']}[/] vars · [magenta]{state['typed']}[/] typed{tag}")

            await asyncio.gather(*(_name_one(f) for f in targets))

            self.query_one("#model-spinner", Static).update("")
            rsn.update(f"\n  {voice.quip('naming_done')}")
            fl.refresh()
            self._refresh_func_count()
            bar.clear_progress()
            bar.set_info(f"{self._b.title} · batch done — {state['done']} named, "
                         f"{state['vars']} vars, {state['typed']} typed")
        finally:
            self._busy = False
            try:
                self.query_one(StatusBar).clear_progress()
            except Exception:
                pass

    def _refresh_func_count(self) -> None:
        """Recompute the named/total tally from the live FuncList items."""
        fl = self.query_one("#func-list", FuncList)
        funcs = fl._all
        named = sum(1 for f in funcs if not is_sub(f["name"]))
        self.query_one("#func-count", Label).update(f"  {len(funcs):,} funcs · {named:,} named")

    # ── deep branch naming (bottom-up call tree from current function) ──
    def action_deep_branch(self) -> None:
        if not self._cur:
            self.notify("select a function first", severity="warning")
            return
        if self._busy:
            self.notify("still working — wait a moment", severity="warning")
            return
        self._busy = True
        self._spawn(self._deep_branch())

    async def _deep_branch(self) -> None:
        fl = self.query_one("#func-list", FuncList)
        by_addr = {f["start"]: f for f in fl._all}
        res = self.query_one("#model-result", Static)
        rsn = self.query_one("#model-reason", Static)
        bar = self.query_one(StatusBar)
        self.query_one("#model-hint", Static).update("")
        spin = self.query_one("#model-spinner", Static)
        spin.update("  ▸ mapping call branch…")
        try:
            from spectrida.api import IDADatabase
            db = IDADatabase(self._b)
            root = self._cur["start"]
            state = {"vars": 0, "typed": 0}

            async def cb(done: int, total: int, r: dict) -> None:
                name = r.get("new_name")
                tgt = by_addr.get(r["address"])
                if name and tgt:
                    tgt["name"] = name
                    fl.refresh()
                    self._refresh_func_count()
                state["vars"] += r.get("renamed_vars", 0)
                state["typed"] += r.get("retyped_vars", 0)
                bar.set_progress(done, total, name or "")
                spin.update(f"  ▸ deep {done}/{total} (bottom-up)")
                res.update(f"  [green]{done}/{total}[/] named · "
                           f"[cyan]{state['vars']}[/] vars · [magenta]{state['typed']}[/] typed")

            results = await db.name_branch(root, rename=True, progress_cb=cb)
            spin.update("")
            if not results:
                res.update("  [dim]nothing to name in this branch (all named already).[/]")
            else:
                rsn.update(f"\n  branch done — {len(results)} functions, "
                           f"{state['vars']} vars, {state['typed']} typed  ·  {voice.quip('naming_done')}")
            fl.refresh()
            self._refresh_func_count()
            bar.clear_progress()
            bar.set_info(f"{self._b.title} · deep branch — {len(results)} named, "
                         f"{state['vars']} vars, {state['typed']} typed")
        except Exception as e:
            spin.update("")
            res.update(f"  [red]{voice.quip('error')}[/]  [dim]{e}[/]")
        finally:
            self._busy = False
            try:
                self.query_one(StatusBar).clear_progress()
            except Exception:
                pass

    async def _do_overview(self) -> None:
        from spectrida.api import IDADatabase
        screen = OverviewScreen("  asking the ghost…")
        self.app.push_screen(screen)
        try:
            db = IDADatabase(self._b)
            full = ""
            it = await db.overview(stream=True)
            async for tok in it:
                full += tok
                screen.update(full)
        except Exception as e:
            screen.update(f"  [red]overview failed:[/] {e}")

    def action_overview(self) -> None:
        self._spawn(self._do_overview())

    def action_help(self) -> None:
        self.app.push_screen(HelpScreen())

    def _clear_model(self) -> None:
        self.query_one("#model-spinner", Static).update("")
        self.query_one("#model-result", Static).update("")
        self.query_one("#model-reason", Static).update("")
        self.query_one("#model-hint", Static).update("Press [b cyan]N[/] to name this function · [b cyan]V[/] for its variables.")
