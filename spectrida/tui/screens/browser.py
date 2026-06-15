"""The function browser — search, disasm/decompile, AI naming, call-chain, rename, batch."""
from __future__ import annotations

import asyncio
import re
from typing import ClassVar

from rich.style import Style
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Input, Label, Static

from spectrida import voice
from spectrida.core.backend import Backend
from spectrida.tui.screens.dialogs import (
    HelpScreen,
    MinXrefsDialog,
    OverviewScreen,
    RenameDialog,
)
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


_ARG_RE = re.compile(r"^(a\d+|this|arg\d*)$", re.IGNORECASE)


def _fmt_dropped(dropped: list[dict]) -> str:
    """Render dropped (unapplied) types for the reason pane: var:type (reason)."""
    if not dropped:
        return ""
    bits = []
    for d in dropped[:8]:
        bits.append(f"[red]{d.get('var','?')}[/]:[magenta]{d.get('type','')}[/] "
                    f"[dim]({d.get('reason','')})[/]")
    more = f"  [dim]+{len(dropped) - 8} more[/]" if len(dropped) > 8 else ""
    return "  ⚠ dropped: " + "  ".join(bits) + more


def _render_deep_tree(
    items: list[dict],
    current_idx: int,
    done_count: int,
    max_rows: int = 26,
    summary: str = "",
) -> str:
    """Render the deep-branch progress tree as Rich markup for a Static widget.

    Each row shows: indicator · function-name · N P T V checkboxes.
    N=name renamed, P=params renamed, T=types/ret applied, V=locals renamed.
    A sliding window keeps the current function visible.
    """
    total = len(items)
    if not total:
        return ""

    focus = max(0, min(current_idx, total - 1))
    half = max_rows // 2
    start = max(0, focus - half + 2)
    end = min(total, start + max_rows)
    start = max(0, end - max_rows)

    header = (
        f"  [bold]deep branch[/] [dim]{done_count}/{total}[/]"
        "   [dim]N[/]=name  [dim]P[/]=params  [dim]T[/]=types  [dim]V[/]=vars"
    )
    lines = [header, ""]

    if start > 0:
        lines.append(f"  [dim]  ↑ {start} more[/]")

    def _chk(val: bool | None) -> str:
        if val is None:
            return "[dim]·[/]"
        return "[green]✓[/]" if val else "[dim]–[/]"

    for i in range(start, end):
        item = items[i]
        status = item["status"]
        is_cur = (i == current_idx)

        if is_cur:
            prefix = "[bold yellow]▶[/]"
        elif status == "done":
            prefix = "[green]✓[/]" if item.get("N") else "[dim]–[/]"
        else:
            prefix = " "

        new_name = item.get("new_name") or ""
        old_name = item.get("old_name") or hex(item["addr"])
        display_text = (new_name if (new_name and status == "done") else old_name)[:24]
        pad = " " * max(0, 25 - len(display_text))

        if new_name and status == "done":
            name_markup = f"[green]{display_text}[/]"
        elif is_cur:
            name_markup = f"[bold]{display_text}[/]"
        elif status == "pending":
            name_markup = f"[dim]{display_text}[/]"
        else:
            name_markup = f"[dim]{display_text}[/]"

        if status == "pending" and not is_cur:
            chks = "[dim]· · · ·[/]"
        else:
            chks = (
                f"{_chk(item.get('N'))}[dim]N[/] "
                f"{_chk(item.get('P'))}[dim]P[/] "
                f"{_chk(item.get('T'))}[dim]T[/] "
                f"{_chk(item.get('V'))}[dim]V[/]"
            )

        lines.append(f"  {prefix} {name_markup}{pad} {chks}")

    if end < total:
        lines.append(f"  [dim]  ↓ {total - end} more[/]")

    if summary:
        lines += ["", f"  [dim]{summary}[/]"]

    return "\n".join(lines)


class BrowserScreen(Screen):
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("n", "name_func", "Name"),
        Binding("v", "name_vars", "Vars"),
        Binding("r", "rename_func", "Rename"),
        Binding("d", "decompile_func", "Decompile"),
        Binding("c", "chain_func", "Chain"),
        Binding("b", "batch_name", "Batch-all"),
        Binding("u", "unnamed_branches", "Unnamed"),
        Binding("t", "deep_branch", "Deep"),
        Binding("f", "recover_structs", "Structs"),
        Binding("g", "name_globals", "Globals"),
        Binding("l", "canonicalize", "Lint"),
        Binding("a", "audit", "Audit"),
        Binding("o", "overview", "Overview"),
        Binding("bracketright", "scroll_report_down", "Report▼", show=False),
        Binding("bracketleft", "scroll_report_up", "Report▲", show=False),
        Binding("slash", "focus_search", "Search"),
        Binding("i", "lumina_info", "Lumina"),
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
        self._db = None   # one long-lived IDADatabase → shared name cache + glossary

    def _database(self):
        """Return the screen's single IDADatabase, created on first use.

        Sharing one instance across every action means the content-addressed name
        cache and the project glossary accumulate over the whole session (a `B`
        sweep warms the cache that `G`/`T`/`V` then reuse) instead of each action
        starting cold with a throwaway instance.
        """
        if self._db is None:
            from spectrida.api import IDADatabase
            self._db = IDADatabase(self._b)
        return self._db

    def _flush_cache(self) -> None:
        """Persist newly-cached names to disk after an action (the TUI never
        close()s the long-lived db, so we flush explicitly)."""
        if self._db is not None:
            self._db.save_cache()

    def on_unmount(self) -> None:
        # final flush when leaving the browser (covers entries below the periodic
        # maybe_save threshold)
        self._flush_cache()

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
                with VerticalScroll(id="model-pane"):
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
        try:
            entry = await self._b.get_entry_point()
            if entry is not None:
                fl.seek(entry)
        except Exception:
            pass
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
            from spectrida.core.llamacpp import extract_name, strip_think
            full = ""
            async for tok in self._b.stream_name(
                    self._cur["start"], self._insns, self._callees, self._callers):
                full += tok
                shown = strip_think(full)        # never render a raw/truncated <think>
                if "REASON:" in shown:
                    name_part, _, reason_part = shown.partition("REASON:")
                    res.update(
                        f"  ► [b green]{name_part.replace('NAME:', '').strip()}[/]")
                    rsn.update(f"\n  {reason_part.strip()}")
                elif "NAME:" in shown:
                    res.update(
                        f"  ► [b green]{shown.replace('NAME:', '').strip()}[/]")
                elif not shown:
                    spin.update("  ▸ thinking…")   # still inside <think>, no answer yet
            spin.update("")
            self._suggested = extract_name(full)
            if full and not self._suggested:
                shown = strip_think(full)
                res.update(f"  [dim]{shown[:300] or '(model produced only reasoning — try again or raise SPECTRIDA_LLAMACPP_MAX_TOKENS)'}[/]")
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
        spin = self.query_one("#model-spinner", Static)
        res  = self.query_one("#model-result", Static)
        rsn  = self.query_one("#model-reason", Static)
        self.query_one("#model-hint", Static).update("")
        res.update("")
        rsn.update("")
        spin.update("  ▸ staged: name → params → locals + return…")
        try:
            db = self._database()
            # staged conversation for context, but DON'T commit the function rename
            result = await db.name_all(self._cur["start"], rename=True, rename_function=False)
            spin.update("")
            mapping = result.get("variables", {})
            n = result.get("renamed_vars", 0)
            t = result.get("retyped_vars", 0)
            ret = result.get("ret_type", "")
            dropped = result.get("dropped", [])
            if not mapping and not ret:
                res.update("  [dim]no variables to name (needs Hex-Rays, or none found).[/]")
                return
            ret_part = f" · ret [b magenta]{ret}[/]" if ret else ""
            drop_part = f" · [b red]{len(dropped)}[/] dropped" if dropped else ""
            res.update(f"  [b green]{n}[/] renamed · [b magenta]{t}[/] typed{ret_part}{drop_part}")
            reason_lines = "\n  " + "  ".join(_var_change(k, v) for k, v in mapping.items())
            if dropped:
                reason_lines += "\n" + _fmt_dropped(dropped)
            rsn.update(reason_lines)
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
            self._flush_cache()

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
        # route through the shared db so its cached function list (used for
        # old-name lookups / glossary seeding) stays in sync with manual renames
        result = await self._database().rename(self._cur["start"], new_name)
        actual = result if isinstance(result, str) else (new_name if result else "")
        if actual:
            self._cur["name"] = actual   # same dict FuncList holds → mutates in place
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
        """Whole-binary sweep: deep-name every call branch bottom-up (leaves→roots).
        Already-named functions are re-entered for variable / return typing, then a
        refine pass re-names low-confidence guesses with full-binary context."""
        await self._run_sweep(
            scope="all", revisit_named=True, refine=True,
            mapping_msg="  ▸ mapping whole binary…", label="whole binary")

    async def _run_sweep(self, *, scope: str, revisit_named: bool,
                         mapping_msg: str, label: str, refine: bool = False) -> None:
        """Drive batch_name_branches over the deep-branch tree UI (reset per branch).

        Shared by the whole-binary batch ('B') and find-unnamed-branches ('U')."""
        self._busy = True
        fl = self.query_one("#func-list", FuncList)
        by_addr = {f["start"]: f for f in fl._all}
        res = self.query_one("#model-result", Static)
        rsn = self.query_one("#model-reason", Static)
        bar = self.query_one(StatusBar)
        spin = self.query_one("#model-spinner", Static)
        self.query_one("#model-hint", Static).update("")
        spin.update(mapping_msg)
        try:
            db = self._database()
            state = {"named": 0, "skipped": 0, "vars": 0, "typed": 0, "dropped": 0}
            tree: list[dict] = []
            cur_idx = [0]
            branch_label = [""]   # spinner prefix, updated per branch

            plan_cb, cb = self._make_deep_callbacks(
                fl=fl, by_addr=by_addr, state=state, tree=tree,
                cur_idx=cur_idx, label=branch_label)

            async def branch_cb(idx: int, root_name: str, root_addr: int) -> None:
                branch_label[0] = f"branch {idx} · {root_name[:20]} · "

            totals = await db.batch_name_branches(
                scope=scope, rename=True, revisit_named=revisit_named, refine=refine,
                branch_cb=branch_cb, plan_cb=plan_cb, progress_cb=cb)

            spin.update("")
            drop = f", {totals['dropped']} dropped" if totals.get("dropped") else ""
            ref  = f", {totals['refined']} refined" if totals.get("refined") else ""
            prop = f", {totals['propagated']} propagated" if totals.get("propagated") else ""
            if not totals["functions"]:
                rsn.update("")
                res.update(f"  [dim]nothing to do — no {label} branches found.[/]")
            else:
                summary = (f"{label} — {totals['branches']} branches, "
                           f"{totals['named']} named, {totals['vars']} vars, "
                           f"{totals['typed']} typed{drop}{ref}{prop}  ·  {voice.quip('naming_done')}")
                rsn.update(_render_deep_tree(tree, len(tree), len(tree), summary=summary))
            fl.refresh()
            self._refresh_func_count()
            bar.clear_progress()
            bar.set_info(f"{self._b.title} · {label} — {totals['named']} named, "
                         f"{totals['vars']} vars, {totals['typed']} typed{drop}{ref}{prop}")
        except Exception as e:
            spin.update("")
            res.update(f"  [red]{voice.quip('error')}[/]  [dim]{e}[/]")
        finally:
            self._busy = False
            self._flush_cache()
            try:
                self.query_one(StatusBar).clear_progress()
            except Exception:
                pass

    # ── find unnamed branches (deep-name every sub_* branch) ──
    def action_unnamed_branches(self) -> None:
        if self._busy:
            self.notify("still working — wait a moment", severity="warning")
            return
        self._spawn(self._unnamed_branches())

    async def _unnamed_branches(self) -> None:
        """Find every sub_* function's branch and deep-name it (bottom-up)."""
        await self._run_sweep(
            scope="unnamed", revisit_named=False,
            mapping_msg="  ▸ finding unnamed branches…", label="unnamed branches")

    def _make_deep_callbacks(self, *, fl, by_addr, state, tree, cur_idx, label):
        """Build (plan_cb, progress_cb) that drive the deep-branch tree widget.

        Shared by the single-branch deep-name ('T') and the whole-binary batch
        ('B'). *tree* is reset per branch via plan_cb; *state* accumulates
        named/vars/typed across however many branches run; *label[0]* is a spinner
        prefix (e.g. "branch 3 · root · ") set by the caller's branch_cb.
        """
        res  = self.query_one("#model-result", Static)
        rsn  = self.query_one("#model-reason", Static)
        bar  = self.query_one(StatusBar)
        spin = self.query_one("#model-spinner", Static)

        async def plan_cb(targets_info: list[tuple[int, str]]) -> None:
            tree[:] = [
                {
                    "addr": addr, "old_name": name, "new_name": "",
                    "status": "running" if i == 0 else "pending",
                    "N": None, "P": None, "T": None, "V": None,
                }
                for i, (addr, name) in enumerate(targets_info)
            ]
            cur_idx[0] = 0
            spin.update(f"  ▸ {label[0]}deep 0/{len(tree)}")
            rsn.update(_render_deep_tree(tree, 0, 0))

        async def cb(done: int, total: int, r: dict) -> None:
            idx = done - 1
            if 0 <= idx < len(tree):
                item = tree[idx]
                item["status"] = "done"
                item["new_name"] = r.get("new_name") or ""
                variables = r.get("variables") or {}
                args = {k: v for k, v in variables.items() if _ARG_RE.match(k)}
                locs = {k: v for k, v in variables.items() if k not in args}
                item["N"] = bool(r.get("new_name"))
                item["P"] = bool(args)
                item["T"] = bool(r.get("ret_type")) or r.get("retyped_vars", 0) > 0
                item["V"] = bool(locs) or r.get("renamed_vars", 0) > 0

            cur_idx[0] = done
            if done < len(tree):
                tree[done]["status"] = "running"

            name = r.get("new_name")
            # only sub_* functions are actually renamed; revisited named funcs keep
            # their name (we just applied variable / return typing to them)
            renamed = name and r.get("old_name", "").lower().startswith("sub_")
            tgt = by_addr.get(r["address"])
            if renamed:
                state["named"] += 1
                if tgt:
                    tgt["name"] = name
                    fl.refresh()
                    self._refresh_func_count()
            elif not name:
                state["skipped"] += 1
            state["vars"]  += r.get("renamed_vars", 0)
            state["typed"] += r.get("retyped_vars", 0)
            state["dropped"] = state.get("dropped", 0) + len(r.get("dropped") or [])
            bar.set_progress(done, total, name or "(no name)")
            spin.update(f"  ▸ {label[0]}deep {done}/{total}")
            drop_part = f" · [red]{state['dropped']}[/] dropped" if state.get("dropped") else ""
            res.update(f"  [green]{state['named']}[/] named · "
                       f"[cyan]{state['vars']}[/] vars · [magenta]{state['typed']}[/] typed{drop_part}")
            rsn.update(_render_deep_tree(tree, cur_idx[0], done))

        return plan_cb, cb

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
            db = self._database()
            root = self._cur["start"]
            state = {"named": 0, "skipped": 0, "vars": 0, "typed": 0, "dropped": 0}

            # Tree state: list of per-function dicts, populated by plan_cb before naming starts.
            tree: list[dict] = []
            cur_idx = [0]  # mutable ref so closures can update it
            label = [""]
            plan_cb, cb = self._make_deep_callbacks(
                fl=fl, by_addr=by_addr, state=state, tree=tree, cur_idx=cur_idx, label=label)

            results = await db.name_branch(
                root, rename=True, revisit_named=True, progress_cb=cb, plan_cb=plan_cb)
            spin.update("")
            if not results:
                rsn.update("")
                res.update("  [dim]nothing to name in this branch (all named already).[/]")
            else:
                skip = f", {state['skipped']} skipped" if state["skipped"] else ""
                drop = f", {state['dropped']} dropped" if state.get("dropped") else ""
                summary = (f"branch done — {state['named']}/{len(results)} named{skip}, "
                           f"{state['vars']} vars, {state['typed']} typed{drop}"
                           f"  ·  {voice.quip('naming_done')}")
                rsn.update(_render_deep_tree(tree, len(tree), len(tree), summary=summary))
            fl.refresh()
            self._refresh_func_count()
            if self._cur:
                self._decompiled = False
                await self._load_disasm()
            bar.clear_progress()
            bar.set_info(f"{self._b.title} · deep branch — {state['named']} named, "
                         f"{state['vars']} vars, {state['typed']} typed")
        except Exception as e:
            spin.update("")
            res.update(f"  [red]{voice.quip('error')}[/]  [dim]{e}[/]")
        finally:
            self._busy = False
            self._flush_cache()
            try:
                self.query_one(StatusBar).clear_progress()
            except Exception:
                pass

    # ── struct recovery (recover structs from field-access patterns) ──
    def action_recover_structs(self) -> None:
        if self._busy:
            self.notify("still working — wait a moment", severity="warning")
            return
        self._spawn(self._recover_structs())

    async def _recover_structs(self) -> None:
        """Recover C structs for generic pointer parameters across the binary and
        apply them. Best run after the whole-binary naming sweep ('B')."""
        self._busy = True
        res  = self.query_one("#model-result", Static)
        rsn  = self.query_one("#model-reason", Static)
        bar  = self.query_one(StatusBar)
        spin = self.query_one("#model-spinner", Static)
        self.query_one("#model-hint", Static).update("")
        rsn.update("")
        spin.update("  ▸ scanning functions for recoverable structs…")
        log: list[str] = []
        try:
            db = self._database()

            async def progress_cb(done: int, total: int, info: dict) -> None:
                fn = (info.get("func") or "")[:26]
                bar.set_progress(done, total, fn)
                spin.update(f"  ▸ structs {done}/{total} · scanning {fn}…")
                changed = False
                for it in info.get("items", []):
                    r = it["result"]; arg = it["arg"]
                    if r.get("ok"):
                        if r.get("new_struct"):
                            tag, col = "new", "green"
                        elif r.get("grew"):
                            tag, col = f"+{r.get('added', 0)} merged", "green"
                        elif r.get("reused"):
                            tag, col = "reused", "cyan"
                        else:
                            tag, col = "applied", "yellow"
                        drop = (f" [red]+{len(r['dropped'])} dropped[/]"
                                if r.get("dropped") else "")
                        # r['fields'] is now the struct's TOTAL field count
                        log.append(f"  [dim]{fn}[/] a{arg} → [b {col}]{r['struct']}[/] "
                                   f"[dim]({r['fields']}f, {tag})[/]{drop}")
                        changed = True
                    elif r.get("fields"):   # had field evidence but didn't make a struct
                        log.append(f"  [dim]{fn} a{arg}: {r['fields']}f — "
                                   f"{r.get('reason', 'skipped')}[/]")
                        changed = True
                if changed:
                    rsn.update("\n".join(log[-40:]))

            totals = await db.recover_structs(scope="named", progress_cb=progress_cb)
            spin.update("")
            drop = f", {totals['dropped']} dropped" if totals.get("dropped") else ""
            merged = f", {totals['merged']} merged" if totals.get("merged") else ""
            if not totals["structs"]:
                res.update("  [dim]no recoverable structs — run naming ('B') first, "
                           "or no generic pointer params with field accesses.[/]")
                if not log:
                    rsn.update("  [dim]scanned every named function · "
                               "no generic pointer params dereferenced at ≥2 offsets.[/]")
            else:
                res.update(f"  [b cyan]{totals['structs']}[/] structs · "
                           f"[b green]{totals['applied']}[/] applied · "
                           f"[magenta]{totals['fields']}[/] fields added{merged}{drop}  ·  "
                           f"{voice.quip('naming_done')}")
            bar.set_info(f"{self._b.title} · structs — {totals['structs']} recovered, "
                         f"{totals['applied']} applied{merged}{drop}")
        except Exception as e:
            spin.update("")
            res.update(f"  [red]{voice.quip('error')}[/]  [dim]{e}[/]")
        finally:
            self._busy = False
            self._flush_cache()
            try:
                self.query_one(StatusBar).clear_progress()
            except Exception:
                pass

    # ── global naming (name + type generic globals from their use sites) ──
    def action_name_globals(self) -> None:
        if self._busy:
            self.notify("still working — wait a moment", severity="warning")
            return
        # ask for the minimum xref count first (more xrefs = higher-leverage globals)
        self.app.push_screen(MinXrefsDialog(default=3), self._after_minxrefs)

    def _after_minxrefs(self, min_xrefs: int | None) -> None:
        if min_xrefs is None:        # cancelled
            return
        self._spawn(self._name_globals(min_xrefs))

    async def _name_globals(self, min_xrefs: int = 3) -> None:
        """Name + type generic globals (dword_*, byte_*, …) from their best-
        understood referencing functions. Best run after the 'B' naming sweep."""
        self._busy = True
        res  = self.query_one("#model-result", Static)
        rsn  = self.query_one("#model-reason", Static)
        bar  = self.query_one(StatusBar)
        spin = self.query_one("#model-spinner", Static)
        self.query_one("#model-hint", Static).update("")
        rsn.update("")
        spin.update(f"  ▸ enumerating generic globals (≥{min_xrefs} xrefs)…")
        log: list[str] = []
        try:
            db = self._database()

            async def progress_cb(done: int, total: int, info: dict) -> None:
                phase = info.get("phase")
                if phase == "enumerated":
                    spin.update(f"  ▸ found {total} global(s) ≥{min_xrefs} xrefs — "
                                f"analysing use sites…")
                    rsn.update(f"  [dim]{total} candidate global(s); reading the "
                               f"best-understood functions that touch each…[/]")
                    return
                if phase == "analyze":
                    nm = (info.get("name") or "")[:28]
                    spin.update(f"  ▸ globals {done}/{total} · {nm} "
                                f"({info.get('nxrefs', 0)} xrefs)…")
                    return
                bar.set_progress(done, total, info.get("name", ""))
                if phase == "skip":
                    log.append(f"  [dim]{(info.get('name') or '')[:28]} — skipped "
                               f"({info.get('reason', '')})[/]")
                else:  # done
                    ty = info.get("type", "")
                    tpart = f" : [magenta]{ty}[/]" if ty else ""
                    drop = (f" · [red]{len(info['dropped'])} dropped[/]"
                            if info.get("dropped") else "")
                    cache = " [dim cyan](cache)[/]" if info.get("source") == "cache" else ""
                    log.append(f"  [dim]{info.get('old_name', '')}[/] → "
                               f"[b green]{info.get('name', '')}[/]{tpart} "
                               f"[dim]({info.get('nxrefs', 0)} xrefs, "
                               f"{info.get('sites', 0)} sites)[/]{cache}{drop}")
                rsn.update("\n".join(log[-40:]))

            totals = await db.name_globals(min_xrefs=min_xrefs, progress_cb=progress_cb)
            spin.update("")
            drop = f", {totals['dropped']} dropped" if totals.get("dropped") else ""
            if not totals["globals"]:
                res.update(f"  [dim]no globals named — none have ≥{min_xrefs} xrefs, "
                           f"or run naming ('B') first for better context.[/]")
            else:
                res.update(f"  [b cyan]{totals['globals']}[/] globals · "
                           f"[b green]{totals['named']}[/] named · "
                           f"[magenta]{totals['typed']}[/] typed{drop}  ·  "
                           f"{voice.quip('naming_done')}")
            bar.set_info(f"{self._b.title} · globals — {totals['named']} named, "
                         f"{totals['typed']} typed{drop}")
        except Exception as e:
            spin.update("")
            res.update(f"  [red]{voice.quip('error')}[/]  [dim]{e}[/]")
        finally:
            self._busy = False
            self._flush_cache()
            try:
                self.query_one(StatusBar).clear_progress()
            except Exception:
                pass

    # ── audit log (show the project change journal + export a revert script) ──
    def action_audit(self) -> None:
        self._spawn(self._show_audit())

    async def _show_audit(self) -> None:
        res = self.query_one("#model-result", Static)
        rsn = self.query_one("#model-reason", Static)
        self.query_one("#model-hint", Static).update("")
        self.query_one("#model-spinner", Static).update("")
        audit = self._database().audit
        n = len(audit)
        if not n:
            res.update("  [dim]no changes recorded yet — name something first.[/]")
            rsn.update("")
            return
        counts = audit.counts()
        summary = " · ".join(f"{k} {v}" for k, v in sorted(counts.items()))
        res.update(f"  [b cyan]{n}[/] changes recorded  ·  [dim]{summary}[/]")
        body = audit.render(400)
        # always export a fresh rollback script alongside the .i64
        i64 = getattr(self._b, "i64", None)
        if i64:
            rp = str(i64) + ".spectrida-revert.py"
            try:
                audit.export_revert(rp)
                body += (f"\n\n  [dim]journal:[/] {i64}.spectrida-audit.jsonl"
                         f"\n  [dim]revert script:[/] {rp}")
            except Exception:
                pass
        rsn.update(body)

    # ── name canonicalisation linter (unify naming across the binary) ──
    def action_canonicalize(self) -> None:
        if self._busy:
            self.notify("still working — wait a moment", severity="warning")
            return
        self._spawn(self._canonicalize())

    async def _canonicalize(self) -> None:
        """Unify function names across the binary (token/typo canonicalisation)."""
        self._busy = True
        fl   = self.query_one("#func-list", FuncList)
        by_addr = {f["start"]: f for f in fl._all}
        res  = self.query_one("#model-result", Static)
        rsn  = self.query_one("#model-reason", Static)
        bar  = self.query_one(StatusBar)
        spin = self.query_one("#model-spinner", Static)
        self.query_one("#model-hint", Static).update("")
        rsn.update("")
        spin.update("  ▸ linting names for consistency…")
        log: list[str] = []
        try:
            db = self._database()

            async def progress_cb(done: int, total: int, info: dict) -> None:
                bar.set_progress(done, total, info.get("suggested") or info["current"])
                if info["reason"] == "normalize":
                    arrow = "✓" if info.get("applied") else "·"
                    log.append(f"  [dim]{info['current']}[/] → "
                               f"[b green]{info['suggested']}[/] [dim]{arrow}[/]")
                    # keep the live list in sync when a rename actually happened
                    if info.get("applied"):
                        tgt = by_addr.get(info["addr"])
                        if tgt:
                            tgt["name"] = info["suggested"]
                elif info["reason"] == "generic":
                    log.append(f"  [yellow]{info['current']}[/] "
                               f"[dim]— generic, rename by hand[/]")
                spin.update(f"  ▸ lint {done}/{total} · {len(log)} flagged")
                rsn.update("\n".join(log[-40:]))

            totals = await db.canonicalize_names(progress_cb=progress_cb)
            spin.update("")
            gen = f", {totals['generic']} generic" if totals.get("generic") else ""
            if not totals["flagged"] and not totals["generic"]:
                res.update(f"  [dim]names already consistent — "
                           f"{totals['checked']} checked, nothing to unify.[/]")
            else:
                res.update(f"  [b cyan]{totals['checked']}[/] checked · "
                           f"[b green]{totals['renamed']}[/] unified · "
                           f"[yellow]{totals['flagged']}[/] flagged{gen}  ·  "
                           f"{voice.quip('naming_done')}")
            fl.refresh()
            self._refresh_func_count()
            bar.set_info(f"{self._b.title} · lint — {totals['renamed']} unified, "
                         f"{totals['flagged']} flagged{gen}")
        except Exception as e:
            spin.update("")
            res.update(f"  [red]{voice.quip('error')}[/]  [dim]{e}[/]")
        finally:
            self._busy = False
            self._flush_cache()
            try:
                self.query_one(StatusBar).clear_progress()
            except Exception:
                pass

    async def _do_overview(self) -> None:
        screen = OverviewScreen("  asking the ghost…")
        self.app.push_screen(screen)
        try:
            db = self._database()
            full = ""
            it = await db.overview(stream=True)
            async for tok in it:
                full += tok
                screen.update(full)
        except Exception as e:
            screen.update(f"  [red]overview failed:[/] {e}")

    def action_overview(self) -> None:
        self._spawn(self._do_overview())

    # ── scroll the report pane (also scrollable by mouse wheel) ──
    def action_scroll_report_down(self) -> None:
        try:
            self.query_one("#model-pane", VerticalScroll).scroll_page_down(animate=False)
        except Exception:
            pass

    def action_scroll_report_up(self) -> None:
        try:
            self.query_one("#model-pane", VerticalScroll).scroll_page_up(animate=False)
        except Exception:
            pass

    def action_lumina_info(self) -> None:
        self._spawn(self._show_lumina_info())

    async def _show_lumina_info(self) -> None:
        import json as _json
        members = await self._b.lumina_probe()
        res = self.query_one("#model-result", Static)
        self.query_one("#model-spinner", Static).update("")
        self.query_one("#model-reason", Static).update("")
        if members is None:
            res.update("[red]ida_lumina[/] not available")
        elif isinstance(members, dict):
            res.update(_json.dumps(members, indent=2, ensure_ascii=False))
        else:
            lines = "\n".join(f"  {m}" for m in sorted(members))
            res.update(f"[bold]ida_lumina[/] ({len(members)} members):\n{lines}")

    def action_help(self) -> None:
        self.app.push_screen(HelpScreen())

    def _clear_model(self) -> None:
        self.query_one("#model-spinner", Static).update("")
        self.query_one("#model-result", Static).update("")
        self.query_one("#model-reason", Static).update("")
        self.query_one("#model-hint", Static).update("Press [b cyan]N[/] to name this function · [b cyan]V[/] for its variables.")
