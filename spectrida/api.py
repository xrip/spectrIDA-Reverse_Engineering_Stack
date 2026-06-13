"""spectrIDA programmatic API — use spectrIDA from scripts, notebooks, or Claude Code
without launching the TUI.

    import asyncio
    from spectrida.api import open_i64

    async def main():
        async with open_i64("path/to/file.i64") as db:
            funcs = await db.list_functions()
            name  = await db.name_function(funcs[0]["start"])
            print(name)

    asyncio.run(main())
"""
from __future__ import annotations

import asyncio
import json
import random
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TypedDict

from spectrida.core.backend import DemoBackend, RealBackend
from spectrida.core.llamacpp import (
    extract_name,
    llamacpp_stream_text,
    name_function,
    stream_name,
)


# ── public types ────────────────────────────────────────────────────────────

class FunctionInfo(TypedDict):
    name:  str
    start: int
    end:   int
    size:  int


class NameResult(TypedDict):
    address:    int
    old_name:   str
    new_name:   str
    reasoning:  str
    confidence: str   # "high" | "medium" | "low"


class OverviewResult(TypedDict):
    summary:    str
    subsystems: list[str]
    notes:      str


# ── funny loading lines (opt-in) ─────────────────────────────────────────────

_LOADING = [
    "bribing idalib with coffee…",
    "deciphering ancient x86 scrolls…",
    "asking the ghost nicely…",
    "warming up the neurons (literally, the GPU is hot)…",
    "counting push/pop pairs for fun…",
    "pretending to understand the calling convention…",
    "loading 150k functions. send help.",
    "this is fine. everything is fine.",
    "reverse engineering the reverse engineering tool…",
    "the compiler threw away all the names. rude.",
    "idalib is doing its thing. probably.",
    "sub_XXXXXX → something meaningful, maybe…",
]

def loading_line() -> str:
    return random.choice(_LOADING)


def _fmt_xref(x: dict) -> str:
    """Best label for a call-chain neighbour: full signature if the function has a
    known type (gives the model params + return type), else its name, else addr."""
    return x.get("proto") or x.get("name") or x.get("address", "")


def _has_pseudocode(pseudocode: str) -> bool:
    """True only if the decompiler produced real pseudocode.

    Hex-Rays-less databases, decompile failures and demo stubs all come back as
    either an empty string or a leading ``//`` comment (e.g. ``// lvars error: …``
    or ``// (demo) no pseudocode``) — treat those as "no pseudocode" so callers
    fall back to disassembly.
    """
    s = (pseudocode or "").strip()
    return bool(s) and not s.startswith("//")


# ── DB handle ────────────────────────────────────────────────────────────────

class IDADatabase:
    """Open .i64 database handle. Use via `open_i64()` context manager."""

    def __init__(self, backend: RealBackend | DemoBackend) -> None:
        self._b = backend
        self._funcs: list[FunctionInfo] | None = None

    # ── core queries ────────────────────────────────────────────────────────

    async def list_functions(self) -> list[FunctionInfo]:
        """Return all functions. Cached after first call."""
        if self._funcs is None:
            self._funcs = await self._b.list_functions()
        return self._funcs

    async def disasm(self, address: int | str) -> list[dict]:
        """Disassemble a function at *address*. Returns list of {address, text}."""
        return await self._b.disasm(address)

    async def decompile(self, address: int | str) -> str:
        """Return pseudocode for the function at *address* (requires Hex-Rays)."""
        return await self._b.decompile(address)

    async def xrefs_to(self, address: int | str) -> list[dict]:
        """Functions that call the function at *address*."""
        return await self._b.xrefs_to(address)

    async def xrefs_from(self, address: int | str) -> list[dict]:
        """Functions called by the function at *address*."""
        return await self._b.xrefs_from(address)

    async def rename(self, address: int | str, new_name: str) -> bool:
        """Rename the function at *address* and persist to the .i64."""
        ok = await self._b.rename(address, new_name)
        if ok and self._funcs:
            a = address if isinstance(address, int) else int(address, 16)
            for f in self._funcs:
                if f["start"] == a:
                    f["name"] = new_name
        return ok

    # ── AI naming ───────────────────────────────────────────────────────────

    async def name_function(
        self,
        address: int | str,
        *,
        rename: bool = False,
    ) -> NameResult:
        """Ask the model to name one function.

        Args:
            address: function start address
            rename:  if True, also persist the AI name to the .i64

        Returns a NameResult dict with old_name, new_name, reasoning, confidence.
        """
        funcs = await self.list_functions()
        a = address if isinstance(address, int) else int(address, 16)
        func = next((f for f in funcs if f["start"] == a), None)
        old_name = func["name"] if func else hex(a)

        insns   = await self.disasm(a)
        callees = [_fmt_xref(x) for x in await self.xrefs_from(a)]
        callers = [_fmt_xref(x) for x in await self.xrefs_to(a)]

        full = ""
        async for tok in self._b.stream_name(a, insns, callees, callers):
            full += tok

        new_name  = extract_name(full) or ""
        reasoning = ""
        if "REASON:" in full:
            reasoning = full.partition("REASON:")[2].strip()

        confidence = "high" if new_name and not old_name.startswith("sub_") else (
                     "medium" if new_name else "low")

        if rename and new_name:
            await self.rename(a, new_name)

        return NameResult(
            address=a, old_name=old_name, new_name=new_name,
            reasoning=reasoning, confidence=confidence,
        )

    def stream_name_tokens(
        self,
        address: int | str,
        insns: list[dict],
        callees: list[str],
        callers: list[str],
    ) -> AsyncIterator[str]:
        """Raw token stream for custom UIs."""
        return self._b.stream_name(address, insns, callees, callers)

    async def batch_name(
        self,
        *,
        limit: int = 50,
        unnamed_only: bool = True,
        rename: bool = True,
        progress_cb=None,
    ) -> list[NameResult]:
        """Name multiple functions.

        Args:
            limit:       max functions to name
            unnamed_only: only process sub_* functions
            rename:      persist names to the .i64
            progress_cb: optional async callable(done, total, result) for progress

        Returns list of NameResult, one per function processed.
        """
        funcs = await self.list_functions()
        targets = [f for f in funcs
                   if not unnamed_only or f["name"].lower().startswith("sub_")]
        targets = targets[:limit]
        results: list[NameResult] = []
        for i, f in enumerate(targets):
            r = await self.name_function(f["start"], rename=rename)
            results.append(r)
            if progress_cb:
                await progress_cb(i + 1, len(targets), r)
        return results

    # ── variable / parameter naming ──────────────────────────────────────────

    async def name_variables(
        self,
        address: int | str,
        *,
        rename: bool = False,
    ) -> dict:
        """Ask the model to name locals + params in the function at *address*.

        Requires Hex-Rays (decompiler). Returns:
            {"mapping": {old: {"name","type"}}, "renamed": N, "retyped": M,
             "pseudocode": str}
        where *pseudocode* is the updated listing when rename=True, else the
        original. *mapping* is empty if there's nothing to name or no decompiler.
        """
        a = address if isinstance(address, int) else int(address, 16)
        info = await self._b.get_lvars(a)
        pseudocode = info.get("pseudocode", "")
        lvars = info.get("lvars", [])
        if not lvars:
            return {"mapping": {}, "renamed": 0, "retyped": 0, "pseudocode": pseudocode}

        mapping = await self._b.name_variables(pseudocode, lvars)
        if not mapping:
            return {"mapping": {}, "renamed": 0, "retyped": 0, "pseudocode": pseudocode}

        if rename:
            result = await self._b.rename_lvars(a, mapping)
            return {"mapping": mapping,
                    "renamed": result.get("renamed", 0),
                    "retyped": result.get("retyped", 0),
                    "pseudocode": result.get("pseudocode", pseudocode)}
        return {"mapping": mapping, "renamed": 0, "retyped": 0, "pseudocode": pseudocode}

    async def batch_name_variables(
        self,
        *,
        limit: int = 50,
        named_only: bool = True,
        rename: bool = True,
        progress_cb=None,
    ) -> list[dict]:
        """Name locals + params across many functions.

        Args:
            limit:      max functions to process
            named_only: only functions that already have a real name (skip sub_*),
                        since a function you haven't named yet has little var context
            rename:     persist variable names to the .i64
            progress_cb: optional async callable(done, total, result)

        Returns one result dict per function (see name_variables).
        """
        funcs = await self.list_functions()
        targets = [f for f in funcs
                   if not named_only or not f["name"].lower().startswith("sub_")]
        targets = targets[:limit]
        results: list[dict] = []
        for i, f in enumerate(targets):
            r = await self.name_variables(f["start"], rename=rename)
            r["address"] = f["start"]
            r["function"] = f["name"]
            results.append(r)
            if progress_cb:
                await progress_cb(i + 1, len(targets), r)
        return results

    # ── staged conversation: name → params → locals + return ─────────────────

    async def name_all(
        self,
        address: int | str,
        *,
        rename: bool = False,
        rename_function: bool = True,
        llm_history: list[dict] | None = None,
    ) -> dict:
        """Name + type a function via a 3-stage LLM CONVERSATION.

        Stage 1 names the function, Stage 2 names+types the parameters, Stage 3
        names+types the locals and infers the return type — each stage building on
        the model's own prior answers (see core.llamacpp.name_function_staged).

        Uses Hex-Rays pseudocode when available; falls back to disassembly-based
        naming (function name only — variables need a decompiler) when there's no
        pseudocode, OR when Stage 1 produced no usable name.

        Args:
            rename:          persist results to the .i64
            rename_function: when False, apply variable/param/return types but DON'T
                             commit the function rename (Stage 1 still runs for
                             context). Used by the interactive "type variables" action.
            llm_history:      optional chat history to reuse across related functions
                             (used by bottom-up branch naming).

        Returns:
            {address, old_name, new_name, reasoning, variables, ret_type,
             renamed_vars, retyped_vars, pseudocode, source}
        where *source* is "pseudocode", "disasm", or "pseudocode+disasm".
        """
        a = address if isinstance(address, int) else int(address, 16)
        funcs = await self.list_functions()
        func = next((f for f in funcs if f["start"] == a), None)
        old_name = func["name"] if func else hex(a)

        callees = [_fmt_xref(x) for x in await self.xrefs_from(a)]
        callers = [_fmt_xref(x) for x in await self.xrefs_to(a)]

        info = await self._b.get_lvars(a)
        pseudocode = info.get("pseudocode", "")
        lvars = info.get("lvars", [])

        # extra naming signals: strings / API calls / constants (best-effort)
        hints = None
        if hasattr(self._b, "get_func_meta"):
            try:
                hints = await self._b.get_func_meta(a)
            except Exception:
                hints = None

        new_name = reasoning = ret_type = ""
        variables: dict = {}
        source = ""

        # Preferred path: staged conversation over the decompiler pseudocode.
        if _has_pseudocode(pseudocode):
            staged = await self._b.name_function_staged(
                pseudocode, lvars, callees, callers, hints, llm_history)
            new_name  = staged.get("name", "")
            reasoning = staged.get("reason", "")
            ret_type  = staged.get("ret_type", "")
            variables = staged.get("variables", {})
            source = "pseudocode"

        # Fallback path: DISASM. Triggers when there's no decompiler at all, or the
        # staged pass produced no name. Variables can't be named without a
        # decompiler, so any vars found above are preserved.
        if not new_name:
            insns = await self.disasm(a)
            full = "".join([t async for t in self._b.stream_name(a, insns, callees, callers)])
            fb_name = extract_name(full) or ""
            if fb_name:
                new_name = fb_name
                reasoning = reasoning or (
                    full.partition("REASON:")[2].strip() if "REASON:" in full else "")
            source = "pseudocode+disasm" if source == "pseudocode" else "disasm"

        renamed_vars = 0
        retyped_vars = 0
        applied_ret = ""
        if rename:
            if new_name and rename_function:
                await self.rename(a, new_name)
            if variables or ret_type:
                r = await self._b.rename_lvars(a, variables, ret_type=ret_type)
                renamed_vars = r.get("renamed", 0)
                retyped_vars = r.get("retyped", 0)
                applied_ret = r.get("ret_type", "")
                pseudocode = r.get("pseudocode", pseudocode)

        return {
            "address": a, "old_name": old_name, "new_name": new_name,
            "source": source,
            "reasoning": reasoning, "variables": variables,
            "ret_type": applied_ret or ret_type,
            "renamed_vars": renamed_vars, "retyped_vars": retyped_vars,
            "pseudocode": pseudocode,
        }

    async def name_branch(
        self,
        address: int | str,
        *,
        max_depth: int = 3,
        max_funcs: int = 60,
        unnamed_only: bool = True,
        rename: bool = True,
        progress_cb=None,
    ) -> list[dict]:
        """Deep-analyse a whole call branch, BOTTOM-UP.

        Walks the callee tree from *address* and names the deepest functions first,
        so by the time each caller is named its callees already have real names +
        signatures — the model reasons over a resolved sub-tree instead of sub_*.

        Args:
            max_depth:    how deep to follow callees from the root
            max_funcs:    safety cap on total functions visited
            unnamed_only: only name sub_* functions (still traverses through named
                          ones to reach unnamed descendants)
            rename:       persist names to the .i64
            progress_cb:  optional async callable(done, total, result)

        Returns one result dict per named function (see name_all), leaves first.
        Runs sequentially by design — each step feeds the next.
        """
        root = address if isinstance(address, int) else int(address, 16)
        funcs = await self.list_functions()
        by_addr = {f["start"]: f for f in funcs}

        order: list[int] = []          # post-order: leaves first, root last
        visited: set[int] = set()

        async def _dfs(addr: int, depth: int) -> None:
            if addr in visited or len(visited) >= max_funcs:
                return
            visited.add(addr)
            if depth < max_depth:
                for x in await self.xrefs_from(addr):
                    try:
                        ca = int(x["address"], 16) if isinstance(x.get("address"), str) else int(x["address"])
                    except (KeyError, ValueError, TypeError):
                        continue
                    if ca in by_addr:
                        await _dfs(ca, depth + 1)
            order.append(addr)

        await _dfs(root, 0)

        targets = [ad for ad in order
                   if ad in by_addr and (not unnamed_only
                                         or by_addr[ad]["name"].lower().startswith("sub_"))]
        results: list[dict] = []
        branch_history: list[dict] = []
        for i, ad in enumerate(targets):
            r = await self.name_all(ad, rename=rename, llm_history=branch_history)
            results.append(r)
            if progress_cb:
                await progress_cb(i + 1, len(targets), r)
        return results

    async def batch_name_all(
        self,
        *,
        limit: int = 50,
        unnamed_only: bool = True,
        rename: bool = True,
        concurrency: int = 1,
        progress_cb=None,
    ) -> list[dict]:
        """Name many functions + their variables, ONE LLM call each.

        Args:
            limit:        max functions to process
            unnamed_only: only process sub_* functions
            rename:       persist names to the .i64
            concurrency:  how many functions to name in parallel (clamped 1..4).
                          Only speeds things up if llama-server has multiple slots
                          (--parallel N); IDA calls still serialize on one worker.
            progress_cb:  optional async callable(done, total, result), invoked in
                          completion order with a monotonic done counter.

        Returns one result dict per function (see name_all), in input order.
        """
        funcs = await self.list_functions()
        targets = [f for f in funcs
                   if not unnamed_only or f["name"].lower().startswith("sub_")]
        targets = targets[:limit]
        total = len(targets)
        results: list[dict] = [None] * total  # type: ignore[list-item]

        conc = max(1, min(4, concurrency))
        if conc == 1:
            for i, f in enumerate(targets):
                r = await self.name_all(f["start"], rename=rename)
                results[i] = r
                if progress_cb:
                    await progress_cb(i + 1, total, r)
            return results

        sem = asyncio.Semaphore(conc)
        done = 0

        async def _work(idx: int, f: dict) -> None:
            nonlocal done
            async with sem:
                r = await self.name_all(f["start"], rename=rename)
            results[idx] = r
            done += 1
            if progress_cb:
                await progress_cb(done, total, r)

        await asyncio.gather(*(_work(i, f) for i, f in enumerate(targets)))
        return results

    # ── binary overview ──────────────────────────────────────────────────────

    async def overview(
        self,
        *,
        sample_size: int = 120,
        extra_addresses: list[int] | None = None,
        stream: bool = False,
    ) -> str | AsyncIterator[str]:
        """Ask the model to describe what this binary does.

        Samples functions weighted by size (larger = more important), plus any
        addresses you explicitly pass in *extra_addresses*.

        Args:
            sample_size:      how many functions to include as context
            extra_addresses:  specific functions you want the model to consider
            stream:           if True, return an async token iterator instead of
                              waiting for the full response

        Returns the full overview string, or an async iterator if stream=True.
        """
        funcs = await self.list_functions()

        # weighted sample: bigger functions are more likely to be interesting
        named = [f for f in funcs if not f["name"].lower().startswith("sub_")]
        unnamed = [f for f in funcs if f["name"].lower().startswith("sub_")]

        # always include explicitly requested addresses
        pinned: list[FunctionInfo] = []
        if extra_addresses:
            addr_set = set(extra_addresses)
            pinned = [f for f in funcs if f["start"] in addr_set]

        # fill remainder with weighted sample (named first, then by size)
        pool = named + sorted(unnamed, key=lambda f: f["size"], reverse=True)
        pool = [f for f in pool if f not in pinned]
        sample = pinned + pool[:max(0, sample_size - len(pinned))]

        # fetch signatures for the sample — a named, typed function tells the model
        # far more than a bare name (params + return type)
        sample = sample[:sample_size]
        try:
            protos = await self._b.get_protos([f["start"] for f in sample])
        except Exception:
            protos = {}

        # build context block — prefer signature, fall back to name
        lines = []
        for f in sample:
            sig = protos.get(hex(f["start"])) or protos.get(f["start"])
            label = sig or f["name"]
            lines.append(f"  {label}  ({f['size']} bytes)")
        context = "\n".join(lines)

        prompt = (
            f"Here are up to {len(sample)} functions from a binary "
            f"({len(funcs):,} total functions), with signatures where known:\n\n"
            f"{context}\n\n"
            "Based on these function names, signatures, and sizes:\n"
            "1. What does this binary likely do? (2-3 sentences)\n"
            "2. What are its major subsystems or components?\n"
            "3. Anything security-relevant, unusual, or interesting?\n\n"
            "Be concise and specific. If function names are mostly sub_*, "
            "say so and give your best guess from patterns you can see."
        )

        async def _token_stream() -> AsyncIterator[str]:
            async for tok in llamacpp_stream_text(
                [{"role": "user", "content": prompt}],
                temperature=None,
            ):
                yield tok

        if stream:
            return _token_stream()

        full = "".join([tok async for tok in _token_stream()])
        return full

    # ── export ───────────────────────────────────────────────────────────────

    async def export(
        self,
        path: str | Path,
        *,
        fmt: str = "json",
        named_only: bool = False,
    ) -> Path:
        """Export function list to *path*.

        Args:
            path:       output file path
            fmt:        "json" | "csv" | "idc" | "symbols"
            named_only: skip sub_* functions

        Returns the resolved output path.
        """
        funcs = await self.list_functions()
        if named_only:
            funcs = [f for f in funcs if not f["name"].lower().startswith("sub_")]

        out = Path(path).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "json":
            out.write_text(json.dumps(funcs, indent=2), encoding="utf-8")

        elif fmt == "csv":
            rows = ["address,name,size"]
            for f in funcs:
                rows.append(f'{f["start"]:#x},{f["name"]},{f["size"]}')
            out.write_text("\n".join(rows), encoding="utf-8")

        elif fmt == "idc":
            lines = [
                '// spectrIDA export — apply with IDA File > Script file',
                '#include <idc.idc>',
                'static main() {',
            ]
            for f in funcs:
                safe = f["name"].replace('"', '\\"')
                lines.append(f'  set_name({f["start"]:#x}, "{safe}", SN_NOWARN);')
            lines.append("}")
            out.write_text("\n".join(lines), encoding="utf-8")

        elif fmt == "symbols":
            lines = [f'{f["start"]:#018x} {f["name"]}' for f in funcs]
            out.write_text("\n".join(lines), encoding="utf-8")

        else:
            raise ValueError(f"unknown format {fmt!r} — use json, csv, idc, or symbols")

        return out

    async def close(self) -> None:
        await self._b.close()


# ── context manager ──────────────────────────────────────────────────────────

@asynccontextmanager
async def open_i64(path: str | Path, *, verbose: bool = False):
    """Async context manager that opens a .i64 and yields an IDADatabase.

        async with open_i64("file.i64") as db:
            funcs = await db.list_functions()

    Args:
        path:    path to an IDA .i64 database
        verbose: print a funny loading line while opening
    """
    if verbose:
        print(loading_line())
    b = RealBackend(str(Path(path).expanduser().resolve()))
    await b.ensure_open()
    db = IDADatabase(b)
    try:
        yield db
    finally:
        await db.close()


@asynccontextmanager
async def open_demo(*, verbose: bool = False):
    """Open the built-in demo database (no IDA required). Good for testing."""
    if verbose:
        print("loading demo — no IDA needed.")
    b = DemoBackend()
    db = IDADatabase(b)
    try:
        yield db
    finally:
        await db.close()
