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

from spectrida.config import (
    audit_log_enabled,
    global_naming_enabled,
    name_cache_enabled,
    name_lint_enabled,
    struct_recovery_enabled,
    type_propagation_enabled,
    type_retry_enabled,
)
from spectrida.core import namecache
from spectrida.core.audit import AuditLog
from spectrida.core.canon import build_preferences, canonical_name
from spectrida.core.globals import rank_globals
from spectrida.core.structs import (
    merge_field_names,
    merge_layouts,
    real_fields,
    reconcile_fields,
    struct_decl,
    struct_signature,
)
from spectrida.core.types import extract_type_identifiers
from spectrida.core.backend import DemoBackend, RealBackend
from spectrida.core.glossary import Glossary
from spectrida.core.namecache import NameCache
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


def _addr_int(x: dict) -> int | None:
    """Parse an xref entry's ``address`` (hex string or int) to int, or None."""
    a = x.get("address")
    if isinstance(a, int):
        return a
    if isinstance(a, str):
        try:
            return int(a, 16)
        except ValueError:
            return None
    return None


# Names that carry no real meaning — the model guessing rather than knowing.
_GENERIC_NAMES = frozenset({
    "process", "handle", "do_stuff", "run", "execute", "thing", "helper",
    "callback", "function", "func", "proc", "stuff", "work", "do_work",
    "main_loop", "init_stuff", "routine", "subroutine", "unknown", "sub",
})


# A shape this many fields or richer may be reused for a *different* pointer by
# signature alone. Below it, two unrelated 2-field structs collide too easily, so
# we never cross-assign one to the other (anti over-merge).
_STRUCT_REUSE_MIN_FIELDS = 4


def _struct_candidate_type(ty: str) -> bool:
    """A parameter type worth trying to recover a struct for: a *generic* pointer
    (or pointer-width scalar) that doesn't already name a known struct/enum. We
    never re-recover a parameter that already has a real typed struct."""
    t = (ty or "").strip()
    if not t:
        return False
    if extract_type_identifiers(t):   # already references a named type → leave it
        return False
    if "*" in t:                       # void *, char *, _QWORD *, …
        return True
    return t.replace(" ", "") in {
        "__int64", "unsigned__int64", "_QWORD", "__int32", "int", "void",
    }


def _worth_propagating(ret_type: str) -> bool:
    """A return type worth pushing onto callers: a pointer or a named struct/enum
    (not a plain scalar like int/void)."""
    if not ret_type:
        return False
    if "*" in ret_type:
        return True
    return bool(extract_type_identifiers(ret_type))


def _name_confidence(new_name: str, source: str, hints: dict | None) -> str:
    """Heuristic confidence in a name: "high" | "medium" | "low".

    Low when there's no name or a generic guess. Disassembly-only naming (no
    decompiler) is weaker than pseudocode; the presence of strong signals
    (API calls / strings / recognised constants) lifts confidence.
    """
    if not new_name:
        return "low"
    if new_name.lower() in _GENERIC_NAMES:
        return "low"
    h = hints or {}
    has_signal = bool(h.get("api_calls") or h.get("strings")
                      or h.get("classified_constants"))
    if source == "disasm":                     # no decompiler output at all
        return "medium" if has_signal else "low"
    return "high" if has_signal else "medium"


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
        self._glossary = Glossary()
        self._glossary_seeded = False
        self._cache = NameCache(enabled=name_cache_enabled())
        self._cache_loaded = False
        self._structs_by_sig: dict[str, str] = {}   # F: layout signature → struct name
        self._struct_layouts: dict[str, list[dict]] = {}  # F: struct name → accumulated layout
        self._structs_loaded = False
        self._structs_dirty = False
        self._audit = AuditLog(enabled=audit_log_enabled())
        self._audit_loaded = False

    async def _ensure_cache_loaded(self) -> None:
        """Load the on-disk naming cache (next to the .i64) once."""
        if self._cache_loaded:
            return
        self._cache_loaded = True
        i64 = getattr(self._b, "i64", None)
        if i64 and self._cache.enabled:
            self._cache.load(str(i64) + ".spectrida-namecache.json")

    def _structs_path(self) -> str | None:
        i64 = getattr(self._b, "i64", None)
        return (str(i64) + ".spectrida-structs.json") if i64 else None

    def _ensure_structs_loaded(self) -> None:
        """Load the accumulated recovered-struct layouts (name → fields) once, and
        rebuild the signature index so re-runs MERGE into the existing structs
        instead of clobbering them with a smaller per-function slice."""
        if self._structs_loaded:
            return
        self._structs_loaded = True
        p = self._structs_path()
        if not p:
            return
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            layouts = data.get("structs", {}) if isinstance(data, dict) else {}
            if isinstance(layouts, dict):
                self._struct_layouts = {k: v for k, v in layouts.items()
                                        if isinstance(v, list)}
                for name, layout in self._struct_layouts.items():
                    self._structs_by_sig[struct_signature(layout)] = name
        except FileNotFoundError:
            pass
        except Exception:
            pass            # corrupt store → start fresh, never fatal

    def _save_structs(self) -> None:
        if not self._structs_dirty:
            return
        p = self._structs_path()
        if not p:
            return
        try:
            tmp = p + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "structs": self._struct_layouts}, f)
            import os as _os
            _os.replace(tmp, p)
            self._structs_dirty = False
        except Exception:
            pass

    def _ensure_audit_loaded(self) -> None:
        """Bind the audit journal to ``<i64>.spectrida-audit.jsonl`` once (loading
        prior history). Demo has no i64 → in-memory only."""
        if self._audit_loaded:
            return
        self._audit_loaded = True
        i64 = getattr(self._b, "i64", None)
        if i64 and self._audit.enabled:
            self._audit.open(str(i64) + ".spectrida-audit.jsonl")

    def _record(self, op: str, **kw) -> None:
        self._ensure_audit_loaded()
        self._audit.record(op, **kw)

    def _record_changes(self, changes: list[dict], *, ea=None) -> None:
        if not changes:
            return
        self._ensure_audit_loaded()
        self._audit.record_changes(changes, ea=ea)

    @property
    def audit(self) -> AuditLog:
        """The project change journal (review / export a revert script)."""
        self._ensure_audit_loaded()
        return self._audit

    async def _ensure_glossary_seed(self) -> None:
        """Seed the project glossary from already-named functions, once."""
        if self._glossary_seeded:
            return
        self._glossary_seeded = True
        try:
            self._glossary.add_existing(await self.list_functions())
        except Exception:
            pass

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

    async def rename(self, address: int | str, new_name: str) -> str | bool:
        """Rename the function at *address*. Returns the actual name used (may
        differ from new_name if deduplicated), or False on failure."""
        a = address if isinstance(address, int) else int(address, 16)
        old_name = ""
        if self._funcs:
            old_name = next((f["name"] for f in self._funcs if f["start"] == a), "")
        result = await self._b.rename(address, new_name)
        actual = result if isinstance(result, str) else (new_name if result else "")
        if actual:
            if old_name != actual:
                self._record("rename_func", ea=a, old=old_name, new=actual)
            if self._funcs:
                for f in self._funcs:
                    if f["start"] == a:
                        f["name"] = actual
        return result

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
            self._record_changes(result.get("changes"), ea=a)
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
        use_cache: bool = True,
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
        await self._ensure_glossary_seed()
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
            await self._ensure_cache_loaded()
            ck = namecache.key(pseudocode, callees, callers, hints)
            cached = self._cache.get(ck) if use_cache else None
            if cached is not None:
                # identical function seen before → reuse name/types verbatim
                new_name  = cached.get("name", "")
                ret_type  = cached.get("ret_type", "")
                variables = dict(cached.get("variables", {}))
                reasoning = "(cached)"
                source = "cache"
            else:
                staged = await self._b.name_function_staged(
                    pseudocode, lvars, callees, callers, hints, llm_history,
                    glossary=self._glossary.render())
                new_name  = staged.get("name", "")
                reasoning = staged.get("reason", "")
                ret_type  = staged.get("ret_type", "")
                variables = staged.get("variables", {})
                self._cache.put(ck, {"name": new_name, "ret_type": ret_type,
                                     "variables": variables})
                self._cache.maybe_save()
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
        dropped: list[dict] = []
        applied_name = ""
        if rename:
            if new_name and rename_function:
                res_rn = await self.rename(a, new_name)
                applied_name = res_rn if isinstance(res_rn, str) and res_rn else new_name
            if variables or ret_type:
                r = await self._b.rename_lvars(a, variables, ret_type=ret_type)
                renamed_vars = r.get("renamed", 0)
                retyped_vars = r.get("retyped", 0)
                applied_ret = r.get("ret_type", "")
                dropped = r.get("dropped", []) or []
                pseudocode = r.get("pseudocode", pseudocode)
                self._record_changes(r.get("changes"), ea=a)

                # E-2: one corrective retry for types rejected as unknown_type —
                # ask the model for a replacement from existing/primitive types.
                if dropped and type_retry_enabled():
                    unknown = [d for d in dropped
                               if str(d.get("reason", "")).startswith("unknown_type")]
                    if unknown:
                        failed = [{"var": d["var"], "type": d["type"]} for d in unknown]
                        corrected = await self._b.correct_types(pseudocode, failed)
                        fix_map = {v: {"name": "", "type": t}
                                   for v, t in corrected.items()
                                   if v != "<return>" and t}
                        fix_ret = corrected.get("<return>", "")
                        if fix_map or fix_ret:
                            r2 = await self._b.rename_lvars(a, fix_map, ret_type=fix_ret)
                            retyped_vars += r2.get("retyped", 0)
                            self._record_changes(r2.get("changes"), ea=a)
                            if fix_ret and r2.get("ret_type"):
                                applied_ret = applied_ret or fix_ret
                            pseudocode = r2.get("pseudocode", pseudocode)
                            # drop only the vars actually fixed this pass
                            attempted = set(fix_map) | ({"<return>"} if fix_ret else set())
                            still = {d["var"] for d in (r2.get("dropped") or [])}
                            fixed = attempted - still
                            dropped = [d for d in dropped if d["var"] not in fixed]

        # D: propagate an interesting (pointer/struct) return type onto caller
        # variables that receive this function's result. Cheap-skip plain scalars.
        propagated = 0
        if (rename and applied_ret and type_propagation_enabled()
                and _worth_propagating(applied_ret)):
            try:
                pr = await self._b.propagate_ret(a)
                propagated = pr.get("propagated", 0)
                self._record_changes(pr.get("changes"))
            except Exception:
                propagated = 0

        confidence = _name_confidence(new_name, source, hints)

        # grow the project glossary with the actually-assigned name (newly named
        # functions only — revisited named funcs are already seeded). Gating (I):
        # don't pollute the shared vocabulary with low-confidence guesses.
        if applied_name and confidence != "low":
            self._glossary.add_name(a, applied_name)

        return {
            "address": a, "old_name": old_name, "new_name": new_name,
            "source": source, "confidence": confidence,
            "reasoning": reasoning, "variables": variables,
            "ret_type": applied_ret or ret_type,
            "renamed_vars": renamed_vars, "retyped_vars": retyped_vars,
            "dropped": dropped, "propagated": propagated,
            "pseudocode": pseudocode,
        }

    # ── struct recovery (F) ───────────────────────────────────────────────────

    async def recover_struct(
        self,
        address: int | str,
        arg_index: int = 0,
        *,
        min_fields: int = 2,
        rename: bool = True,
    ) -> dict:
        """Recover a C struct for parameter *arg_index* of the function at
        *address* from the offsets it's dereferenced at, then apply it.

        Pipeline: harvest field-access evidence → reconcile a deterministic,
        non-overlapping layout → (model) name the struct + fields, refine scalar
        types → register the struct in IDA → set the parameter to ``Struct *``.
        Offsets/sizes come only from observed accesses, never the model.

        A struct's full shape is the UNION of how it's dereferenced across every
        function that receives it. So recoveries are accumulated **by name**: a
        function that resolves to an already-recovered struct merges its observed
        fields into that struct's layout (widest-access-wins) and the struct is
        redefined with the superset — field count only grows, the richest layout is
        never clobbered by a later per-function slice. The accumulated layouts
        persist next to the .i64, so a second `F` pass keeps refining.

        Returns ``{ok, struct, fields, added, applied, reused, grew, new_struct,
        dropped, reason}`` where *fields* is the struct's TOTAL field count after
        the merge and *added* is what this call contributed.
        """
        a = address if isinstance(address, int) else int(address, 16)
        self._ensure_structs_loaded()
        ev = await self._b.struct_evidence(a, arg_index)
        layout = reconcile_fields(ev.get("evidence", []))
        real = real_fields(layout)
        if len(real) < min_fields:
            return {"ok": False, "reason": "too_few_fields", "struct": "",
                    "fields": len(real), "added": 0, "applied": False,
                    "reused": False, "grew": False, "new_struct": False,
                    "dropped": []}

        await self._ensure_glossary_seed()
        sig = struct_signature(layout)
        dropped: list[dict] = []

        # 1. choose the target struct name.
        #    a) the param is already typed as a struct WE recovered → merge into it
        #       (this is what lets a 2nd F pass refine already-typed params);
        #    b) a rich shape matches a known signature → reuse that struct;
        #    c) otherwise the model names a (possibly new) struct.
        cur_idents = [i for i in extract_type_identifiers(ev.get("var_type", ""))
                      if i in self._struct_layouts]
        reused = False
        if cur_idents:
            name = cur_idents[0]
        elif len(real) >= _STRUCT_REUSE_MIN_FIELDS and sig in self._structs_by_sig:
            name = self._structs_by_sig[sig]
            reused = True
        else:
            named = await self._b.name_struct(
                layout, ev.get("snippet", ""), glossary=self._glossary.render())
            layout = merge_field_names(layout, named.get("fields", {}))
            name = named.get("struct_name") or ""
            if not name:
                func = next((f for f in await self.list_functions()
                             if f["start"] == a), None)
                base = (func["name"] if func else hex(a)).replace("$$", "_")
                name = "%s_arg%d_t" % (base, arg_index)

        # 2. merge this slice into the struct's accumulated layout.
        prev = self._struct_layouts.get(name)
        merged = merge_layouts(prev, layout)
        total = len(real_fields(merged))
        new_struct = prev is None
        grew = new_struct or total > len(real_fields(prev))
        added = total - (0 if new_struct else len(real_fields(prev)))

        # 3. (re)define the struct only when it actually changed.
        if rename and grew:
            decl = struct_decl(name, merged)
            mk = await self._b.make_struct(name, decl)
            if not mk.get("ok"):
                return {"ok": False, "reason": "make_failed", "struct": name,
                        "fields": len(real), "added": 0, "applied": False,
                        "reused": False, "grew": False, "new_struct": new_struct,
                        "dropped": mk.get("dropped", [])}
            self._record("make_struct", ea=a, new=name, extra=f"{total} fields")

        self._struct_layouts[name] = merged
        self._structs_dirty = True
        self._structs_by_sig[struct_signature(merged)] = name
        if len(real) >= _STRUCT_REUSE_MIN_FIELDS:
            self._structs_by_sig[sig] = name
        self._glossary.add_term(name)

        applied = False
        if rename:
            ap = await self._b.apply_struct(a, arg_index, name + " *")
            applied = bool(ap.get("applied"))
            dropped = ap.get("dropped", []) or []
            self._record_changes(ap.get("changes"), ea=a)

        return {"ok": True, "struct": name, "fields": total, "added": added,
                "applied": applied, "reused": reused, "grew": grew,
                "new_struct": new_struct, "dropped": dropped, "reason": ""}

    async def recover_structs(
        self,
        *,
        scope: str = "named",
        min_fields: int = 2,
        limit: int = 100_000,
        rename: bool = True,
        progress_cb=None,
    ) -> dict:
        """Recover structs across the binary — for every generic pointer parameter
        with enough distinct field accesses.

        Best run AFTER the whole-binary naming sweep (``B``): named functions give
        the model meaningful naming context, and a recovered ``Struct *`` becomes a
        natural seed for return-type propagation (D).

        Args:
            scope: ``"named"`` (default) processes only functions that already have
                   a real name; ``"all"`` includes ``sub_*`` too.
            min_fields: minimum distinct fields before a struct is worth creating.
            limit:      cap on functions scanned.

        Returns ``{"functions", "structs", "fields", "applied", "reused",
        "dropped"}``.
        """
        if rename and not struct_recovery_enabled():
            return {"functions": 0, "structs": 0, "fields": 0, "applied": 0,
                    "reused": 0, "dropped": 0}
        self._ensure_structs_loaded()
        funcs = await self.list_functions()
        if scope == "named":
            targets = [f for f in funcs if not f["name"].lower().startswith("sub_")]
        else:
            targets = list(funcs)
        targets = targets[:limit]

        def _recoverable(ty: str) -> bool:
            # a generic pointer, OR a param already typed as one of OUR recovered
            # structs (so a repeat pass keeps merging in newly-seen fields) — but
            # never a real, pre-existing named type from the type library.
            if _struct_candidate_type(ty):
                return True
            return any(i in self._struct_layouts
                       for i in extract_type_identifiers(ty))

        totals = {"functions": 0, "structs": 0, "fields": 0, "applied": 0,
                  "reused": 0, "merged": 0, "dropped": 0}
        distinct: set[str] = set()
        total = len(targets)
        for fi, f in enumerate(targets):
            info = await self._b.get_lvars(f["start"])
            args = [lv for lv in info.get("lvars", []) if lv.get("is_arg")]
            items: list[dict] = []
            recovered_here = False
            for idx, lv in enumerate(args):
                if not _recoverable(lv.get("type", "")):
                    continue
                r = await self.recover_struct(f["start"], idx,
                                              min_fields=min_fields, rename=rename)
                items.append({"arg": idx, "var": lv.get("name", ""), "result": r})
                if r.get("ok"):
                    recovered_here = True
                    distinct.add(r.get("struct", ""))
                    totals["fields"] += r.get("added", 0)   # NEW fields contributed
                    totals["applied"] += 1 if r.get("applied") else 0
                    totals["reused"] += 1 if r.get("reused") else 0
                    if r.get("grew") and not r.get("new_struct"):
                        totals["merged"] += 1
                totals["dropped"] += len(r.get("dropped") or [])
            if recovered_here:
                totals["functions"] += 1
            # fire once per function (even with no candidate args) so the caller
            # sees a steady 1..total scan, not silence until the first hit
            if progress_cb:
                await progress_cb(fi + 1, total,
                                  {"func": f["name"], "addr": f["start"], "items": items})
        totals["structs"] = len(distinct)
        self._save_structs()
        return totals

    # ── global variable naming + typing (G) ───────────────────────────────────

    async def name_globals(
        self,
        *,
        top_k: int = 5,
        min_xrefs: int = 2,
        limit: int = 100_000,
        rename: bool = True,
        use_cache: bool = True,
        progress_cb=None,
    ) -> dict:
        """Name + type generic globals (``dword_*``, ``byte_*``, ``off_*``, …) from
        their best-understood use sites.

        For each global, ranked by leverage (xref count), the worker selects the
        top-``top_k`` referencing functions by analysis quality (named / typed /
        signal-rich — see ``core.globals.function_quality``) and returns windowed
        snippets + access kinds; the model proposes a name + type, which is applied
        (name first, then type — validated + read-back). A pointer/struct type on a
        global is a natural seed for return-type propagation (D).

        Best run AFTER the whole-binary naming sweep (``B``) so the referencing
        functions are already named/typed — maximum context quality.

        Returns ``{"globals", "named", "typed", "dropped"}``.
        """
        totals = {"globals": 0, "named": 0, "typed": 0, "dropped": 0}
        if rename and not global_naming_enabled():
            return totals
        try:
            raw = await self._b.list_globals(min_xrefs)
        except Exception:
            raw = []
        ranked = rank_globals([g for g in raw
                               if int(g.get("nxrefs", 0)) >= min_xrefs])[:limit]
        await self._ensure_glossary_seed()
        await self._ensure_cache_loaded()

        total = len(ranked)
        # phase callbacks let the UI explain the (slow) per-global analysis:
        # enumeration → "analysing X (n xrefs)" → result, instead of a dead spinner.
        if progress_cb:
            await progress_cb(0, total, {"phase": "enumerated"})
        for gi, g in enumerate(ranked):
            ea = g["ea"]; gname = g.get("name", ""); nx = g.get("nxrefs", 0)
            if progress_cb:
                await progress_cb(gi, total,
                                  {"phase": "analyze", "name": gname, "nxrefs": nx})
            ctx = await self._b.global_context(ea, top_k)
            sites = ctx.get("sites", [])
            if not sites:
                if progress_cb:
                    await progress_cb(gi + 1, total, {"phase": "skip", "name": gname,
                                                      "nxrefs": nx, "reason": "no use sites"})
                continue
            # content-addressed cache: identical use-site shape on an unchanged
            # binary → reuse the prior name/type, no LLM round-trip.
            gk = namecache.key_global(ctx, sites)
            cached = self._cache.get(gk) if use_cache else None
            cache_hit = cached is not None
            if cache_hit:
                nm = cached.get("name", ""); ty = cached.get("type", "")
            else:
                staged = await self._b.name_global(
                    ctx, sites, glossary=self._glossary.render())
                nm = staged.get("name", ""); ty = staged.get("type", "")
                self._cache.put_global(gk, {"name": nm, "type": ty})
                self._cache.maybe_save()
            if not nm and not ty:
                if progress_cb:
                    await progress_cb(gi + 1, total, {"phase": "skip", "name": gname,
                                                      "nxrefs": nx, "reason": "model gave no name"})
                continue
            totals["globals"] += 1
            applied_name = ""
            dropped: list[dict] = []
            if rename:
                r = await self._b.set_global(ea, nm, ty)
                if r.get("named"):
                    totals["named"] += 1
                    applied_name = r["named"]
                if r.get("typed"):
                    totals["typed"] += 1
                dropped = r.get("dropped", []) or []
                totals["dropped"] += len(dropped)
                self._record_changes(r.get("changes"), ea=ea)
                # grow the glossary so later globals/functions reuse the vocabulary
                if applied_name:
                    self._glossary.add_name(ea, applied_name)
            if progress_cb:
                await progress_cb(gi + 1, total, {
                    "phase": "done", "name": applied_name or nm, "type": ty,
                    "old_name": gname, "nxrefs": nx, "sites": len(sites),
                    "dropped": dropped, "source": "cache" if cache_hit else "model",
                })
        return totals

    # ── name canonicalisation linter (C) ──────────────────────────────────────

    async def canonicalize_names(
        self,
        *,
        scope: str = "named",
        rename: bool = True,
        progress_cb=None,
    ) -> dict:
        """Lint + unify function names across the binary for consistency.

        Equivalent tokens (``message``/``msg``, ``receive``/``recv``, …) are
        unified to the form THIS binary already uses most (data-driven — nothing is
        imposed unless the binary is already inconsistent), and always-wrong
        spellings are fixed. Only multi-token snake_case names are rewritten;
        library/runtime/class names are left untouched (see ``core.canon``).

        Generic, meaningless names are *reported* (``reason="generic"``) but never
        auto-renamed — there's no safe target.

        Returns ``{"checked", "flagged", "renamed", "generic"}``.
        """
        funcs = await self.list_functions()
        named = [f for f in funcs if not f["name"].lower().startswith("sub_")]
        names = [f["name"] for f in named]
        prefs = build_preferences(names)

        totals = {"checked": len(named), "flagged": 0, "renamed": 0, "generic": 0}
        do_rename = rename and name_lint_enabled()
        total = len(named)
        for i, f in enumerate(named):
            cur = f["name"]
            sug = canonical_name(cur, prefs)
            info = {"current": cur, "suggested": "", "reason": "", "applied": False,
                    "addr": f["start"]}
            if sug != cur:
                totals["flagged"] += 1
                info["suggested"] = sug
                info["reason"] = "normalize"
                if do_rename:
                    actual = await self.rename(f["start"], sug)
                    applied = actual if isinstance(actual, str) else (sug if actual else "")
                    if applied:
                        totals["renamed"] += 1
                        info["applied"] = True
                        info["suggested"] = applied   # may differ if deduped
            elif cur.lower() in _GENERIC_NAMES:
                totals["generic"] += 1
                info["reason"] = "generic"
            if progress_cb and info["reason"]:
                await progress_cb(i + 1, total, info)
        return totals

    async def name_branch(
        self,
        address: int | str,
        *,
        max_depth: int = 3,
        max_funcs: int = 60,
        unnamed_only: bool = True,
        revisit_named: bool = False,
        rename: bool = True,
        progress_cb=None,
        plan_cb=None,
        _shared_visited: set[int] | None = None,
        _callees_map: dict[int, list[int]] | None = None,
    ) -> list[dict]:
        """Deep-analyse a whole call branch, BOTTOM-UP.

        Walks the callee tree from *address* and names the deepest functions first,
        so by the time each caller is named its callees already have real names +
        signatures — the model reasons over a resolved sub-tree instead of sub_*.

        Args:
            max_depth:    how deep to follow callees from the root
            max_funcs:    safety cap on functions visited *from this root*
            unnamed_only: only name sub_* functions (still traverses through named
                          ones to reach unnamed descendants)
            revisit_named: also RE-ENTER functions that already have a real name and
                          apply variable / return typing to them (like the 'V'
                          action) WITHOUT renaming the function. Overrides
                          unnamed_only — every visited function becomes a target.
            rename:       persist names to the .i64
            progress_cb:  optional async callable(done, total, result)
            _shared_visited: internal — a visited-set shared across multiple
                          name_branch calls (used by batch_name_branches) so each
                          function is walked / named exactly once across branches.
            _callees_map: internal — prebuilt {addr: [callee_addr, …]} adjacency so
                          the DFS doesn't re-query xrefs_from per function.

        Returns one result dict per named function (see name_all), leaves first.
        Runs sequentially by design — each step feeds the next.
        """
        root = address if isinstance(address, int) else int(address, 16)
        funcs = await self.list_functions()
        by_addr = {f["start"]: f for f in funcs}

        order: list[int] = []          # post-order: leaves first, root last
        visited: set[int] = _shared_visited if _shared_visited is not None else set()
        start_count = len(visited)     # cap max_funcs on *new* visits this call

        async def _dfs(addr: int, depth: int) -> None:
            if addr in visited or (len(visited) - start_count) >= max_funcs:
                return
            visited.add(addr)
            if depth < max_depth:
                if _callees_map is not None:
                    neighbours = _callees_map.get(addr, [])
                else:
                    neighbours = [ca for x in await self.xrefs_from(addr)
                                  if (ca := _addr_int(x)) is not None]
                for ca in neighbours:
                    if ca in by_addr:
                        await _dfs(ca, depth + 1)
            order.append(addr)

        await _dfs(root, 0)

        def _is_named(ad: int) -> bool:
            return not by_addr[ad]["name"].lower().startswith("sub_")

        if revisit_named:
            targets = [ad for ad in order if ad in by_addr]
        else:
            targets = [ad for ad in order
                       if ad in by_addr and (not unnamed_only or not _is_named(ad))]

        if plan_cb:
            plan_info = [
                (ad, by_addr[ad]["name"] if ad in by_addr else hex(ad))
                for ad in targets
            ]
            await plan_cb(plan_info)

        results: list[dict] = []
        branch_history: list[dict] = []
        for i, ad in enumerate(targets):
            # Already-named functions are re-entered for variable / return typing
            # (like the interactive 'V' action) but NOT renamed; sub_* get full naming.
            rename_function = not _is_named(ad)
            r = await self.name_all(ad, rename=rename, rename_function=rename_function,
                                    llm_history=branch_history)
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

    async def batch_name_branches(
        self,
        *,
        scope: str = "all",
        rename: bool = True,
        revisit_named: bool = True,
        refine: bool = False,
        max_depth: int = 64,
        max_funcs_per_branch: int = 100_000,
        branch_cb=None,
        plan_cb=None,
        progress_cb=None,
    ) -> dict:
        """Deep-name the binary bottom-up, branch by branch.

        Builds the call graph once, then runs deep bottom-up naming
        (:meth:`name_branch`) on a set of branch roots in turn — so within each
        branch the deepest functions are named first. A shared visited-set dedups
        overlap between branches, so each function is processed at most once.

        Args:
            scope: which branches to cover.
                "all"     — start from the top-level roots (functions nothing
                            else calls), then sweep any leftover (cycles / below
                            the depth cap) until the WHOLE binary is covered.
                "unnamed" — start from every sub_* function ("find unnamed
                            branches"); only branches that contain unnamed
                            functions are walked, the rest of the binary is left
                            untouched. No full-coverage leftover sweep.
            revisit_named: when True, functions that already have a real name are
                            still entered and get their variables / return type
                            applied (like the interactive 'V' action) without
                            being renamed. For scope="unnamed" pass False to focus
                            purely on naming the sub_* functions.
            refine: after the sweep, run a SECOND pass over functions that were
                            named with low confidence (generic/weak guesses), now
                            that the whole binary has context (full glossary, named
                            neighbours). The refine pass bypasses the name cache so
                            the model re-reasons with the richer context.

        Callbacks:
            branch_cb:   async (branch_idx, root_name, root_addr) — a new branch begins
            plan_cb:     forwarded to name_branch — per-branch tree plan
            progress_cb: forwarded to name_branch — per-function progress

        Returns {"branches", "functions", "named", "vars", "typed", "dropped",
        "refined"}.
        """
        funcs = await self.list_functions()
        by_addr = {f["start"]: f for f in funcs}

        def _is_sub(ad: int) -> bool:
            return by_addr[ad]["name"].lower().startswith("sub_")

        # ── build the callee graph once (one xrefs_from per function) ──
        callees: dict[int, list[int]] = {}
        indeg: dict[int, int] = {a: 0 for a in by_addr}
        for a in by_addr:
            cs = [ca for x in await self.xrefs_from(a)
                  if (ca := _addr_int(x)) is not None and ca in by_addr and ca != a]
            callees[a] = cs
        for cs in callees.values():
            for c in set(cs):
                indeg[c] = indeg.get(c, 0) + 1

        if scope == "unnamed":
            # every sub_* function is a branch root — guarantees each gets named,
            # bottom-up within its own callee subtree.
            roots = sorted(a for a in by_addr if _is_sub(a))
            full_coverage = False
        else:
            # roots = nothing calls them; lowest address first for determinism
            roots = sorted(a for a in by_addr if indeg.get(a, 0) == 0)
            full_coverage = True

        shared: set[int] = set()
        totals = {"branches": 0, "functions": 0, "named": 0, "vars": 0,
                  "typed": 0, "dropped": 0, "refined": 0, "propagated": 0}
        low_conf: list[int] = []   # sub_* funcs named with low confidence (for refine)

        def _tally(r: dict) -> None:
            totals["vars"]  += r.get("renamed_vars", 0)
            totals["typed"] += r.get("retyped_vars", 0)
            totals["dropped"] += len(r.get("dropped") or [])
            totals["propagated"] += r.get("propagated", 0)

        async def _run_branch(start: int) -> None:
            totals["branches"] += 1
            if branch_cb:
                await branch_cb(totals["branches"], by_addr[start]["name"], start)
            res = await self.name_branch(
                start, max_depth=max_depth, max_funcs=max_funcs_per_branch,
                revisit_named=revisit_named, rename=rename,
                progress_cb=progress_cb, plan_cb=plan_cb,
                _shared_visited=shared, _callees_map=callees,
            )
            for r in res:
                totals["functions"] += 1
                was_sub = r.get("old_name", "").lower().startswith("sub_")
                if r.get("new_name") and was_sub:
                    totals["named"] += 1
                    if refine and r.get("confidence") == "low":
                        low_conf.append(r["address"])
                _tally(r)

        for r in roots:
            if r not in shared:
                await _run_branch(r)

        # safety net (scope="all" only): cover cycles / functions below the cap
        if full_coverage:
            remaining = [a for a in sorted(by_addr) if a not in shared]
            while remaining:
                await _run_branch(remaining[0])
                remaining = [a for a in sorted(by_addr) if a not in shared]

        # H: refine pass — re-name low-confidence functions now that the whole
        # binary is named (richer glossary + resolved neighbours). Cache bypassed.
        if refine and low_conf:
            totals["branches"] += 1
            if branch_cb:
                await branch_cb(totals["branches"], "refine low-confidence", low_conf[0])
            if plan_cb:
                await plan_cb([(ad, by_addr.get(ad, {}).get("name", hex(ad)))
                               for ad in low_conf])
            for i, ad in enumerate(low_conf):
                before = by_addr.get(ad, {}).get("name", "")
                r = await self.name_all(ad, rename=rename, use_cache=False)
                if r.get("new_name") and r["new_name"] != before:
                    totals["refined"] += 1
                _tally(r)
                if progress_cb:
                    await progress_cb(i + 1, len(low_conf), r)

        return totals

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

    def save_cache(self) -> None:
        """Flush the naming cache + recovered-struct store to disk WITHOUT closing
        the backend.

        The TUI keeps one long-lived IDADatabase and never calls close() (the
        backend outlives any single action), so it calls this after each AI action
        to persist newly-cached names / merged struct layouts instead of relying on
        the periodic ``maybe_save`` threshold or the close-time save it never reaches.
        """
        try:
            self._cache.save()
        except Exception:
            pass
        self._save_structs()

    async def close(self) -> None:
        try:
            self._cache.save()
        except Exception:
            pass
        self._save_structs()
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
