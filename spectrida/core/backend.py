"""The data backend the TUI talks to — real (idalib + llama.cpp) or demo (canned).

Screens never branch on demo-vs-real; they hold a Backend and call its async
methods. `stream_name` takes everything either backend might need; each uses
what's relevant.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

from spectrida.core import demo as _demo
from spectrida.core import ida as _ida
from spectrida.core import llamacpp as _llamacpp


def format_local_types(ltypes: dict, *, max_structs: int = 160,
                       max_enums: int = 80) -> str:
    """Render the binary's user-defined struct/enum library as a compact line for
    the (cached) system prompt: ``Name(Nf,0xSize)`` per struct, ``Name(Mm,0xSize)``
    per enum. The field/member count + size let the model pick the type that fits a
    given access pattern without us pasting every full definition. Returns "" when
    there are no user types. Tolerates the legacy name-only (str) entry form.
    """
    structs = ltypes.get("structs", []) or []
    enums = ltypes.get("enums", []) or []
    if not structs and not enums:
        return ""

    def _fmt(entry, count_key: str, suffix: str) -> str:
        if isinstance(entry, str):
            return entry
        name = entry.get("name", "")
        n = entry.get(count_key, -1)
        sz = entry.get("size", 0)
        bits = []
        if isinstance(n, int) and n >= 0:
            bits.append(f"{n}{suffix}")
        if sz:
            bits.append(f"{sz:#x}")
        return name + (f"({','.join(bits)})" if bits else "")

    lines = ["User-defined types in this binary - name(field/member count, "
             "byte size). Prefer these when typing parameters, variables and "
             "struct fields; pick the one whose size/shape matches the access:"]
    if structs:
        lines.append("  Structs/unions: "
                     + ", ".join(_fmt(s, "fields", "f") for s in structs[:max_structs]))
    if enums:
        lines.append("  Enums: "
                     + ", ".join(_fmt(e, "members", "m") for e in enums[:max_enums]))
    return "\n".join(lines)


class Backend:
    title: str = ""
    demo: bool = False

    async def ensure_open(self) -> None:
        return None

    async def list_functions(self) -> list[dict]: ...
    async def disasm(self, addr) -> list[dict]: ...
    async def decompile(self, addr) -> str: ...
    async def xrefs_to(self, addr) -> list[dict]: ...
    async def xrefs_from(self, addr) -> list[dict]: ...
    async def rename(self, addr, name: str) -> bool: ...
    async def get_lvars(self, addr) -> dict: ...
    async def get_protos(self, addresses: list) -> dict: ...
    async def get_func_meta(self, addr) -> dict: ...
    async def rename_lvars(self, addr, names: dict, ret_type: str = "") -> dict: ...
    async def propagate_ret(self, addr) -> dict: ...
    async def struct_evidence(self, addr, arg_index: int = 0) -> dict: ...
    async def make_struct(self, name: str, decl: str) -> dict: ...
    async def apply_struct(self, addr, arg_index: int, type_str: str) -> dict: ...
    async def name_struct(self, layout: list[dict], snippets: str, glossary: str = "") -> dict: ...
    async def list_globals(self, min_xrefs: int = 1) -> list[dict]: ...
    async def global_context(self, ea, top_k: int = 5) -> dict: ...
    async def set_global(self, ea, name: str, type_str: str = "") -> dict: ...
    async def name_global(self, global_info: dict, sites: list[dict], glossary: str = "") -> dict: ...
    async def name_variables(self, pseudocode: str, lvars: list[dict]) -> dict: ...
    async def correct_types(self, pseudocode: str, failed: list[dict]) -> dict: ...
    async def name_function_staged(self, pseudocode, lvars, callees, callers,
                                   hints=None, history=None, glossary="") -> dict: ...
    def stream_name(self, addr, insns, callees, callers) -> AsyncIterator[str]: ...
    async def get_entry_point(self) -> int | None: ...
    async def lumina_probe(self) -> list[str] | None: ...
    async def close(self) -> None: ...


class RealBackend(Backend):
    def __init__(self, i64: str) -> None:
        self.i64 = i64
        self.title = Path(i64).stem.replace("_parallel", "")
        self._ida: _ida.IDAHandle | None = None
        self._opened = False

    async def open(self) -> None:
        self._ida = await _ida.open_ida(self.i64)
        ctx = await _ida.get_binary_context(self._ida)
        # Append user-defined structs/enums so the LLM knows which types exist
        # and can apply them when assigning parameter / variable types.
        try:
            ltypes = await _ida.get_local_types(self._ida)
            block = format_local_types(ltypes)
            if block:
                ctx = ctx.rstrip() + "\n\n" + block
        except Exception:
            pass
        _llamacpp.set_binary_context(ctx)
        self._lumina_members: list[str] | None = await _ida.lumina_probe(self._ida)
        self._opened = True

    async def lumina_probe(self) -> list[str] | dict | None:
        return self._lumina_members

    async def ensure_open(self) -> None:
        if not self._opened:
            await self.open()

    async def list_functions(self):  return await _ida.list_functions(self._ida)
    async def disasm(self, addr):    return await _ida.disasm(self._ida, addr)
    async def decompile(self, addr): return await _ida.decompile(self._ida, addr)
    async def xrefs_to(self, addr):  return await _ida.xrefs_to(self._ida, addr)
    async def xrefs_from(self, addr): return await _ida.xrefs_from(self._ida, addr)
    async def rename(self, addr, name): return await _ida.rename(self._ida, addr, name)
    async def get_lvars(self, addr):   return await _ida.get_lvars(self._ida, addr)
    async def get_protos(self, addresses): return await _ida.get_protos(self._ida, addresses)
    async def get_func_meta(self, addr): return await _ida.get_func_meta(self._ida, addr)
    async def rename_lvars(self, addr, names, ret_type=""):
        return await _ida.rename_lvars(self._ida, addr, names, ret_type)

    async def propagate_ret(self, addr):
        return await _ida.propagate_ret(self._ida, addr)

    async def struct_evidence(self, addr, arg_index=0):
        return await _ida.struct_evidence(self._ida, addr, arg_index)

    async def make_struct(self, name, decl):
        return await _ida.make_struct(self._ida, name, decl)

    async def apply_struct(self, addr, arg_index, type_str):
        return await _ida.apply_struct(self._ida, addr, arg_index, type_str)

    async def name_struct(self, layout, snippets, glossary=""):
        return await _llamacpp.name_struct(layout, snippets, glossary=glossary)

    async def list_globals(self, min_xrefs=1):
        return await _ida.list_globals(self._ida, min_xrefs)

    async def global_context(self, ea, top_k=5):
        return await _ida.global_context(self._ida, ea, top_k)

    async def set_global(self, ea, name, type_str=""):
        return await _ida.set_global(self._ida, ea, name, type_str)

    async def name_global(self, global_info, sites, glossary=""):
        return await _llamacpp.name_global(global_info, sites, glossary=glossary)

    async def name_variables(self, pseudocode, lvars):
        return await _llamacpp.name_variables(pseudocode, lvars)

    async def correct_types(self, pseudocode, failed):
        return await _llamacpp.correct_types(pseudocode, failed)

    async def name_function_staged(self, pseudocode, lvars, callees, callers,
                                   hints=None, history=None, glossary=""):
        return await _llamacpp.name_function_staged(
            pseudocode, lvars, callees, callers, hints, history, glossary=glossary)

    async def stream_name(self, addr, insns, callees, callers):
        # Fetch pseudocode so the streaming preview uses the same rich context
        # as the staged naming pass.  Falls back silently to asm-only when
        # Hex-Rays is not installed or decompilation fails.
        pseudocode = ""
        try:
            pseudocode = await _ida.decompile(self._ida, addr)
        except Exception:
            pass
        async for tok in _llamacpp.stream_name(insns, callees, callers,
                                                pseudocode=pseudocode):
            yield tok

    async def get_entry_point(self) -> int | None:
        return await _ida.get_entry_point(self._ida)

    async def close(self):
        if self._ida:
            await self._ida.close()


class DemoBackend(Backend):
    demo = True
    title = "demo.dll"
    last_glossary = ""   # last glossary block passed to name_function_staged

    def __init__(self) -> None:
        self._funcs = [dict(f) for f in _demo.FUNCTIONS]

    async def list_functions(self):  return self._funcs
    async def disasm(self, addr):    return _demo.disasm(addr)
    async def decompile(self, addr): return _demo.decompile(addr)
    async def xrefs_to(self, addr):  return _demo.xrefs_to(addr)
    async def xrefs_from(self, addr): return _demo.xrefs_from(addr)

    async def rename(self, addr, name):
        a = addr if isinstance(addr, int) else int(str(addr), 16)
        for f in self._funcs:
            if f["start"] == a:
                f["name"] = name
                return True
        return True

    async def get_lvars(self, addr):   return _demo.get_lvars(addr)
    async def get_protos(self, addresses): return _demo.get_protos(addresses)
    async def get_func_meta(self, addr): return _demo.get_func_meta(addr)
    async def rename_lvars(self, addr, names, ret_type=""):
        return _demo.rename_lvars(addr, names, ret_type)

    async def propagate_ret(self, addr):
        return _demo.propagate_ret(addr)

    async def struct_evidence(self, addr, arg_index=0):
        return _demo.struct_evidence(addr, arg_index)

    async def make_struct(self, name, decl):
        return _demo.make_struct(name, decl)

    async def apply_struct(self, addr, arg_index, type_str):
        return _demo.apply_struct(addr, arg_index, type_str)

    async def name_struct(self, layout, snippets, glossary=""):
        return _demo.name_struct(layout, snippets, glossary=glossary)

    async def list_globals(self, min_xrefs=1):
        return _demo.list_globals(min_xrefs)

    async def global_context(self, ea, top_k=5):
        return _demo.global_context(ea, top_k)

    async def set_global(self, ea, name, type_str=""):
        return _demo.set_global(ea, name, type_str)

    async def name_global(self, global_info, sites, glossary=""):
        return _demo.name_global(global_info, sites, glossary=glossary)

    async def name_variables(self, pseudocode, lvars):
        return _demo.name_variables(pseudocode, lvars)

    async def correct_types(self, pseudocode, failed):
        return _demo.correct_types(pseudocode, failed)

    async def name_function_staged(self, pseudocode, lvars, callees, callers,
                                   hints=None, history=None, glossary=""):
        self.last_glossary = glossary   # observable for tests / debugging
        return _demo.name_function_staged(pseudocode, lvars, callees, callers,
                                          history=history, glossary=glossary)

    def stream_name(self, addr, insns, callees, callers):
        return _demo.stream_name(addr)

    async def get_entry_point(self) -> int | None:
        return None

    async def lumina_probe(self) -> list[str] | None:
        return None

    async def close(self):
        return None


async def make_backend(*, demo: bool = False, i64: str | None = None) -> Backend:
    if demo or not i64:
        return DemoBackend()
    b = RealBackend(i64)
    await b.open()
    return b
