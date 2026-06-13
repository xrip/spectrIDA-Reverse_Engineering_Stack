"""The data backend the TUI talks to — real (idalib + Ollama) or demo (canned).

Screens never branch on demo-vs-real; they hold a Backend and call its async
methods. `stream_name` takes everything either backend might need; each uses
what's relevant.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

from spectrida.core import demo as _demo
from spectrida.core import ida as _ida
from spectrida.core import ollama as _ollama


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
    async def name_variables(self, pseudocode: str, lvars: list[dict]) -> dict: ...
    async def name_function_and_vars(self, pseudocode, lvars, callees, callers, hints=None) -> dict: ...
    def stream_name(self, addr, insns, callees, callers) -> AsyncIterator[str]: ...
    async def close(self) -> None: ...


class RealBackend(Backend):
    def __init__(self, i64: str) -> None:
        self.i64 = i64
        self.title = Path(i64).stem.replace("_parallel", "")
        self._ida: _ida.IDAHandle | None = None
        self._opened = False

    async def open(self) -> None:
        self._ida = await _ida.open_ida(self.i64)
        self._opened = True

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

    async def name_variables(self, pseudocode, lvars):
        return await _ollama.name_variables(pseudocode, lvars)

    async def name_function_and_vars(self, pseudocode, lvars, callees, callers, hints=None):
        return await _ollama.name_function_and_vars(pseudocode, lvars, callees, callers, hints)

    def stream_name(self, addr, insns, callees, callers):
        return _ollama.stream_name(insns, callees, callers)

    async def close(self):
        if self._ida:
            await self._ida.close()


class DemoBackend(Backend):
    demo = True
    title = "demo.dll"

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
    async def name_variables(self, pseudocode, lvars):
        return _demo.name_variables(pseudocode, lvars)

    async def name_function_and_vars(self, pseudocode, lvars, callees, callers, hints=None):
        return _demo.name_function_and_vars(pseudocode, lvars, callees, callers)

    def stream_name(self, addr, insns, callees, callers):
        return _demo.stream_name(addr)

    async def close(self):
        return None


async def make_backend(*, demo: bool = False, i64: str | None = None) -> Backend:
    if demo or not i64:
        return DemoBackend()
    b = RealBackend(i64)
    await b.open()
    return b
