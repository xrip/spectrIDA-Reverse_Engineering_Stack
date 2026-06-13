"""idalib-backed IDA operations via a persistent worker subprocess.

The worker opens the .i64 once and answers commands over stdin/stdout, so the
TUI stays snappy (no reopening a 700 MB database on every click). idalib prints
noise to stdout, so every real response is prefixed with ``@@RESP`` and the
client skips everything else.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from spectrida.config import idalib_dir

# Worker: open db, then loop reading {"cmd","args"} lines, reply "@@RESP <json>".
_WORKER = r"""
import sys, json
sys.path.insert(0, sys.argv[1])
import idapro

def emit(obj):
    sys.stdout.write("@@RESP " + json.dumps(obj) + "\n"); sys.stdout.flush()

rc = idapro.open_database(sys.argv[2], False)
if rc != 0:
    emit({"ok": False, "result": f"open_database failed rc={rc}"})
    sys.exit(1)
import idautils, idc, idaapi, ida_funcs

def _norm(a):
    return int(a, 16) if isinstance(a, str) and a.startswith("0x") else int(a)

def _proto(ea):
    # one-line C prototype WITH name + params, so callers/callees give the model
    # real signatures (e.g. 'void apply_fall_damage(Entity *a1, float *a2)').
    try:
        s = idaapi.print_type(ea, idaapi.PRTYPE_1LINE)
        if s:
            return " ".join(s.split())
    except Exception:
        pass
    try:
        t = idc.get_type(ea)
        if t:
            nm = idc.get_func_name(ea)
            if "(" in t:
                ret, _, rest = t.partition("(")
                return (ret.strip() + " " + nm + "(" + rest).strip()
            return nm + " : " + t
    except Exception:
        pass
    return ""

def _parse_type(type_str):
    # turn a C type string ('Player *', 'unsigned int') into a tinfo_t, or None
    import ida_typeinf
    s = (type_str or "").strip().rstrip(";").strip()
    if not s:
        return None
    tif = ida_typeinf.tinfo_t()
    for decl in (s + " x;", s + ";"):
        try:
            if ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL) is not None:
                return tif
        except Exception:
            pass
    return None

def _set_lvar_type(func_ea, var_name, tif):
    # set an lvar's TYPE (distinct from rename). Requires the var to already have
    # user-info — callers rename first so the saved entry exists under var_name.
    import ida_hexrays
    class _M(ida_hexrays.user_lvar_modifier_t):
        def modify_lvars(self, lvinf):
            for si in lvinf.lvvec:
                if si.name == var_name:
                    si.type = tif
                    return True
            return False
    try:
        return bool(ida_hexrays.modify_user_lvar_info(func_ea, ida_hexrays.MLI_TYPE, _M()))
    except Exception:
        return False

def _set_func_proto(func_ea, ret_type, arg_specs):
    # set the FUNCTION prototype: return type + per-arg name/type, preserving the
    # detected calling convention. arg_specs = {param_index: {"name":.., "type":..}}.
    # Returns dict counting what stuck: {"ret":0/1, "arg_types":N, "arg_names":M}.
    import ida_typeinf, idaapi
    done = {"ret": 0, "arg_types": 0, "arg_names": 0}
    tif = ida_typeinf.tinfo_t()
    if not (idaapi.get_tinfo(tif, func_ea) and tif.is_func()):
        g = ida_typeinf.tinfo_t()
        try:
            ida_typeinf.guess_tinfo(g, func_ea)
        except Exception:
            pass
        if g.is_func():
            tif = g
    fi = ida_typeinf.func_type_data_t()
    if not tif.get_func_details(fi):
        return done
    changed = False
    if ret_type:
        rt = _parse_type(ret_type)
        if rt is not None:
            fi.rettype = rt; done["ret"] = 1; changed = True
    n = fi.size()
    for idx, spec in arg_specs.items():
        if idx < 0 or idx >= n:
            continue
        ty = spec.get("type"); nm = spec.get("name")
        if ty:
            at = _parse_type(ty)
            if at is not None:
                fi[idx].type = at; done["arg_types"] += 1; changed = True
        if nm and nm.isidentifier():
            fi[idx].name = nm; done["arg_names"] += 1; changed = True
    if changed:
        nt = ida_typeinf.tinfo_t()
        if not (nt.create_func(fi) and ida_typeinf.apply_tinfo(func_ea, nt, ida_typeinf.TINFO_DEFINITE)):
            return {"ret": 0, "arg_types": 0, "arg_names": 0}
    return done

emit({"ok": True, "result": "ready"})
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line); cmd = req.get("cmd"); a = req.get("args", {})
        if cmd == "quit":
            break
        elif cmd == "list":
            lim = int(a.get("limit", 200000)); out = []
            for ea in idautils.Functions():
                if len(out) >= lim: break
                fn = idaapi.get_func(ea); sz = fn.size() if fn else 0
                out.append({"name": idc.get_func_name(ea), "start": ea, "end": ea + sz, "size": sz})
            emit({"ok": True, "result": out})
        elif cmd == "disasm":
            addr = _norm(a["address"]); fn = idaapi.get_func(addr); out = []
            if fn:
                for ea in idautils.FuncItems(fn.start_ea):
                    out.append({"address": hex(ea), "text": idc.generate_disasm_line(ea, 0)})
            emit({"ok": True, "result": out})
        elif cmd == "decompile":
            try:
                cf = idaapi.decompile(_norm(a["address"])); emit({"ok": True, "result": str(cf) if cf else ""})
            except Exception as e:
                emit({"ok": True, "result": "// decompile error: %s" % e})
        elif cmd == "lvars":
            # list locals + params (a1.., v1..) alongside the pseudocode
            try:
                import ida_hexrays
                cf = idaapi.decompile(_norm(a["address"]))
                if not cf:
                    emit({"ok": True, "result": {"pseudocode": "", "lvars": []}})
                else:
                    lv_out = []
                    for lv in cf.get_lvars():
                        if not lv.name:
                            continue
                        try:
                            tname = str(lv.type())
                        except Exception:
                            tname = ""
                        lv_out.append({"name": lv.name, "type": tname, "is_arg": bool(lv.is_arg_var)})
                    emit({"ok": True, "result": {"pseudocode": str(cf), "lvars": lv_out}})
            except Exception as e:
                emit({"ok": True, "result": {"pseudocode": "// lvars error: %s" % e, "lvars": []}})
        elif cmd == "rename_lvars":
            # a["names"] = {old: {"name":.., "type":..}}  (legacy: {old: new_name})
            # a["ret_type"] = optional C return type for the function.
            # IDA splits ownership: ARGS + return + convention live in the function
            # PROTOTYPE (apply_tinfo); locals live in LVAR settings. We route each
            # there so _proto() (which reads the stored prototype) shows typed args.
            try:
                import ida_hexrays
                addr = _norm(a["address"]); mapping = a.get("names", {}); ret_type = a.get("ret_type", "")
                cf = idaapi.decompile(addr)
                renamed = 0; retyped = 0
                if cf:
                    func_ea = cf.entry_ea
                    # normalize legacy flat form → {old: {"name","type"}}
                    norm = {}
                    for k, v in mapping.items():
                        if isinstance(v, dict):
                            norm[k] = {"name": v.get("name", "") or "", "type": v.get("type", "") or ""}
                        else:
                            norm[k] = {"name": v or "", "type": ""}
                    arg_specs = {}; arg_renames = 0
                    for lv in cf.get_lvars():
                        spec = norm.get(lv.name)
                        if not spec:
                            continue
                        new = spec["name"]; ty = spec["type"]
                        if lv.is_arg_var:
                            # default arg name aN → prototype param index N-1
                            if lv.name[:1] == "a" and lv.name[1:].isdigit():
                                arg_specs[int(lv.name[1:]) - 1] = {"name": new, "type": ty}
                                if new and new != lv.name and new.isidentifier():
                                    arg_renames += 1
                        else:
                            cur = lv.name
                            if new and new != lv.name and new.isidentifier():
                                if ida_hexrays.rename_lvar(func_ea, lv.name, new):
                                    renamed += 1; cur = new
                            if ty:
                                tif = _parse_type(ty)
                                if tif is not None and _set_lvar_type(func_ea, cur, tif):
                                    retyped += 1
                    # function prototype: return type + arg names/types
                    pd = _set_func_proto(func_ea, ret_type, arg_specs)
                    renamed += min(arg_renames, pd["arg_names"])
                    retyped += pd["ret"] + pd["arg_types"]
                    cf2 = idaapi.decompile(addr)
                    emit({"ok": True, "result": {"renamed": renamed, "retyped": retyped,
                                                 "ret_type": ret_type if pd["ret"] else "",
                                                 "pseudocode": str(cf2) if cf2 else ""}})
                else:
                    emit({"ok": True, "result": {"renamed": 0, "retyped": 0, "ret_type": "", "pseudocode": ""}})
            except Exception as e:
                emit({"ok": False, "error": "rename_lvars: %s" % e})
        elif cmd == "protos":
            # cheap one-line signatures for many functions (no decompile) —
            # used to give the overview real prototypes instead of bare names
            out = {}
            for addr in a.get("addresses", []):
                ea = _norm(addr); out[hex(ea)] = _proto(ea)
            emit({"ok": True, "result": out})
        elif cmd == "func_meta":
            # extra naming hints: compact RE facts that help the model name and type
            # the function without dumping unbounded disassembly into the prompt.
            addr = _norm(a["address"]); fn = idaapi.get_func(addr)
            strings = []; consts = []; classified_consts = []; apis = []
            callsites = []; caller_sites = []; globals_ = []; fields = []
            ss = set(); sc = set(); scc = set(); sa = set()
            scall = set(); scaller = set(); sg = set(); sf = set()

            def _line(ea):
                try:
                    return " ".join((idc.generate_disasm_line(ea, 0) or "").split())
                except Exception:
                    return ""

            def _add(out, seen, value, limit):
                if value and value not in seen and len(out) < limit:
                    seen.add(value); out.append(value)

            def _const_hint(v):
                v32 = v & 0xFFFFFFFF
                known = {
                    0xEDB88320: "CRC32 polynomial",
                    0x04C11DB7: "CRC32 polynomial",
                    0x811C9DC5: "FNV-1a offset basis",
                    0x01000193: "FNV-1a prime",
                    0x9E3779B9: "golden-ratio hash constant",
                    0xDEADBEEF: "debug/sentinel constant",
                    0xFFFFFFFF: "all-bits-set / -1",
                }
                if v32 in known:
                    return "%s (%s)" % (hex(v32), known[v32])
                if v in known:
                    return "%s (%s)" % (hex(v), known[v])
                return ""

            def _api_label(ea, nm):
                proto = _proto(ea)
                try:
                    seg = idc.get_segm_name(ea) or ""
                except Exception:
                    seg = ""
                label = proto or nm
                if seg and seg.lower() not in (".text", "text", "code"):
                    return "%s!%s" % (seg, label)
                return label

            facts = {}
            if fn:
                items = list(idautils.FuncItems(fn.start_ea))
                out_calls = 0
                facts = {
                    "size": fn.size(),
                    "instruction_count": len(items),
                    "leaf": True,
                }

                for ea in items:
                    line = _line(ea)
                    try:
                        mnem = (idc.print_insn_mnem(ea) or "").lower()
                    except Exception:
                        mnem = ""

                    # referenced string literals and other global/data references
                    for dr in idautils.DataRefsFrom(ea):
                        try:
                            raw = idc.get_strlit_contents(dr, -1, 0)
                        except Exception:
                            raw = None
                        if raw:
                            try: s = raw.decode("utf-8", "replace")
                            except Exception: s = str(raw)
                            s = s.strip()
                            _add(strings, ss, s, 20)
                            continue

                        try:
                            nm = idc.get_name(dr) or ""
                        except Exception:
                            nm = ""
                        if not nm:
                            try:
                                seg = idc.get_segm_name(dr) or "data"
                            except Exception:
                                seg = "data"
                            nm = "%s:%s" % (seg, hex(dr))
                        access = "writes" if (
                            idc.get_operand_type(ea, 0) in (idc.o_mem, idc.o_displ)
                            and idc.get_operand_value(ea, 0) == dr
                            and mnem.startswith(("mov", "stos", "xchg"))
                        ) else "reads/refs"
                        _add(globals_, sg, "%s %s at %s" % (access, nm, hex(dr)), 16)

                    # notable immediate constants and pointer/field-like operands
                    for opi in (0, 1, 2):
                        try:
                            otype = idc.get_operand_type(ea, opi)
                            op = idc.print_operand(ea, opi) or ""
                        except Exception:
                            continue
                        if otype == idc.o_imm:
                            v = idc.get_operand_value(ea, opi) & 0xFFFFFFFFFFFFFFFF
                            if v >= 0x80:
                                _add(consts, sc, hex(v), 16)
                                _add(classified_consts, scc, _const_hint(v), 8)
                        elif otype == idc.o_displ:
                            lop = op.lower()
                            if not any(r in lop for r in ("[rsp", "[esp", "[rbp", "[ebp")):
                                _add(fields, sf, "%s in %s" % (op, line), 16)

                    # outgoing calls/imports with the actual call instruction
                    for cr in idautils.CodeRefsFrom(ea, 0):
                        nm = idc.get_func_name(cr)
                        tf = idaapi.get_func(cr)
                        if tf and tf.start_ea == fn.start_ea:
                            continue
                        is_import = tf is None or bool(tf.flags & idaapi.FUNC_THUNK)
                        if tf or nm:
                            out_calls += 1
                            facts["leaf"] = False
                            label = _proto(tf.start_ea) if tf else ""
                            label = label or nm or hex(cr)
                            _add(callsites, scall, "%s -> %s: %s" % (hex(ea), label, line), 12)
                        if nm and not nm.startswith("sub_") and not nm.startswith("j_") and is_import:
                            _add(apis, sa, _api_label(cr, nm), 20)

                facts["calls_out"] = out_calls

                # how callers use this function, especially the return value
                callers_count = 0
                for xr in idautils.XrefsTo(fn.start_ea):
                    cfn = idaapi.get_func(xr.frm)
                    if not cfn:
                        continue
                    callers_count += 1
                    if len(caller_sites) >= 12:
                        continue
                    caller = idc.get_func_name(cfn.start_ea) or hex(cfn.start_ea)
                    off = xr.frm - cfn.start_ea
                    parts = [_line(xr.frm)]
                    try:
                        n1 = idc.next_head(xr.frm, cfn.end_ea)
                        if n1 != idc.BADADDR and n1 < cfn.end_ea:
                            parts.append("next: " + _line(n1))
                            n2 = idc.next_head(n1, cfn.end_ea)
                            if n2 != idc.BADADDR and n2 < cfn.end_ea:
                                parts.append("next2: " + _line(n2))
                    except Exception:
                        pass
                    _add(caller_sites, scaller,
                         "%s+0x%x: %s" % (caller, off, " ; ".join(p for p in parts if p)),
                         12)
                facts["callers"] = callers_count

            emit({"ok": True, "result": {
                "strings": strings,
                "constants": consts,
                "classified_constants": classified_consts,
                "api_calls": apis,
                "function_facts": facts,
                "callsite_snippets": callsites,
                "caller_return_usage": caller_sites,
                "globals": globals_,
                "field_accesses": fields,
            }})
        elif cmd == "rename":
            ok = idc.set_name(_norm(a["address"]), a["name"], idc.SN_NOWARN | idc.SN_NOCHECK)
            emit({"ok": True, "result": bool(ok)})
        elif cmd == "save":
            idc.save_database(""); emit({"ok": True, "result": True})
        elif cmd == "xrefs_to":   # callers of this function
            addr = _norm(a["address"]); seen = {};
            for xr in idautils.XrefsTo(addr):
                fn = idaapi.get_func(xr.frm)
                if fn and fn.start_ea not in seen:
                    seen[fn.start_ea] = {"address": hex(fn.start_ea),
                                         "name": idc.get_func_name(fn.start_ea),
                                         "proto": _proto(fn.start_ea)}
            emit({"ok": True, "result": list(seen.values())})
        elif cmd == "xrefs_from":  # callees referenced inside this function
            addr = _norm(a["address"]); fn = idaapi.get_func(addr); seen = {}
            if fn:
                for ea in idautils.FuncItems(fn.start_ea):
                    for xr in idautils.XrefsFrom(ea, 0):
                        tf = idaapi.get_func(xr.to)
                        if tf and tf.start_ea != fn.start_ea and tf.start_ea not in seen:
                            seen[tf.start_ea] = {"address": hex(tf.start_ea),
                                                 "name": idc.get_func_name(tf.start_ea),
                                                 "proto": _proto(tf.start_ea)}
            emit({"ok": True, "result": list(seen.values())})
        else:
            emit({"ok": False, "error": "unknown cmd %s" % cmd})
    except Exception as e:
        emit({"ok": False, "error": str(e)})
idapro.close_database(True)
"""


def _idalib_env() -> dict[str, str]:
    env = os.environ.copy()
    ida = idalib_dir()
    if ida:
        p = str(Path(ida).resolve())
        env["PATH"] = p + os.pathsep + env.get("PATH", "")
        env["PYTHONPATH"] = p + os.pathsep + env.get("PYTHONPATH", "")
        env["IDADIR"] = p
    return env


class IDAHandle:
    def __init__(self, proc: asyncio.subprocess.Process, i64: str) -> None:
        self._proc = proc
        self.i64 = i64
        self._lock = asyncio.Lock()

    async def _readresp(self) -> dict:
        # skip idapro's stdout noise; only @@RESP lines are ours
        noise: list[str] = []
        while True:
            line = await self._proc.stdout.readline()
            if not line:
                stderr_out = ""
                if self._proc.stderr:
                    try:
                        raw = await asyncio.wait_for(self._proc.stderr.read(4096), timeout=1.0)
                        stderr_out = raw.decode(errors="replace").strip()
                    except Exception:
                        pass
                stdout_out = "\n".join(noise[-20:])
                detail = ""
                if stdout_out:
                    detail += f"\n--- idalib stdout ---\n{stdout_out}"
                if stderr_out:
                    detail += f"\n--- idalib stderr ---\n{stderr_out}"
                raise RuntimeError(f"idalib worker exited unexpectedly{detail}")
            text = line.decode(errors="replace").strip()
            if text.startswith("@@RESP "):
                return json.loads(text[len("@@RESP "):])
            if text:
                noise.append(text)

    async def call(self, cmd: str, **args):
        async with self._lock:
            self._proc.stdin.write((json.dumps({"cmd": cmd, "args": args}) + "\n").encode())
            await self._proc.stdin.drain()
            resp = await self._readresp()
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error", "idalib error"))
        return resp["result"]

    async def close(self) -> None:
        try:
            self._proc.stdin.write(b'{"cmd":"quit"}\n')
            await self._proc.stdin.drain()
            await asyncio.wait_for(self._proc.wait(), timeout=10)
        except Exception:
            try:
                self._proc.terminate()
            except Exception:
                pass
        # Explicitly close pipes so asyncio transports are released before GC.
        # Without this, Python 3.12+ on Windows prints ResourceWarning noise.
        try:
            self._proc.stdin.close()
            await asyncio.wait_for(self._proc.stdin.wait_closed(), timeout=1)
        except Exception:
            pass
        for reader in (r for r in (self._proc.stdout, self._proc.stderr) if r):
            try:
                await asyncio.wait_for(reader.read(), timeout=1)
            except Exception:
                pass


_STREAM_LIMIT = 128 * 1024 * 1024  # 128 MB — list of 150k funcs is ~12 MB as JSON


async def open_ida(i64_path: str) -> IDAHandle:
    ida = idalib_dir()
    if not ida:
        raise RuntimeError("idalib not configured - run: spectrida onboard")
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-c", _WORKER, str(Path(ida).resolve()), i64_path,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, env=_idalib_env(),
        limit=_STREAM_LIMIT,
    )
    handle = IDAHandle(proc, i64_path)
    ready = await handle._readresp()   # waits for the "ready" @@RESP
    if not ready.get("ok"):
        detail = ready.get("result") or ready.get("error") or "unknown error"
        try:
            await handle.close()
        except Exception:
            pass
        raise RuntimeError(f"idalib worker failed to open the database: {i64_path} ({detail})")
    return handle


# ── thin async API used by the TUI ──────────────────────────────────────────

async def list_functions(ida: IDAHandle, limit: int = 200000) -> list[dict]:
    return await ida.call("list", limit=limit)

async def disasm(ida: IDAHandle, address: str | int) -> list[dict]:
    try:
        return await ida.call("disasm", address=_hex(address))
    except Exception:
        return []

async def decompile(ida: IDAHandle, address: str | int) -> str:
    try:
        return await ida.call("decompile", address=_hex(address))
    except Exception:
        return ""

async def rename(ida: IDAHandle, address: str | int, new_name: str) -> bool:
    try:
        ok = await ida.call("rename", address=_hex(address), name=new_name)
        if ok:
            await ida.call("save")
        return bool(ok)
    except Exception:
        return False

async def xrefs_to(ida: IDAHandle, address: str | int) -> list[dict]:
    try:
        return await ida.call("xrefs_to", address=_hex(address))
    except Exception:
        return []

async def xrefs_from(ida: IDAHandle, address: str | int) -> list[dict]:
    try:
        return await ida.call("xrefs_from", address=_hex(address))
    except Exception:
        return []

async def get_lvars(ida: IDAHandle, address: str | int) -> dict:
    """Return {"pseudocode": str, "lvars": [{name,type,is_arg}, ...]} (needs Hex-Rays)."""
    try:
        return await ida.call("lvars", address=_hex(address))
    except Exception:
        return {"pseudocode": "", "lvars": []}

async def get_protos(ida: IDAHandle, addresses: list) -> dict:
    """Return {hex_addr: signature} for many functions in one round-trip."""
    try:
        return await ida.call("protos", addresses=[_hex(x) for x in addresses])
    except Exception:
        return {}

async def get_func_meta(ida: IDAHandle, address: str | int) -> dict:
    """Return naming hints: {"strings": [...], "constants": [...], "api_calls": [...]}."""
    try:
        return await ida.call("func_meta", address=_hex(address))
    except Exception:
        return {"strings": [], "constants": [], "api_calls": []}

async def rename_lvars(ida: IDAHandle, address: str | int, names: dict,
                       ret_type: str = "") -> dict:
    """Rename + type locals/params, and set the function's return type.

    *names* maps old name → {"name": new, "type": c_type} (legacy {old: new} also
    accepted). *ret_type* is an optional C return type for the function itself.
    Returns {"renamed": N, "retyped": M, "ret_type": str, "pseudocode": str}.
    """
    try:
        result = await ida.call("rename_lvars", address=_hex(address), names=names, ret_type=ret_type)
        if result.get("renamed") or result.get("retyped"):
            await ida.call("save")
        return result
    except Exception:
        return {"renamed": 0, "retyped": 0, "ret_type": "", "pseudocode": ""}


def _hex(address: str | int) -> str:
    return hex(address) if isinstance(address, int) else str(address)
