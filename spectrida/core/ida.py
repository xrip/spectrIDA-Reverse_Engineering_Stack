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
import tempfile
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
import idautils, idc, idaapi, ida_funcs, os as _os

# Load Lumina plugin so IDA can use it for auto-naming during the session.
_lumina_dll = _os.path.join(sys.argv[1], "plugins", "lumina.dll")
try: idaapi.load_plugin(_lumina_dll)
except Exception: pass

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

# ── type validation / verification ───────────────────────────────────────────
# Mirror of spectrida.core.types (the worker can't import it — idalib-only path).
# Keep these sets in sync with that canonical, unit-tested module.
import re as _re_t
_BUILTIN_TYPES = {
    "void","bool","_bool","char","short","int","long","float","double",
    "wchar_t","size_t","ssize_t","ptrdiff_t","intptr_t","uintptr_t",
    "__int8","__int16","__int32","__int64","__int128",
    "int8_t","int16_t","int32_t","int64_t","uint8_t","uint16_t","uint32_t","uint64_t",
    "_byte","_word","_dword","_qword","_oword","_unknown",
    "byte","word","dword","qword","uchar","ushort","uint","ulong",
}
_TYPE_KEYWORDS = {
    "const","volatile","struct","union","enum","signed","unsigned","register",
    "static","restrict","__restrict","__unaligned","near","far","__ptr32","__ptr64",
    "__cdecl","__stdcall","__fastcall","__thiscall","__usercall",
}

def _type_idents(type_str):
    out = []
    for tok in _re_t.findall(r"[A-Za-z_][A-Za-z0-9_]*", type_str or ""):
        low = tok.lower()
        if low in _TYPE_KEYWORDS or low in _BUILTIN_TYPES:
            continue
        if tok not in out:
            out.append(tok)
    return out

def _type_exists(ident):
    # True if a named struct/union/enum/typedef `ident` is in the type library.
    import ida_typeinf
    try:
        til = ida_typeinf.get_idati()
        t = ida_typeinf.tinfo_t()
        if t.get_named_type(til, ident):
            return True
        return ida_typeinf.get_named_type(til, ident, ida_typeinf.NTF_TYPE) is not None
    except Exception:
        return True  # be permissive when we genuinely can't check

def _classify_type(type_str):
    # → (tinfo|None, reason). reason ∈ {"", "empty", "unknown_type:<id>", "parse_failed"}
    s = (type_str or "").strip().rstrip(";").strip()
    if not s:
        return (None, "empty")
    for ident in _type_idents(s):
        if not _type_exists(ident):
            return (None, "unknown_type:%s" % ident)
    tif = _parse_type(s)
    if tif is None:
        return (None, "parse_failed")
    return (tif, "")

# Mirror of spectrida.core.globals — generic-data placeholder names + the
# referencing-function quality weighting (keep in sync with that tested module).
_GENERIC_DATA_RE = _re_t.compile(
    r"^(?:dword|qword|word|byte|off|unk|stru|asc|xmmword|ymmword|flt|dbl|"
    r"packreal|tbyte)_[0-9A-Fa-f]+$")

def _is_generic_global(nm):
    return bool(_GENERIC_DATA_RE.match(nm or ""))

def _fn_quality(m):
    s = 0.0
    if m.get("named"): s += 5.0
    if m.get("typed_proto"): s += 3.0
    s += 1.5 * min(m.get("napis", 0), 6)
    s += 1.0 * min(m.get("nstrings", 0), 6)
    s += 0.8 * min(m.get("nnamed_callees", 0), 8)
    sz = m.get("size", 0) or 0
    if sz > 4000: s -= 2.0
    elif sz > 1500: s -= 0.5
    return s

def _norm_ty(s):
    return _re_t.sub(r"\s+", "", s or "")

def _ty_match(applied, intended):
    if _norm_ty(applied) == _norm_ty(intended):
        return True
    return (sorted(_type_idents(applied)) == sorted(_type_idents(intended))
            and (applied or "").count("*") == (intended or "").count("*"))

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
    # detected calling convention. arg_specs = {param_index: {"name","type","old"}}.
    # Returns {"ret":0/1, "arg_types":N, "arg_names":M, "dropped":[{var,type,reason}]}
    # — counts reflect only types VERIFIED via read-back after apply_tinfo.
    import ida_typeinf, idaapi
    done = {"ret": 0, "arg_types": 0, "arg_names": 0, "dropped": [], "changes": []}

    def _drop(idx, ty, reason):
        if idx == "ret":
            var = "<return>"
        else:
            sp = arg_specs.get(idx, {})
            # post-rename name (the arg keeps its new name even if the type was
            # rejected) so a corrective re-apply can match it; fall back to old.
            var = sp.get("name") or sp.get("old") or ("arg%s" % idx)
        done["dropped"].append({"var": var, "type": ty, "reason": reason})

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
        if ret_type:
            _drop("ret", ret_type, "no_func_details")
        for idx, spec in arg_specs.items():
            if spec.get("type"):
                _drop(idx, spec["type"], "no_func_details")
        return done

    changed = False
    intended = {}  # idx (or "ret") -> intended type string, for read-back verify
    olds = {}      # idx (or "ret") -> old type string, for the audit log
    if ret_type:
        rt, reason = _classify_type(ret_type)
        if rt is not None:
            olds["ret"] = str(fi.rettype); fi.rettype = rt
            intended["ret"] = ret_type; changed = True
        else:
            _drop("ret", ret_type, reason)
    n = fi.size()
    for idx, spec in arg_specs.items():
        ty = spec.get("type"); nm = spec.get("name")
        if idx < 0 or idx >= n:
            if ty:
                _drop(idx, ty, "arg_index_oob")
            continue
        if ty:
            at, reason = _classify_type(ty)
            if at is not None:
                olds[idx] = str(fi[idx].type); fi[idx].type = at
                intended[idx] = ty; changed = True
            else:
                _drop(idx, ty, reason)
        if nm and nm.isidentifier():
            old_an = fi[idx].name or ("a%d" % (idx + 1))
            if nm != old_an:
                done["changes"].append({"op": "rename_arg", "target": str(idx),
                                        "old": old_an, "new": nm})
            fi[idx].name = nm; done["arg_names"] += 1; changed = True

    if not changed:
        return done

    nt = ida_typeinf.tinfo_t()
    if not (nt.create_func(fi) and ida_typeinf.apply_tinfo(func_ea, nt, ida_typeinf.TINFO_DEFINITE)):
        # whole apply failed → every intended type is dropped
        for idx, ty in intended.items():
            _drop(idx, ty, "apply_failed")
        return {"ret": 0, "arg_types": 0, "arg_names": 0, "dropped": done["dropped"]}

    def _chg(idx, new_ty):
        if idx == "ret":
            done["changes"].append({"op": "func_ret", "old": olds.get("ret", ""),
                                    "new": new_ty})
        else:
            done["changes"].append({"op": "func_arg", "target": "arg%d" % idx,
                                    "old": olds.get(idx, ""), "new": new_ty})

    # read back and verify each intended type actually stuck
    v = ida_typeinf.tinfo_t(); fi2 = ida_typeinf.func_type_data_t()
    if idaapi.get_tinfo(v, func_ea) and v.is_func() and v.get_func_details(fi2):
        for idx, ty in intended.items():
            if idx == "ret":
                if _ty_match(str(fi2.rettype), ty):
                    done["ret"] = 1; _chg("ret", ty)
                else:
                    _drop("ret", ty, "verify_mismatch")
            elif idx < fi2.size() and _ty_match(str(fi2[idx].type), ty):
                done["arg_types"] += 1; _chg(idx, ty)
            else:
                _drop(idx, ty, "verify_mismatch")
    else:
        # couldn't read back — trust the successful apply
        if "ret" in intended:
            done["ret"] = 1; _chg("ret", intended["ret"])
        for k, ty in intended.items():
            if k != "ret":
                done["arg_types"] += 1; _chg(k, ty)
    return done

def _struct_evidence(cf, var_vec_idx):
    # F — harvest field-access evidence for the lvar at vector index *var_vec_idx*.
    # Walks the ctree for dereferences of that base pointer: *(T*)(var+off),
    # var[idx], var->field. Returns [{offset,size,kind}], kind ∈ read/write/deref.
    import ida_hexrays
    ev = []

    def _resolve(addr_expr):
        # operand of a '*' deref → constant offset if it references our var, else None
        a = addr_expr
        while a is not None and a.op == ida_hexrays.cot_cast:
            a = a.x
        if a is None:
            return None
        if a.op == ida_hexrays.cot_var and a.v.idx == var_vec_idx:
            return 0
        if a.op == ida_hexrays.cot_add:
            x = a.x; y = a.y
            while x is not None and x.op == ida_hexrays.cot_cast:
                x = x.x
            if (x is not None and x.op == ida_hexrays.cot_var and x.v.idx == var_vec_idx
                    and y is not None and y.op == ida_hexrays.cot_num):
                try:
                    return int(y.numval())
                except Exception:
                    return None
        return None

    def _emit(off, et, kind):
        try:
            sz = int(et.get_size()) if et is not None else 0
            is_ptr = bool(et.is_ptr()) if et is not None else False
        except Exception:
            sz, is_ptr = 0, False
        if sz and 0 < sz <= 0x1000:
            ev.append({"offset": int(off), "size": sz,
                       "kind": "deref" if is_ptr else kind})

    class _V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        def visit_expr(self, e):
            try:
                if e.op == ida_hexrays.cot_asg and e.x is not None and e.x.op == ida_hexrays.cot_ptr:
                    off = _resolve(e.x.x)
                    if off is not None:
                        _emit(off, e.x.type, "write")
                if e.op == ida_hexrays.cot_ptr:
                    off = _resolve(e.x)
                    if off is not None:
                        _emit(off, e.type, "read")
                elif e.op == ida_hexrays.cot_memptr:
                    x = e.x
                    while x is not None and x.op == ida_hexrays.cot_cast:
                        x = x.x
                    if x is not None and x.op == ida_hexrays.cot_var and x.v.idx == var_vec_idx:
                        _emit(int(e.m), e.type, "read")
            except Exception:
                pass
            return 0
    try:
        _V().apply_to(cf.body, None)
    except Exception:
        pass
    return ev

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
                _flags = fn.flags if fn else 0
                out.append({"name": idc.get_func_name(ea), "start": ea, "end": ea + sz, "size": sz,
                            "lumina": bool(_flags & getattr(idaapi, "FUNC_LUMINA", 0))})
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
                renamed = 0; retyped = 0; dropped = []; changes = []
                if cf:
                    func_ea = cf.entry_ea
                    # normalize legacy flat form → {old: {"name","type"}}
                    norm = {}
                    for k, v in mapping.items():
                        if isinstance(v, dict):
                            norm[k] = {"name": v.get("name", "") or "", "type": v.get("type", "") or ""}
                        else:
                            norm[k] = {"name": v or "", "type": ""}
                    # Deduplicate proposed names within this function: if two
                    # variables get the same name, the second becomes name_2, etc.
                    _seen: dict[str, int] = {}
                    for k in norm:
                        nm = norm[k]["name"]
                        if not nm:
                            continue
                        if nm in _seen:
                            _seen[nm] += 1
                            norm[k]["name"] = f"{nm}_{_seen[nm]}"
                        else:
                            _seen[nm] = 1
                    arg_specs = {}; arg_renames = 0
                    arg_idx = 0  # positional index in func_type_data_t
                    for lv in cf.get_lvars():
                        if lv.is_arg_var:
                            # Map by POSITION, not by name — name-based indexing
                            # (a1→0, a2→1) breaks for __thiscall where `this` is
                            # arg 0 and a1 is arg 1, and skips non-aN names like `this`.
                            spec = norm.get(lv.name)
                            if spec:
                                new = spec["name"]; ty = spec["type"]
                                arg_specs[arg_idx] = {"name": new, "type": ty, "old": lv.name}
                                if new and new != lv.name and new.isidentifier():
                                    arg_renames += 1
                            arg_idx += 1
                        else:
                            spec = norm.get(lv.name)
                            if not spec:
                                continue
                            new = spec["name"]; ty = spec["type"]
                            cur = lv.name
                            old_lt = ""
                            try: old_lt = str(lv.type())
                            except Exception: old_lt = ""
                            if new and new != lv.name and new.isidentifier():
                                if ida_hexrays.rename_lvar(func_ea, lv.name, new):
                                    renamed += 1
                                    changes.append({"op": "rename_var", "target": lv.name,
                                                    "old": lv.name, "new": new})
                                    cur = new
                            if ty:
                                tif, reason = _classify_type(ty)
                                if tif is None:
                                    dropped.append({"var": cur, "type": ty, "reason": reason})
                                elif _set_lvar_type(func_ea, cur, tif):
                                    retyped += 1
                                    changes.append({"op": "retype_var", "target": cur,
                                                    "old": old_lt, "new": ty})
                                else:
                                    dropped.append({"var": cur, "type": ty, "reason": "apply_failed"})
                    # function prototype: return type + arg names/types
                    pd = _set_func_proto(func_ea, ret_type, arg_specs)
                    renamed += min(arg_renames, pd["arg_names"])
                    retyped += pd["ret"] + pd["arg_types"]
                    dropped.extend(pd.get("dropped", []))
                    changes.extend(pd.get("changes", []))
                    cf2 = idaapi.decompile(addr)
                    emit({"ok": True, "result": {"renamed": renamed, "retyped": retyped,
                                                 "ret_type": ret_type if pd["ret"] else "",
                                                 "dropped": dropped, "changes": changes,
                                                 "pseudocode": str(cf2) if cf2 else ""}})
                else:
                    emit({"ok": True, "result": {"renamed": 0, "retyped": 0, "ret_type": "",
                                                 "dropped": [], "changes": [], "pseudocode": ""}})
            except Exception as e:
                emit({"ok": False, "error": "rename_lvars: %s" % e})
        elif cmd == "protos":
            # cheap one-line signatures for many functions (no decompile) —
            # used to give the overview real prototypes instead of bare names
            out = {}
            for addr in a.get("addresses", []):
                ea = _norm(addr); out[hex(ea)] = _proto(ea)
            emit({"ok": True, "result": out})
        elif cmd == "propagate_ret":
            # D — return-type propagation: once a callee's return type is known and
            # interesting (pointer / struct / enum), push it onto each caller's
            # local variable that receives the call result, but only when that
            # variable is still a generic placeholder (don't clobber a better type).
            try:
                import ida_hexrays, ida_typeinf
                callee = _norm(a["address"])
                rt = None
                ftif = ida_typeinf.tinfo_t()
                if idaapi.get_tinfo(ftif, callee) and ftif.is_func():
                    fd = ida_typeinf.func_type_data_t()
                    if ftif.get_func_details(fd):
                        rt = fd.rettype
                interesting = bool(rt is not None and not rt.is_void()
                                   and (rt.is_ptr() or rt.is_udt() or rt.is_enum()))
                propagated = 0; ncallers = 0; changes = []
                _GENERIC = {"__int64", "unsigned __int64", "int", "unsigned int",
                            "__int32", "unsigned __int32", "_DWORD", "_QWORD",
                            "_BYTE", "_OWORD", "void *", "char *", "__int64 *",
                            "int *", "_UNKNOWN *", "_DWORD *", "_QWORD *"}
                if interesting:
                    _seen = set()
                    for xr in idautils.XrefsTo(callee):
                        _fn = idaapi.get_func(xr.frm)
                        if not _fn or _fn.start_ea in _seen or _fn.start_ea == callee:
                            continue
                        _seen.add(_fn.start_ea); ncallers += 1
                        try:
                            _cf = idaapi.decompile(_fn.start_ea)
                        except Exception:
                            _cf = None
                        if not _cf:
                            continue
                        _targets = []
                        class _RetV(ida_hexrays.ctree_visitor_t):
                            def __init__(self):
                                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                            def visit_expr(self, e):
                                if e.op == ida_hexrays.cot_asg:
                                    rhs = e.y
                                    while rhs is not None and rhs.op == ida_hexrays.cot_cast:
                                        rhs = rhs.x
                                    if (rhs is not None and rhs.op == ida_hexrays.cot_call
                                            and rhs.x.op == ida_hexrays.cot_obj
                                            and rhs.x.obj_ea == callee
                                            and e.x.op == ida_hexrays.cot_var):
                                        _targets.append(e.x.v.idx)
                                return 0
                        try:
                            _RetV().apply_to(_cf.body, None)
                        except Exception:
                            _targets = []
                        if not _targets:
                            continue
                        _lvs = _cf.get_lvars()
                        for _idx in set(_targets):
                            if _idx < 0 or _idx >= _lvs.size():
                                continue
                            _lv = _lvs[_idx]
                            _old_t = str(_lv.type())
                            if _old_t not in _GENERIC:
                                continue
                            if _set_lvar_type(_fn.start_ea, _lv.name, rt):
                                propagated += 1
                                changes.append({"op": "propagate_ret",
                                                "ea": hex(_fn.start_ea),
                                                "target": _lv.name,
                                                "old": _old_t, "new": str(rt)})
                emit({"ok": True, "result": {"propagated": propagated,
                                             "callers": ncallers, "changes": changes}})
            except Exception as e:
                emit({"ok": False, "error": "propagate_ret: %s" % e})
        elif cmd == "struct_evidence":
            # F — collect field-access evidence for parameter #arg_index of a
            # function: the offsets/sizes/kinds at which that pointer is deref'd.
            try:
                import ida_hexrays
                addr = _norm(a["address"]); arg_index = int(a.get("arg_index", 0))
                cf = idaapi.decompile(addr)
                if not cf:
                    emit({"ok": True, "result": {"evidence": [], "snippet": "",
                                                 "var_name": "", "var_type": ""}})
                else:
                    # find the vector index + name of the arg at positional arg_index
                    lvs = cf.get_lvars()
                    vec_idx = -1; vname = ""; vtype = ""; seen_args = 0
                    for i in range(lvs.size()):
                        lv = lvs[i]
                        if lv.is_arg_var:
                            if seen_args == arg_index:
                                vec_idx = i; vname = lv.name
                                try: vtype = str(lv.type())
                                except Exception: vtype = ""
                                break
                            seen_args += 1
                    ev = _struct_evidence(cf, vec_idx) if vec_idx >= 0 else []
                    # a few pseudocode lines mentioning the var, as naming context
                    snippet = ""
                    if vname:
                        keep = [ln for ln in str(cf).splitlines()
                                if _re_t.search(r"\b%s\b" % _re_t.escape(vname), ln)]
                        snippet = "\n".join(keep[:24])
                    emit({"ok": True, "result": {"evidence": ev, "snippet": snippet,
                                                 "var_name": vname, "var_type": vtype}})
            except Exception as e:
                emit({"ok": False, "error": "struct_evidence: %s" % e})
        elif cmd == "make_struct":
            # F — register a recovered struct from a prebuilt C declaration. The
            # host (core.structs.struct_decl) computes the exact layout; we just
            # parse it into the type library and verify it now exists.
            try:
                import ida_typeinf
                name = a["name"]; decl = a["decl"]
                errs = idc.parse_decls(decl, idc.PT_SIL)
                ok = (errs == 0) and _type_exists(name)
                emit({"ok": True, "result": {"ok": bool(ok), "name": name,
                                             "errors": int(errs),
                                             "dropped": [] if ok else
                                             [{"var": name, "type": "struct",
                                               "reason": "parse_failed" if errs else "not_registered"}]}})
            except Exception as e:
                emit({"ok": False, "error": "make_struct: %s" % e})
        elif cmd == "apply_struct":
            # F — set parameter #arg_index of a function to the recovered struct
            # pointer type, via the prototype (name preserved, type validated +
            # read-back verified by _set_func_proto).
            try:
                addr = _norm(a["address"]); arg_index = int(a.get("arg_index", 0))
                ty = a.get("type", "")
                pd = _set_func_proto(addr, "", {arg_index: {"type": ty}})
                applied = pd.get("arg_types", 0) > 0
                # _set_func_proto already emitted a func_arg change with the old
                # type; re-label it apply_struct so the audit reads as a struct op.
                changes = []
                for ch in pd.get("changes", []):
                    if ch.get("op") == "func_arg":
                        changes.append({"op": "apply_struct",
                                        "target": "arg%d" % arg_index,
                                        "old": ch.get("old", ""), "new": ty})
                if applied:
                    idc.save_database("")
                emit({"ok": True, "result": {"applied": bool(applied),
                                             "dropped": pd.get("dropped", []),
                                             "changes": changes}})
            except Exception as e:
                emit({"ok": False, "error": "apply_struct: %s" % e})
        elif cmd == "list_globals":
            # G — enumerate generic data placeholders (dword_*, byte_*, off_*, …)
            # that have ≥min_xrefs code references; rank/leverage decided host-side.
            # NOTE: idautils.Names() does NOT include auto-generated "dummy" names
            # (dword_*, byte_*, … are exactly those), so we walk the heads of the
            # data segments and read each item's (possibly dummy) name directly.
            try:
                lim = int(a.get("limit", 20000)); minx = int(a.get("min_xrefs", 1))
                out = []
                _CODE = getattr(idaapi, "SEG_CODE", 2)
                for seg_ea in idautils.Segments():
                    seg = idaapi.getseg(seg_ea)
                    if not seg or seg.type == _CODE:
                        continue
                    for head in idautils.Heads(seg.start_ea, seg.end_ea):
                        # only data items, not code that slipped into a data seg
                        if idc.is_code(idc.get_full_flags(head)):
                            continue
                        nm = idc.get_name(head) or ""
                        if not _is_generic_global(nm):
                            continue
                        # full code-xref count drives host-side ranking by leverage
                        nx = sum(1 for xr in idautils.XrefsTo(head, 0)
                                 if idaapi.get_func(xr.frm) is not None)
                        if nx < minx:
                            continue
                        try: sz = int(idc.get_item_size(head))
                        except Exception: sz = 0
                        try: ct = idc.get_type(head) or ""
                        except Exception: ct = ""
                        out.append({"ea": head, "name": nm, "size": sz,
                                    "cur_type": ct, "nxrefs": nx})
                        if len(out) >= lim:
                            break
                    if len(out) >= lim:
                        break
                emit({"ok": True, "result": out})
            except Exception as e:
                emit({"ok": False, "error": "list_globals: %s" % e})
        elif cmd == "global_context":
            # G — for one global, find its referencing functions, rank them by
            # analysis quality (named/typed/signal-rich), and return the top-K with
            # a windowed pseudocode snippet + access kind (read/write/address-taken).
            try:
                import ida_hexrays
                gea = _norm(a["address"]); top_k = int(a.get("top_k", 5))
                gname = idc.get_name(gea) or hex(gea)
                seen = {}
                for xr in idautils.XrefsTo(gea, 0):
                    fn = idaapi.get_func(xr.frm)
                    if not fn or fn.start_ea in seen:
                        continue
                    fea = fn.start_ea
                    fnm = idc.get_func_name(fea) or hex(fea)
                    named = not (fnm.startswith("sub_") or fnm.startswith("j_")
                                 or fnm.startswith("nullsub_"))
                    proto = _proto(fea)
                    napis = 0; nnamed_callees = 0
                    for ea2 in idautils.FuncItems(fea):
                        for cr in idautils.CodeRefsFrom(ea2, 0):
                            tf = idaapi.get_func(cr)
                            cnm = idc.get_func_name(cr) or ""
                            if tf is None or (tf.flags & idaapi.FUNC_THUNK):
                                if cnm and not cnm.startswith("sub_"):
                                    napis += 1
                            elif cnm and not cnm.startswith("sub_") and tf.start_ea != fea:
                                nnamed_callees += 1
                    seen[fea] = {"func_ea": fea, "func_name": fnm, "proto": proto,
                                 "named": named, "typed_proto": bool(proto and "(" in proto),
                                 "napis": napis, "nnamed_callees": nnamed_callees,
                                 "size": fn.size()}
                cands = sorted(seen.values(),
                               key=lambda m: (-_fn_quality(m), -m["size"], m["func_ea"]))
                sites = []
                for m in cands[:top_k]:
                    snippet = ""; access = set()
                    try:
                        cf = idaapi.decompile(m["func_ea"])
                    except Exception:
                        cf = None
                    if cf:
                        keep = [ln for ln in str(cf).splitlines()
                                if _re_t.search(r"\b%s\b" % _re_t.escape(gname), ln)]
                        snippet = "\n".join(keep[:12])
                        class _GV(ida_hexrays.ctree_visitor_t):
                            def __init__(self):
                                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                            def visit_expr(self, e):
                                try:
                                    if e.op == ida_hexrays.cot_asg and e.x is not None:
                                        t = e.x
                                        while t is not None and t.op == ida_hexrays.cot_cast:
                                            t = t.x
                                        if t is not None and t.op == ida_hexrays.cot_obj and t.obj_ea == gea:
                                            access.add("write")
                                    if e.op == ida_hexrays.cot_obj and e.obj_ea == gea:
                                        access.add("read")
                                    if (e.op == ida_hexrays.cot_ref and e.x is not None
                                            and e.x.op == ida_hexrays.cot_obj and e.x.obj_ea == gea):
                                        access.add("address-taken")
                                except Exception:
                                    pass
                                return 0
                        try: _GV().apply_to(cf.body, None)
                        except Exception: pass
                    sites.append({"func_ea": m["func_ea"], "func_name": m["func_name"],
                                  "proto": m["proto"], "snippet": snippet,
                                  "access": sorted(access) or ["read"]})
                try: gsz = int(idc.get_item_size(gea))
                except Exception: gsz = 0
                emit({"ok": True, "result": {"ea": gea, "name": gname, "size": gsz,
                                             "cur_type": idc.get_type(gea) or "",
                                             "nrefs": len(cands), "sites": sites}})
            except Exception as e:
                emit({"ok": False, "error": "global_context: %s" % e})
        elif cmd == "set_global":
            # G — name + type a global. Name first, then type (IDA splits the two);
            # type is validated + read-back verified (E), failures returned, never
            # silently dropped. Existing non-generic type is not clobbered.
            try:
                import ida_typeinf
                gea = _norm(a["address"]); nm = a.get("name", ""); ty = a.get("type", "")
                named = ""; typed = False; dropped = []
                old_name = idc.get_name(gea) or ""
                try: old_type = idc.get_type(gea) or ""
                except Exception: old_type = ""
                if nm and nm.isidentifier():
                    use = nm
                    _ex = idc.get_name_ea_simple(use)
                    if _ex != idc.BADADDR and _ex != gea:
                        for _i in range(1, 100):
                            _c = "%s_%d" % (nm, _i)
                            if idc.get_name_ea_simple(_c) == idc.BADADDR:
                                use = _c; break
                    if idc.set_name(gea, use, idc.SN_NOWARN | idc.SN_NOCHECK):
                        named = use
                if ty:
                    tif, reason = _classify_type(ty)
                    if tif is None:
                        dropped.append({"var": named or nm or hex(gea), "type": ty, "reason": reason})
                    else:
                        ok = ida_typeinf.apply_tinfo(gea, tif, ida_typeinf.TINFO_DEFINITE)
                        chk = ida_typeinf.tinfo_t()
                        if ok and idaapi.get_tinfo(chk, gea) and _ty_match(str(chk), ty):
                            typed = True
                        else:
                            dropped.append({"var": named or nm or hex(gea), "type": ty,
                                            "reason": "verify_mismatch"})
                changes = []
                if named:
                    changes.append({"op": "global_name", "old": old_name, "new": named})
                if typed:
                    changes.append({"op": "global_type", "old": old_type, "new": ty})
                if named or typed:
                    idc.save_database("")
                emit({"ok": True, "result": {"named": named, "typed": typed,
                                             "dropped": dropped, "changes": changes}})
            except Exception as e:
                emit({"ok": False, "error": "set_global: %s" % e})
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

            typed_call_sites = []
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

                # Typed call sites: decompile each unique caller and extract the
                # pseudocode line that calls our function.  The decompiler shows the
                # actual argument types/casts as inferred by Hex-Rays, so the LLM
                # can use them to assign proper struct/enum types to our parameters.
                # Best-effort: silently skipped when Hex-Rays is unavailable.
                try:
                    import ida_hexrays as _hr
                    try: _hr.init_hexrays_plugin()
                    except Exception: pass
                    _fn_nm = idc.get_func_name(fn.start_ea) or ""
                    _done_callers = set()
                    for _xr in idautils.XrefsTo(fn.start_ea):
                        if len(typed_call_sites) >= 5:
                            break
                        _cfn = idaapi.get_func(_xr.frm)
                        if not _cfn or _cfn.start_ea in _done_callers:
                            continue
                        _done_callers.add(_cfn.start_ea)
                        _cnm = idc.get_func_name(_cfn.start_ea) or hex(_cfn.start_ea)
                        try:
                            _cf = _hr.decompile(_cfn.start_ea)
                            if not _cf:
                                continue
                            for _ln in str(_cf).splitlines():
                                _ls = _ln.strip()
                                if _fn_nm and _fn_nm in _ls and "(" in _ls:
                                    typed_call_sites.append("%s: %s" % (_cnm, _ls))
                                    break
                        except Exception:
                            continue
                except (ImportError, AttributeError, Exception):
                    pass

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
                "typed_call_sites": typed_call_sites,
            }})
        elif cmd == "rename":
            target_ea = _norm(a["address"])
            name = a["name"]
            # Make name globally unique: if already used at a different address,
            # try name_1, name_2, … so we never silently collide.
            _ex = idc.get_name_ea_simple(name)
            if _ex != idc.BADADDR and _ex != target_ea:
                for _i in range(1, 100):
                    _c = f"{name}_{_i}"
                    if idc.get_name_ea_simple(_c) == idc.BADADDR:
                        name = _c; break
            ok = idc.set_name(target_ea, name, idc.SN_NOWARN | idc.SN_NOCHECK)
            # Return the actual name used so callers can update their display.
            emit({"ok": True, "result": name if ok else False})
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
        elif cmd == "entry_point":
            found = None
            _lflags = idc.get_inf_attr(idc.INF_LFLAGS)
            _is_dll = bool(_lflags & 0x4)  # LFLG_IS_DLL
            if _is_dll:
                # DLL: first named export that isn't DllMain, then any export
                _exports = [(ea, nm) for _, _, ea, nm in idautils.Entries()
                            if ea != idc.BADADDR]
                for ea, nm in _exports:
                    if nm and nm != "DllMain":
                        found = ea; break
                if found is None and _exports:
                    found = _exports[0][0]
            else:
                # EXE: well-known entry names > PE entry table > INF_MAIN > INF_START_EA
                _ENTRY_NAMES = (
                    "main", "wmain", "_main", "WinMain", "wWinMain", "DllMain",
                    "_WinMain@16", "mainCRTStartup", "WinMainCRTStartup",
                    "wWinMainCRTStartup", "wmainCRTStartup", "start", "_start",
                )
                for nm in _ENTRY_NAMES:
                    ea = idc.get_name_ea_simple(nm)
                    if ea != idc.BADADDR:
                        found = ea; break
                if found is None:
                    for _, _, ea, nm in idautils.Entries():
                        if ea != idc.BADADDR:
                            found = ea; break
                if found is None:
                    for attr in (idc.INF_MAIN, idc.INF_START_EA):
                        try:
                            ea = idc.get_inf_attr(attr)
                            if ea and ea != idc.BADADDR:
                                found = ea; break
                        except Exception:
                            pass
            emit({"ok": True, "result": hex(found) if found is not None else None})
        elif cmd == "lumina_probe":
            import os as _os, tempfile as _tf
            # Load lumina plugin by full path — load_plugin("lumina") resolves
            # relative to cwd, not the IDA dir, so we must be explicit.
            _ida_dir = sys.argv[1]  # IDA installation directory
            _lumina_dll = _os.path.join(_ida_dir, "plugins", "lumina.dll")
            try: idaapi.load_plugin(_lumina_dll)
            except Exception: pass
            # Collect ALL lumina-related symbols from idaapi and idc
            idaapi_all = sorted(x for x in dir(idaapi) if "lumina" in x.lower())
            idc_all    = sorted(x for x in dir(idc)    if "lumina" in x.lower())
            # Separate callables from constants
            callables  = [x for x in idaapi_all if callable(getattr(idaapi, x, None))]
            constants  = [x for x in idaapi_all if not callable(getattr(idaapi, x, None))]
            report = {
                "idaapi_callables": callables,
                "idaapi_constants": constants,
                "idc_lumina": idc_all,
            }
            # Write full report to a temp file so nothing is truncated
            _log = _tf.mktemp(prefix="spectrida_lumina_", suffix=".json")
            try:
                import json as _j
                with open(_log, "w") as _f:
                    _j.dump(report, _f, indent=2)
                report["log_file"] = _log
            except Exception: pass
            emit({"ok": True, "result": report})
        elif cmd == "binary_context":
            info = idaapi.get_inf_structure()
            bits = "64" if info.is_64bit() else "32"
            arch = info.procName.strip() or "unknown"
            ibase = idaapi.get_imagebase()
            fname = idc.get_input_file_path() or ""
            import os as _os
            _lflags = idc.get_inf_attr(idc.INF_LFLAGS)
            _is_dll = bool(_lflags & 0x4)
            _kind = "DLL" if _is_dll else "EXE"
            lines = [
                f"File: {_os.path.basename(fname)}  |  PE{bits}, {arch}, {_kind}  |  ImageBase: {ibase:#x}",
            ]
            # For DLLs: exports are the primary interface — show them first
            _exports = [(ord_n, ea, nm) for _, ord_n, ea, nm in idautils.Entries()
                        if ea != idc.BADADDR]
            if _is_dll and _exports:
                lines.append("")
                lines.append("Exports (public API of this DLL):")
                for ord_n, ea, nm in _exports[:60]:
                    label = nm if nm else f"ord_{ord_n}"
                    lines.append(f"  [{ord_n}] {label}")
                if len(_exports) > 60:
                    lines.append(f"  ... and {len(_exports)-60} more")
            # Imports sorted by call frequency
            lines.append("")
            lines.append("Imports (sorted by call frequency):")
            total_dlls = 0
            qty = idaapi.get_import_module_qty()
            for i in range(qty):
                dll = idaapi.get_import_module_name(i) or f"module_{i}"
                entries = []
                def _cb(ea, nm, ord_n, _e=entries):
                    if nm: _e.append((ea, nm))
                    return True
                idaapi.enum_import_names(i, _cb)
                if not entries:
                    continue
                counted = sorted(
                    ((nm, len(list(idautils.XrefsTo(ea)))) for ea, nm in entries),
                    key=lambda x: -x[1]
                )[:20]
                parts = [f"{nm}({n})" if n else nm for nm, n in counted]
                lines.append(f"  {dll}: {', '.join(parts)}")
                total_dlls += 1
                if total_dlls >= 40:
                    lines.append("  ... (truncated)")
                    break
            # For EXEs: exports at the bottom (rare but possible)
            if not _is_dll:
                lines.append("")
                exp_names = [nm for _, _, nm in _exports if nm][:20]
                lines.append(f"Exports: {', '.join(exp_names)}" if exp_names else "Exports: (none)")
            emit({"ok": True, "result": "\n".join(lines)})
        elif cmd == "get_local_types":
            # Enumerate user-defined structs, unions, and enums from the IDA
            # local type library.  Names are added to the binary context so the
            # LLM knows what types exist and can use them when assigning parameter
            # and variable types.  Compiler-internal names (starting with _ $ tag)
            # and common Windows handle stubs are filtered out.
            try:
                import ida_typeinf as _iti
                _ti = _iti.get_idati()
                _total = _iti.get_ordinal_count(_ti)
                _structs, _enums = [], []
                _skip_pfx = ("_", "$", "tag", "GUID", "IID", "CLSID",
                             "HINSTANCE__", "HWND__", "HDC__", "HKEY__")
                for _i in range(1, min(_total + 1, 3001)):
                    try:
                        _nm = _iti.get_numbered_type_name(_ti, _i)
                        if not _nm or any(_nm.startswith(_p) for _p in _skip_pfx):
                            continue
                        _tif = _iti.tinfo_t()
                        if not _iti.get_numbered_type(_ti, _i, _tif):
                            continue
                        # carry field count + byte size so the model can pick the
                        # struct/enum that fits the access pattern (cheap: this rides
                        # in the cached system prefix, computed once per session).
                        try: _sz = int(_tif.get_size())
                        except Exception: _sz = 0
                        if _tif.is_struct() or _tif.is_union():
                            try: _nf = int(_tif.get_udt_nmembers())
                            except Exception: _nf = -1
                            _structs.append({"name": _nm, "fields": _nf, "size": _sz})
                        elif _tif.is_enum():
                            try: _nm_ct = int(_tif.get_enum_nmembers())
                            except Exception: _nm_ct = -1
                            _enums.append({"name": _nm, "members": _nm_ct, "size": _sz})
                    except Exception:
                        continue
                # richest (most fields) first, so the long tail of trivial structs
                # is what gets truncated, not the meaningful ones
                _structs.sort(key=lambda s: -s.get("fields", 0))
                emit({"ok": True, "result": {
                    "structs": _structs[:300], "enums": _enums[:150]
                }})
            except Exception as _e:
                emit({"ok": True, "result": {"structs": [], "enums": [], "note": str(_e)}})
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
    def __init__(self, proc: asyncio.subprocess.Process, i64: str,
                 script_path: str | None = None) -> None:
        self._proc = proc
        self.i64 = i64
        self._script_path = script_path   # temp worker .py to clean up on close
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
        # remove the temp worker script
        if self._script_path:
            try:
                os.unlink(self._script_path)
            except Exception:
                pass
            self._script_path = None


_STREAM_LIMIT = 128 * 1024 * 1024  # 128 MB — list of 150k funcs is ~12 MB as JSON


async def open_ida(i64_path: str) -> IDAHandle:
    ida = idalib_dir()
    if not ida:
        raise RuntimeError("idalib not configured - run: spectrida onboard")
    # Run the worker from a temp .py file rather than `python -c <src>`: the
    # inline form puts the whole script on the command line, which on Windows
    # blows past the ~32 KB limit (WinError 206). argv stays [script, ida, i64],
    # so the worker's argv[1]/argv[2] indexing is unchanged.
    fd, script_path = tempfile.mkstemp(suffix=".py", prefix="spectrida_worker_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(_WORKER)
        proc = await asyncio.create_subprocess_exec(
            sys.executable, script_path, str(Path(ida).resolve()), i64_path,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, env=_idalib_env(),
            limit=_STREAM_LIMIT,
        )
    except BaseException:
        try:
            os.unlink(script_path)
        except Exception:
            pass
        raise
    handle = IDAHandle(proc, i64_path, script_path=script_path)
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

async def rename(ida: IDAHandle, address: str | int, new_name: str) -> str | bool:
    """Rename function. Returns the actual name used (may differ if deduped), or False."""
    try:
        result = await ida.call("rename", address=_hex(address), name=new_name)
        # result is either a bool (old worker) or the actual name string (new worker)
        if isinstance(result, str):
            if result:
                await ida.call("save")
            return result or False
        ok = bool(result)
        if ok:
            await ida.call("save")
        return ok
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

async def get_entry_point(ida: IDAHandle) -> int | None:
    """Return the best-guess entry point address (WinMain/main/PE entry), or None."""
    try:
        raw = await ida.call("entry_point")
        return int(raw, 16) if raw else None
    except Exception:
        return None


async def lumina_probe(ida: IDAHandle) -> list[str] | None:
    """Return list of public names in ida_lumina, or None if unavailable."""
    try:
        return await ida.call("lumina_probe")
    except Exception:
        return None


async def get_binary_context(ida: IDAHandle) -> str:
    """Return a static one-line-per-import summary for the KV-cache system prefix."""
    try:
        return await ida.call("binary_context") or ""
    except Exception:
        return ""

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

async def get_local_types(ida: IDAHandle) -> dict:
    """Return {"structs": [...], "enums": [...]} — user-defined types from IDA type library."""
    try:
        return await ida.call("get_local_types") or {}
    except Exception:
        return {}

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
        return {"renamed": 0, "retyped": 0, "ret_type": "", "dropped": [],
                "changes": [], "pseudocode": ""}


async def propagate_ret(ida: IDAHandle, address: str | int) -> dict:
    """Push a function's (interesting) return type onto caller variables that hold
    its result. Returns {"propagated": N, "callers": M}."""
    try:
        result = await ida.call("propagate_ret", address=_hex(address))
        if result.get("propagated"):
            await ida.call("save")
        return result
    except Exception:
        return {"propagated": 0, "callers": 0, "changes": []}


async def struct_evidence(ida: IDAHandle, address: str | int, arg_index: int = 0) -> dict:
    """Harvest field-access evidence for parameter *arg_index* of a function.

    Returns {"evidence": [{offset,size,kind}], "snippet": str, "var_name": str,
    "var_type": str}. Empty when there's no decompiler or no such argument."""
    try:
        return await ida.call("struct_evidence", address=_hex(address), arg_index=arg_index)
    except Exception:
        return {"evidence": [], "snippet": "", "var_name": "", "var_type": ""}


async def make_struct(ida: IDAHandle, name: str, decl: str) -> dict:
    """Register a recovered struct from a C declaration. Returns
    {"ok": bool, "name": str, "errors": int, "dropped": [...]}."""
    try:
        result = await ida.call("make_struct", name=name, decl=decl)
        if result.get("ok"):
            await ida.call("save")
        return result
    except Exception as e:
        return {"ok": False, "name": name, "errors": -1,
                "dropped": [{"var": name, "type": "struct", "reason": str(e)}]}


async def apply_struct(ida: IDAHandle, address: str | int, arg_index: int,
                       type_str: str) -> dict:
    """Set parameter *arg_index* of the function to *type_str* (the recovered
    ``Struct *``). Returns {"applied": bool, "dropped": [...]}."""
    try:
        return await ida.call("apply_struct", address=_hex(address),
                              arg_index=arg_index, type=type_str)
    except Exception:
        return {"applied": False, "dropped": [], "changes": []}


async def list_globals(ida: IDAHandle, min_xrefs: int = 1, limit: int = 5000) -> list[dict]:
    """Enumerate generic data placeholders (dword_*, byte_*, …) with ≥min_xrefs
    code references. Each: {ea, name, size, cur_type, nxrefs}."""
    try:
        return await ida.call("list_globals", min_xrefs=min_xrefs, limit=limit)
    except Exception:
        return []


async def global_context(ida: IDAHandle, address: str | int, top_k: int = 5) -> dict:
    """Top-K best-understood referencing functions for a global, with snippets +
    access kinds. Returns {ea, name, size, cur_type, nrefs, sites: [...]}."""
    try:
        return await ida.call("global_context", address=_hex(address), top_k=top_k)
    except Exception:
        return {"ea": 0, "name": "", "size": 0, "cur_type": "", "nrefs": 0, "sites": []}


async def set_global(ida: IDAHandle, address: str | int, name: str,
                     type_str: str = "") -> dict:
    """Name + type a global (name first, then type — validated + read-back). Returns
    {"named": actual_name|"", "typed": bool, "dropped": [...]}."""
    try:
        return await ida.call("set_global", address=_hex(address),
                              name=name, type=type_str)
    except Exception:
        return {"named": "", "typed": False, "dropped": [], "changes": []}


def _hex(address: str | int) -> str:
    return hex(address) if isinstance(address, int) else str(address)
