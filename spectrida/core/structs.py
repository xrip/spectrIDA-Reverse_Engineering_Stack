"""Pure struct-layout helpers — no IDA dependency, fully unit-testable.

Struct recovery (F) is a *collect-then-synthesise* pass: the in-IDA worker
harvests raw ``{offset, size, kind}`` field-access tuples for one base pointer
from every function that dereferences it, and THIS module reconciles those
observations into a concrete, non-overlapping field layout. The layout is
computed deterministically from observed offsets — never hallucinated — so the
LLM only ever names fields / refines scalar types, it cannot move them.

The worker (`core/ida.py` ``_WORKER``) can't import this module (idalib-only
``sys.path``); ``make_struct`` re-derives padding from the field offsets so a
worker/host mismatch can't produce a corrupt layout.
"""
from __future__ import annotations

import hashlib

# Access size (bytes) → default C scalar. IDA's ``_BYTE``/``_WORD``/``_DWORD``/
# ``_QWORD`` are builtins (see core.types.BUILTIN_TYPES) so they always parse.
_SIZE_SCALAR: dict[int, str] = {1: "_BYTE", 2: "_WORD", 4: "_DWORD", 8: "_QWORD"}

# Pointer width — an 8-byte access that is itself dereferenced is a pointer field.
_PTR_SIZE = 8


def size_to_type(size: int, *, is_pointer: bool = False) -> str:
    """Default C type for a field of *size* bytes.

    A pointer field becomes ``void *``; a power-of-two scalar maps to the IDA
    ``_BYTE``/.../``_QWORD`` builtins; any other width becomes a byte array.
    """
    if is_pointer:
        return "void *"
    if size in _SIZE_SCALAR:
        return _SIZE_SCALAR[size]
    return "_BYTE"   # array width carried separately (flags=["array"])


def field_name(offset: int) -> str:
    """IDA-style default member name for a field at *offset* (e.g. ``field_40``)."""
    return "field_%X" % offset


def reconcile_fields(evidence: list[dict]) -> list[dict]:
    """Reconcile raw field-access observations into an ordered, non-overlapping
    struct field layout.

    *evidence* = ``[{"offset", "size", "kind"}, …]`` — kind ∈ read / write /
    deref / access; many entries may share an offset. Returns an offset-sorted
    list of field dicts::

        {"offset", "size", "name", "type", "is_pointer", "flags": [...]}

    Rules (deterministic — same input always yields the same layout):
      * widest observed access at an offset wins;
      * an access that overlaps an already-placed wider field is dropped, and the
        wider field is flagged ``union_candidate`` (we never emit overlapping
        members — union recovery is left for a later refinement);
      * gaps between fields are filled with explicit ``_BYTE pad_<off>[n]`` padding
        members so the on-disk layout is exact;
      * an 8-byte access seen with kind ``deref`` (the value is itself
        dereferenced) becomes a ``void *`` pointer field.
    """
    # 1. fold observations by offset: widest size wins; remember kinds seen
    by_off: dict[int, dict] = {}
    for ev in evidence or []:
        try:
            off = int(ev.get("offset"))
            size = int(ev.get("size"))
        except (TypeError, ValueError):
            continue
        if off < 0 or size <= 0 or size > 0x1000:
            continue
        kind = str(ev.get("kind") or "access")
        slot = by_off.get(off)
        if slot is None:
            by_off[off] = {"offset": off, "size": size, "kinds": {kind}}
        else:
            slot["size"] = max(slot["size"], size)
            slot["kinds"].add(kind)

    # 2. walk offsets in order, dropping overlaps and inserting padding
    fields: list[dict] = []
    pos = 0
    for off in sorted(by_off):
        slot = by_off[off]
        if off < pos:
            # overlaps the previously placed field → don't emit; flag the prior
            if fields:
                _add_flag(fields[-1], "union_candidate")
            continue
        if off > pos:
            gap = off - pos
            fields.append({
                "offset": pos, "size": gap,
                "name": "pad_%X" % pos, "type": "_BYTE",
                "is_pointer": False, "flags": ["padding", "array"],
            })
        size = slot["size"]
        is_ptr = (size == _PTR_SIZE and "deref" in slot["kinds"])
        flags: list[str] = []
        if size not in _SIZE_SCALAR:
            flags.append("array")
        if "write" in slot["kinds"]:
            flags.append("written")
        fields.append({
            "offset": off, "size": size,
            "name": field_name(off),
            "type": size_to_type(size, is_pointer=is_ptr),
            "is_pointer": is_ptr, "flags": flags,
        })
        pos = off + size
    return fields


def _add_flag(field: dict, flag: str) -> None:
    flags = field.setdefault("flags", [])
    if flag not in flags:
        flags.append(flag)


def struct_signature(fields: list[dict]) -> str:
    """Content hash of a layout's SHAPE — the sorted ``(offset, size)`` set of its
    real (non-padding) members. Two pointers dereferenced at the same offsets
    collapse to one signature, so clones / shared base classes reuse a single
    recovered struct instead of spawning duplicates. Field names/types are
    excluded so renaming never changes identity.
    """
    shape = sorted(
        (int(f["offset"]), int(f["size"]))
        for f in fields
        if "padding" not in (f.get("flags") or [])
    )
    h = hashlib.sha1(repr(shape).encode("utf-8"))
    return h.hexdigest()[:16]


def merge_field_names(fields: list[dict], named: dict) -> list[dict]:
    """Apply the model's ``{offset: {name, type}}`` onto a reconciled layout,
    keeping offsets/sizes FIXED.

    *named* keys may be ints or hex/decimal strings. A proposed name must be a
    valid C identifier; a proposed type may refine the scalar but the host still
    re-validates it in IDA. Padding members are never renamed. Returns a new list;
    *fields* is not mutated.
    """
    def _key(o: int) -> dict | None:
        for k in (o, str(o), hex(o), "%X" % o, "0x%X" % o):
            if k in named:
                v = named[k]
                return v if isinstance(v, dict) else {"name": v}
        return None

    out: list[dict] = []
    for f in fields:
        nf = dict(f)
        nf["flags"] = list(f.get("flags") or [])
        if "padding" not in nf["flags"]:
            spec = _key(int(f["offset"]))
            if spec:
                nm = spec.get("name") or ""
                ty = spec.get("type") or ""
                if isinstance(nm, str) and nm.isidentifier():
                    nf["name"] = nm
                # only let the model change the type when it preserves the width
                # (array/padding excluded); width mismatches are ignored here and
                # re-checked in IDA.
                if (isinstance(ty, str) and ty.strip()
                        and "array" not in nf["flags"]):
                    nf["type"] = ty.strip()
                    nf["is_pointer"] = "*" in ty
        out.append(nf)
    return out


def struct_decl(name: str, fields: list[dict]) -> str:
    """Render a C ``struct`` declaration from a reconciled layout, re-deriving
    padding from offsets so the layout is exact regardless of how *fields* was
    built. Used by the worker to ``parse_decls`` the type into IDA.
    """
    lines = ["struct %s" % name, "{"]
    pos = 0
    for f in sorted(fields, key=lambda x: int(x["offset"])):
        off = int(f["offset"]); size = int(f["size"])
        if off < pos:
            continue  # overlap — already excluded by reconcile, belt-and-braces
        if off > pos:
            lines.append("  _BYTE _pad_%X[%d];" % (pos, off - pos))
        nm = f.get("name") or field_name(off)
        ty = f.get("type") or size_to_type(size, is_pointer=f.get("is_pointer"))
        flags = f.get("flags") or []
        if "array" in flags or "padding" in flags:
            # byte array spanning the access width
            base = ty if ty and "*" not in ty else "_BYTE"
            lines.append("  %s %s[%d];" % (base, nm, size))
        else:
            lines.append("  %s %s;" % (ty, nm))
        pos = off + size
    lines.append("};")
    return "\n".join(lines)
