"""F — struct recovery: pure layout engine + demo integration."""
import asyncio

from spectrida.api import _struct_candidate_type, open_demo
from spectrida.core import demo
from spectrida.core.structs import (
    field_name,
    merge_field_names,
    merge_layouts,
    real_fields,
    reconcile_fields,
    size_to_type,
    struct_decl,
    struct_signature,
)


# ── size → type / names ──────────────────────────────────────────────────────

def test_size_to_type():
    assert size_to_type(1) == "_BYTE"
    assert size_to_type(2) == "_WORD"
    assert size_to_type(4) == "_DWORD"
    assert size_to_type(8) == "_QWORD"
    assert size_to_type(8, is_pointer=True) == "void *"
    assert size_to_type(3) == "_BYTE"          # odd width → byte array base


def test_field_name():
    assert field_name(0x40) == "field_40"
    assert field_name(0) == "field_0"


# ── reconcile_fields ─────────────────────────────────────────────────────────

def test_reconcile_basic_layout_with_padding():
    ev = [
        {"offset": 0x0,  "size": 8, "kind": "deref"},
        {"offset": 0x40, "size": 4, "kind": "write"},
        {"offset": 0x40, "size": 4, "kind": "read"},
    ]
    fields = reconcile_fields(ev)
    real = [f for f in fields if "padding" not in f["flags"]]
    assert [f["offset"] for f in real] == [0x0, 0x40]
    # offset 0 is a pointer (deref) → void *
    assert real[0]["type"] == "void *"
    assert real[0]["is_pointer"] is True
    # offset 0x40 is a 4-byte scalar
    assert real[1]["type"] == "_DWORD"
    assert real[1]["offset"] == 0x40
    # a padding member fills 0x8..0x40
    pads = [f for f in fields if "padding" in f["flags"]]
    assert len(pads) == 1
    assert pads[0]["offset"] == 0x8
    assert pads[0]["size"] == 0x40 - 0x8


def test_reconcile_widest_access_wins():
    ev = [
        {"offset": 0x10, "size": 4, "kind": "read"},
        {"offset": 0x10, "size": 8, "kind": "read"},   # wider — wins
    ]
    fields = reconcile_fields(ev)
    real = [f for f in fields if "padding" not in f["flags"]]
    assert len(real) == 1
    assert real[0]["size"] == 8


def test_reconcile_overlap_flags_union_candidate():
    ev = [
        {"offset": 0x0, "size": 8, "kind": "read"},
        {"offset": 0x4, "size": 4, "kind": "read"},   # overlaps the 8-byte field
    ]
    fields = reconcile_fields(ev)
    real = [f for f in fields if "padding" not in f["flags"]]
    assert len(real) == 1                              # overlap not emitted
    assert "union_candidate" in real[0]["flags"]


def test_reconcile_array_width():
    ev = [{"offset": 0x0, "size": 6, "kind": "read"}]  # non-power-of-two
    fields = reconcile_fields(ev)
    assert "array" in fields[0]["flags"]
    assert fields[0]["size"] == 6


def test_reconcile_ignores_garbage():
    ev = [
        {"offset": -4, "size": 4, "kind": "read"},
        {"offset": 0x0, "size": 0, "kind": "read"},
        {"offset": 0x0, "size": 999999, "kind": "read"},
        {"offset": "x", "size": "y", "kind": "read"},
    ]
    assert reconcile_fields(ev) == []


# ── struct_signature ─────────────────────────────────────────────────────────

def test_signature_same_shape_equal():
    a = reconcile_fields([{"offset": 0, "size": 8, "kind": "read"},
                          {"offset": 0x40, "size": 4, "kind": "read"}])
    b = reconcile_fields([{"offset": 0, "size": 8, "kind": "write"},
                          {"offset": 0x40, "size": 4, "kind": "read"}])
    assert struct_signature(a) == struct_signature(b)


def test_signature_different_shape_differs():
    a = reconcile_fields([{"offset": 0, "size": 8, "kind": "read"}])
    b = reconcile_fields([{"offset": 0, "size": 4, "kind": "read"}])
    assert struct_signature(a) != struct_signature(b)


def test_signature_ignores_names():
    fields = reconcile_fields([{"offset": 0, "size": 4, "kind": "read"}])
    before = struct_signature(fields)
    renamed = merge_field_names(fields, {"0x0": {"name": "health", "type": "float"}})
    assert struct_signature(renamed) == before


# ── merge_field_names ────────────────────────────────────────────────────────

def test_merge_applies_name_and_type():
    fields = reconcile_fields([{"offset": 0x40, "size": 4, "kind": "read"}])
    merged = merge_field_names(fields, {"0x40": {"name": "health", "type": "float"}})
    real = [f for f in merged if "padding" not in f["flags"]]
    assert real[0]["name"] == "health"
    assert real[0]["type"] == "float"


def test_merge_rejects_bad_identifier():
    fields = reconcile_fields([{"offset": 0x0, "size": 4, "kind": "read"}])
    merged = merge_field_names(fields, {"0x0": {"name": "1bad", "type": "float"}})
    real = [f for f in merged if "padding" not in f["flags"]]
    assert real[0]["name"] == "field_0"               # kept default
    assert real[0]["type"] == "float"                 # type still refined


def test_merge_does_not_mutate_input():
    fields = reconcile_fields([{"offset": 0x0, "size": 4, "kind": "read"}])
    merge_field_names(fields, {"0x0": {"name": "health"}})
    real = [f for f in fields if "padding" not in f["flags"]]
    assert real[0]["name"] == "field_0"


# ── struct_decl ──────────────────────────────────────────────────────────────

def test_struct_decl_layout_exact():
    fields = reconcile_fields([
        {"offset": 0x0, "size": 8, "kind": "deref"},
        {"offset": 0x40, "size": 4, "kind": "read"},
    ])
    fields = merge_field_names(fields, {
        "0x0": {"name": "vtable", "type": "void *"},
        "0x40": {"name": "health", "type": "float"},
    })
    decl = struct_decl("EntityState", fields)
    assert decl.startswith("struct EntityState")
    assert "void * vtable;" in decl
    assert "float health;" in decl
    assert "pad_8[56]" in decl                        # 0x40-0x8 = 56 bytes padding


# ── _struct_candidate_type ───────────────────────────────────────────────────

# ── merge_layouts (accumulate by name) ───────────────────────────────────────

def test_merge_layouts_unions_disjoint():
    a = reconcile_fields([{"offset": 0x0, "size": 8, "kind": "deref"},
                          {"offset": 0x40, "size": 4, "kind": "read"}])
    b = reconcile_fields([{"offset": 0x0, "size": 8, "kind": "deref"},
                          {"offset": 0x80, "size": 4, "kind": "read"}])
    m = real_fields(merge_layouts(a, b))
    assert [f["offset"] for f in m] == [0x0, 0x40, 0x80]   # union of both


def test_merge_layouts_monotonic_and_none():
    a = reconcile_fields([{"offset": 0x0, "size": 4, "kind": "read"}])
    # merging with None / a subset never shrinks
    assert len(real_fields(merge_layouts(None, a))) == 1
    assert len(real_fields(merge_layouts(a, a))) == 1


def test_merge_layouts_widest_and_named_win():
    a = reconcile_fields([{"offset": 0x10, "size": 4, "kind": "read"}])
    a = merge_field_names(a, {"0x10": {"name": "count", "type": "int"}})
    b = reconcile_fields([{"offset": 0x10, "size": 8, "kind": "read"}])  # wider, unnamed
    m = real_fields(merge_layouts(a, b))
    assert len(m) == 1
    assert m[0]["size"] == 8              # widest access wins
    assert m[0]["name"] == "count"        # meaningful name preserved over default


def test_struct_candidate_type():
    assert _struct_candidate_type("void *")
    assert _struct_candidate_type("_QWORD")
    assert _struct_candidate_type("__int64")
    assert not _struct_candidate_type("Player *")     # already a named struct
    assert not _struct_candidate_type("float")
    assert not _struct_candidate_type("")


# ── demo integration ─────────────────────────────────────────────────────────

def test_recover_struct_demo():
    async def run():
        async with open_demo() as db:
            addr = 0x1400013A0
            r = await db.recover_struct(addr, 0)
            assert r["ok"]
            assert r["struct"] == "EntityState"
            assert r["fields"] == 2
            assert r["applied"] is True
            assert r["reused"] is False
            assert not r["dropped"]
    asyncio.run(run())


def test_recover_struct_clones_share_one_struct():
    async def run():
        async with open_demo() as db:
            # same evidence shape under a second address → same struct, no growth,
            # no second struct created (clones collapse via merge-by-name)
            demo._DEMO_STRUCT_EVIDENCE[(0x140001999, 0)] = list(
                demo._DEMO_STRUCT_EVIDENCE[(0x1400013A0, 0)])
            try:
                r1 = await db.recover_struct(0x1400013A0, 0)
                r2 = await db.recover_struct(0x140001999, 0)
                assert r1["struct"] == r2["struct"]
                assert r2["new_struct"] is False    # didn't make a second struct
                assert r2["grew"] is False          # identical shape → no new fields
            finally:
                demo._DEMO_STRUCT_EVIDENCE.pop((0x140001999, 0), None)
    asyncio.run(run())


def test_recover_struct_merges_by_name():
    async def run():
        async with open_demo() as db:
            # a different function sees a DIFFERENT slice of the same (model-named)
            # struct → fields accumulate, the struct is not clobbered
            demo._DEMO_STRUCT_EVIDENCE[(0x140001999, 0)] = [
                {"offset": 0x0,  "size": 8, "kind": "deref"},
                {"offset": 0x80, "size": 4, "kind": "read"},
            ]
            try:
                r1 = await db.recover_struct(0x1400013A0, 0)
                assert r1["new_struct"] is True and r1["fields"] == 2
                r2 = await db.recover_struct(0x140001999, 0)
                assert r2["struct"] == r1["struct"]      # same name (demo model)
                assert r2["new_struct"] is False
                assert r2["grew"] is True
                assert r2["added"] == 1
                assert r2["fields"] == 3                 # union {0, 0x40, 0x80}
            finally:
                demo._DEMO_STRUCT_EVIDENCE.pop((0x140001999, 0), None)
    asyncio.run(run())


def test_recover_struct_reenters_typed_param():
    async def run():
        async with open_demo() as db:
            ev = demo._DEMO_STRUCT_EVIDENCE[(0x1400013A0, 0)]
            try:
                r1 = await db.recover_struct(0x1400013A0, 0)   # types a0 = EntityState*
                assert r1["fields"] == 2
                # a later pass: the param is already EntityState*, and a new offset
                # is now observed → re-entry merges it in (not skipped)
                demo._DEMO_STRUCT_EVIDENCE[(0x1400013A0, 0)] = ev + [
                    {"offset": 0xC0, "size": 4, "kind": "read"}]
                r2 = await db.recover_struct(0x1400013A0, 0)
                assert r2["struct"] == "EntityState"
                assert r2["grew"] is True and r2["fields"] == 3
            finally:
                demo._DEMO_STRUCT_EVIDENCE[(0x1400013A0, 0)] = ev
                demo._demo_applied_struct_types.clear()
    asyncio.run(run())


def test_recover_struct_rebuild_reenters_orphan():
    async def run():
        async with open_demo() as db:
            # a struct applied by an earlier run, NOT in our accumulated store
            demo._demo_applied_struct_types[(0x1400013A0, 0)] = "OrphanStruct *"
            demo._DEMO_KNOWN_TYPES.add("OrphanStruct")
            try:
                # reenter_any strips the type, re-harvests raw accesses, and
                # re-derives the struct under its existing name
                r = await db.recover_struct(0x1400013A0, 0, reenter_any=True)
                assert r["ok"]
                assert r["struct"] == "OrphanStruct"
                assert r["fields"] == 2
                assert "OrphanStruct" in db._struct_layouts   # now tracked
            finally:
                demo._demo_applied_struct_types.clear()
                demo._DEMO_KNOWN_TYPES.discard("OrphanStruct")
    asyncio.run(run())


def test_recover_struct_too_few_fields():
    async def run():
        async with open_demo() as db:
            # an address with no evidence → nothing recovered
            r = await db.recover_struct(0x140001600, 0)
            assert r["ok"] is False
            assert r["reason"] == "too_few_fields"
    asyncio.run(run())


def test_apply_struct_unknown_type_dropped():
    async def run():
        async with open_demo() as db:
            # applying an unregistered struct surfaces a dropped entry
            ap = await db._b.apply_struct(0x1400013A0, 0, "NeverRegistered *")
            assert ap["applied"] is False
            assert ap["dropped"]
            assert ap["dropped"][0]["reason"].startswith("unknown_type")
    asyncio.run(run())


def test_recover_structs_sweep_demo():
    async def run():
        async with open_demo() as db:
            totals = await db.recover_structs(scope="all")
            assert totals["structs"] >= 1
            assert totals["fields"] >= 2
            assert totals["applied"] >= 1
    asyncio.run(run())
