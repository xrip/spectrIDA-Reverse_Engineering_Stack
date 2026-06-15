"""Project change journal — append-only audit log + revert script."""
import asyncio

from spectrida.api import open_demo
from spectrida.core import demo
from spectrida.core.audit import AuditLog


# ── pure AuditLog ────────────────────────────────────────────────────────────

def test_record_and_entries():
    a = AuditLog()
    a.record("rename_func", ea=0x1000, old="sub_1000", new="parse_header")
    assert len(a) == 1
    e = a.entries[0]
    assert e["op"] == "rename_func"
    assert e["ea"] == "0x1000"
    assert e["old"] == "sub_1000" and e["new"] == "parse_header"
    assert "ts" in e


def test_record_changes_stamps_ea():
    a = AuditLog()
    a.record_changes([{"op": "rename_var", "target": "a1", "old": "a1", "new": "buf"}],
                     ea=0x2000)
    assert a.entries[0]["ea"] == "0x2000"
    # a change carrying its own ea (propagation into a caller) wins
    a.record_changes([{"op": "propagate_ret", "ea": "0x3000", "target": "v1",
                       "old": "__int64", "new": "Foo *"}], ea=0x2000)
    assert a.entries[1]["ea"] == "0x3000"


def test_disabled_records_nothing():
    a = AuditLog(enabled=False)
    a.record("rename_func", ea=1, new="x")
    assert len(a) == 0


def test_persist_jsonl_roundtrip(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    a = AuditLog().open(p)
    a.record("rename_func", ea=0x1000, old="sub_1000", new="foo")
    a.record("global_name", ea=0x2000, old="dword_2000", new="g_count")
    # a fresh instance loads the persisted history (append-on-write)
    b = AuditLog().open(p)
    assert len(b) == 2
    assert b.entries[0]["new"] == "foo"
    assert b.entries[1]["new"] == "g_count"


def test_render_and_counts():
    a = AuditLog()
    a.record("rename_func", ea=0x1000, old="sub_1000", new="foo")
    a.record("rename_var", ea=0x1000, target="a1", old="a1", new="buf")
    r = a.render()
    assert "→" in r and "foo" in r
    assert a.counts() == {"rename_func": 1, "rename_var": 1}


def test_revert_script_names_and_order():
    a = AuditLog()
    a.record("rename_func", ea=0x1000, old="sub_1000", new="foo")
    a.record("global_name", ea=0x2000, old="dword_2000", new="g_count")
    a.record("global_type", ea=0x2000, old="", new="int")
    a.record("make_struct", ea=0x1000, new="FooState")
    a.record("rename_var", ea=0x1000, target="a1", old="a1", new="buf")
    s = a.revert_script()
    assert 'idc.set_name(0x1000, "sub_1000"' in s
    assert 'idc.set_name(0x2000, "dword_2000"' in s
    assert "del_struc" in s and "FooState" in s
    assert 'ida_hexrays.rename_lvar(0x1000, "buf", "a1")' in s
    # reverse order: the last-recorded change (rename_var) is reverted first
    assert s.index("rename_lvar") < s.index('set_name(0x1000')


def test_export_revert(tmp_path):
    a = AuditLog()
    a.record("rename_func", ea=0x1000, old="sub_1000", new="foo")
    p = str(tmp_path / "revert.py")
    assert a.export_revert(p) == p
    txt = open(p, encoding="utf-8").read()
    assert "set_name(0x1000" in txt


# ── demo integration: real ops record real before/after ──────────────────────

def test_name_all_records_audit():
    async def run():
        async with open_demo() as db:
            addr = 0x1400013A0     # demo sub_ with pseudocode + lvars
            await db.name_all(addr, rename=True)
            ops = [e["op"] for e in db._audit.entries]
            assert "rename_func" in ops          # sub_ → apply_fall_damage
            assert "rename_var" in ops           # a1 → entity, …
            rn = next(e for e in db._audit.entries if e["op"] == "rename_func")
            assert rn["old"].startswith("sub_")
            assert rn["new"] == "apply_fall_damage"
    asyncio.run(run())


def test_name_globals_records_audit():
    async def run():
        async with open_demo() as db:
            await db.name_globals(min_xrefs=2)
            ops = [e["op"] for e in db._audit.entries]
            assert "global_name" in ops
            assert "global_type" in ops
            gn = next(e for e in db._audit.entries if e["op"] == "global_name")
            assert gn["old"] == "dword_140030010"
            assert gn["new"] == "g_player_count"
    asyncio.run(run())


def test_recover_struct_records_audit():
    async def run():
        async with open_demo() as db:
            await db.recover_struct(0x1400013A0, 0)
            ops = [e["op"] for e in db._audit.entries]
            assert "make_struct" in ops
            assert "apply_struct" in ops
    asyncio.run(run())


def test_audit_disabled(monkeypatch):
    monkeypatch.setenv("SPECTRIDA_AUDIT_LOG", "0")

    async def run():
        async with open_demo() as db:
            await db.name_all(0x1400013A0, rename=True)
            assert len(db._audit) == 0
    asyncio.run(run())
