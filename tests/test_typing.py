"""E — typing: dropped (unapplied) types are reported, not silently lost."""
import asyncio

from spectrida.core import demo
from spectrida.api import open_demo


def test_demo_rename_lvars_reports_bad_type():
    addr = demo.FUNCTIONS[3]["start"]            # a sub_* with demo lvars
    lvars = demo.get_lvars(addr)["lvars"]
    assert lvars, "demo function should expose lvars"
    name = lvars[0]["name"]
    # a malformed type must be reported as dropped, a good one applied
    res = demo.rename_lvars(addr, {name: {"name": "buf", "type": "?bad?"}})
    assert res["retyped"] == 0
    assert res["dropped"] and res["dropped"][0]["reason"] == "parse_failed"
    assert res["dropped"][0]["type"] == "?bad?"

    res2 = demo.rename_lvars(addr, {name: {"name": "buf2", "type": "uint8_t *"}})
    assert res2["retyped"] == 1
    assert res2["dropped"] == []


def test_demo_classify_unknown_type():
    from spectrida.core.demo import _demo_classify_type
    assert _demo_classify_type("int") == ""
    assert _demo_classify_type("Entity *") == ""          # in demo's type library
    assert _demo_classify_type("Whatsit *") == "unknown_type:Whatsit"
    assert _demo_classify_type("@@bad@@") == "parse_failed"


def test_type_retry_resolves_unknown_type(monkeypatch):
    """With SPECTRIDA_TYPE_RETRY=1, an unknown-struct type is replaced and applied."""
    monkeypatch.setenv("SPECTRIDA_TYPE_RETRY", "1")

    async def run():
        async with open_demo() as db:
            addr = demo.FUNCTIONS[3]["start"]
            lvars = (await db._b.get_lvars(addr))["lvars"]
            var = lvars[0]["name"]

            def fake_staged(pseudocode, lvars, callees, callers, history=None, glossary=""):
                return {"name": "decode_frame", "reason": "demo", "ret_type": "void",
                        "variables": {var: {"name": var, "type": "Whatsit *"}}}
            monkeypatch.setattr(demo, "name_function_staged", fake_staged)

            calls = {"n": 0}
            orig_correct = demo.correct_types
            def counting_correct(pc, failed):
                calls["n"] += 1
                return orig_correct(pc, failed)
            monkeypatch.setattr(demo, "correct_types", counting_correct)

            r = await db.name_all(addr, rename=True)
            assert calls["n"] == 1                       # corrective call happened
            assert not r["dropped"]                      # unknown type was fixed
            assert r["retyped_vars"] >= 1

    asyncio.run(run())


def test_type_retry_off_by_default(monkeypatch):
    monkeypatch.delenv("SPECTRIDA_TYPE_RETRY", raising=False)

    async def run():
        async with open_demo() as db:
            addr = demo.FUNCTIONS[3]["start"]
            lvars = (await db._b.get_lvars(addr))["lvars"]
            var = lvars[0]["name"]

            def fake_staged(pseudocode, lvars, callees, callers, history=None, glossary=""):
                return {"name": "decode_frame", "reason": "demo", "ret_type": "void",
                        "variables": {var: {"name": var, "type": "Whatsit *"}}}
            monkeypatch.setattr(demo, "name_function_staged", fake_staged)
            called = {"n": 0}
            monkeypatch.setattr(demo, "correct_types",
                                lambda pc, f: called.__setitem__("n", called["n"] + 1) or {})

            r = await db.name_all(addr, rename=True)
            assert called["n"] == 0                       # no retry by default
            assert any(d["reason"].startswith("unknown_type") for d in r["dropped"])

    asyncio.run(run())


def test_name_all_surfaces_dropped(monkeypatch):
    """name_all must thread the worker's `dropped` list into its result."""
    async def run():
        async with open_demo() as db:
            addr = demo.FUNCTIONS[3]["start"]
            lvars = (await db._b.get_lvars(addr))["lvars"]
            var = lvars[0]["name"]

            # force the fake model to emit one good + one bad type
            def fake_staged(pseudocode, lvars, callees, callers, history=None, glossary=""):
                return {
                    "name": "decode_frame",
                    "reason": "demo",
                    "ret_type": "void",
                    "variables": {var: {"name": "buf", "type": "@@invalid@@"}},
                }
            monkeypatch.setattr(demo, "name_function_staged", fake_staged)

            r = await db.name_all(addr, rename=True)
            assert "dropped" in r
            assert any(d["reason"] == "parse_failed" for d in r["dropped"])
            assert r["dropped"][0]["type"] == "@@invalid@@"

    asyncio.run(run())
