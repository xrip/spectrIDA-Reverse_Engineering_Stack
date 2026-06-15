"""G — global variable naming/typing: pure helpers + demo integration."""
import asyncio

from spectrida.api import open_demo
from spectrida.core import demo
from spectrida.core.globals import (
    function_quality,
    is_generic_global,
    rank_functions,
    rank_globals,
)


# ── is_generic_global ────────────────────────────────────────────────────────

def test_is_generic_global_true():
    assert is_generic_global("dword_140C00010")
    assert is_generic_global("byte_140030020")
    assert is_generic_global("off_401000")
    assert is_generic_global("unk_ABCDEF")
    assert is_generic_global("qword_140001000")
    assert is_generic_global("flt_408000")


def test_is_generic_global_false():
    assert not is_generic_global("WinMain")
    assert not is_generic_global("g_PlayerList")     # g_ carries analyst intent
    assert not is_generic_global("sub_140001000")    # a function, not data
    assert not is_generic_global("")
    assert not is_generic_global("dword_")           # no hex suffix
    assert not is_generic_global("dword_xyz")        # suffix not hex


# ── function_quality ─────────────────────────────────────────────────────────

def test_function_quality_named_beats_stub():
    rich = {"named": True, "typed_proto": True, "napis": 4, "nstrings": 2,
            "nnamed_callees": 3, "size": 400}
    stub = {"named": False, "typed_proto": False, "napis": 0, "nstrings": 0,
            "nnamed_callees": 0, "size": 80}
    assert function_quality(rich) > function_quality(stub)


def test_function_quality_penalises_huge_body():
    small = {"named": True, "typed_proto": True, "size": 300}
    huge  = {"named": True, "typed_proto": True, "size": 9000}
    assert function_quality(small) > function_quality(huge)


def test_function_quality_handles_partial_meta():
    # missing keys default to 0/False, no crash
    assert function_quality({}) == 0.0
    assert function_quality({"named": True}) == 5.0


def test_function_quality_caps_signal():
    a = {"napis": 6}
    b = {"napis": 600}
    assert function_quality(a) == function_quality(b)   # capped at 6


# ── rank_functions / rank_globals ────────────────────────────────────────────

def test_rank_functions_best_first():
    funcs = [
        {"func_ea": 1, "named": False, "size": 100},
        {"func_ea": 2, "named": True, "typed_proto": True, "napis": 5, "size": 200},
        {"func_ea": 3, "named": True, "size": 150},
    ]
    ranked = rank_functions(funcs, top_k=2)
    assert [f["func_ea"] for f in ranked] == [2, 3]


def test_rank_globals_by_xrefs():
    gs = [
        {"ea": 0x10, "nxrefs": 1, "size": 4},
        {"ea": 0x20, "nxrefs": 40, "size": 4},
        {"ea": 0x30, "nxrefs": 7, "size": 8},
    ]
    ranked = rank_globals(gs)
    assert [g["ea"] for g in ranked] == [0x20, 0x30, 0x10]


# ── demo integration ─────────────────────────────────────────────────────────

def test_name_globals_demo():
    async def run():
        async with open_demo() as db:
            done_infos = []

            async def progress_cb(done, total, info):
                if info.get("phase") == "done":
                    done_infos.append(info)

            totals = await db.name_globals(min_xrefs=2, progress_cb=progress_cb)
            assert totals["globals"] >= 1
            assert totals["named"] >= 1
            assert totals["typed"] >= 1
            # the hot global was named + typed
            hit = [r for r in done_infos if r["name"] == "g_player_count"]
            assert hit and hit[0]["type"] == "int"
            # and it landed in the project glossary
            assert 0x140030010 in db._glossary.names
    asyncio.run(run())


def test_name_globals_phases_emitted():
    async def run():
        async with open_demo() as db:
            phases = []

            async def progress_cb(done, total, info):
                phases.append(info.get("phase"))

            await db.name_globals(min_xrefs=2, progress_cb=progress_cb)
            assert phases[0] == "enumerated"
            assert "analyze" in phases
            assert "done" in phases
    asyncio.run(run())


def test_name_globals_min_xrefs_filters():
    async def run():
        async with open_demo() as db:
            # off_140030020 has nxrefs=1 → excluded by min_xrefs=2
            names = []

            async def progress_cb(done, total, info):
                if info.get("name"):
                    names.append(info["name"])

            await db.name_globals(min_xrefs=2, progress_cb=progress_cb)
            assert "off_140030020" not in names
    asyncio.run(run())


def test_name_globals_bad_type_dropped(monkeypatch):
    async def run():
        async with open_demo() as db:
            def bad(global_info, sites, glossary=""):
                return {"name": "g_player_count", "type": "NoSuchStruct *",
                        "reason": "x"}
            monkeypatch.setattr(demo, "name_global", bad)

            totals = await db.name_globals(min_xrefs=2)
            assert totals["dropped"] >= 1
            assert totals["named"] >= 1          # name still applied
            assert totals["typed"] == 0          # bad type not applied
    asyncio.run(run())


def test_name_globals_uses_cache(monkeypatch):
    async def run():
        async with open_demo() as db:
            calls = {"n": 0}
            orig = demo.name_global

            def counting(gi, sites, glossary=""):
                calls["n"] += 1
                return orig(gi, sites, glossary)
            monkeypatch.setattr(demo, "name_global", counting)

            await db.name_globals(min_xrefs=2)
            first = calls["n"]
            assert first >= 1
            # second run over the same use-site shape → cache hit, no model call
            sources = []

            async def progress_cb(done, total, info):
                if info.get("phase") == "done":
                    sources.append(info.get("source"))

            await db.name_globals(min_xrefs=2, progress_cb=progress_cb)
            assert calls["n"] == first            # model not called again
            assert "cache" in sources
    asyncio.run(run())


def test_name_globals_cache_bypass(monkeypatch):
    async def run():
        async with open_demo() as db:
            calls = {"n": 0}
            orig = demo.name_global

            def counting(gi, sites, glossary=""):
                calls["n"] += 1
                return orig(gi, sites, glossary)
            monkeypatch.setattr(demo, "name_global", counting)

            await db.name_globals(min_xrefs=2)
            first = calls["n"]
            await db.name_globals(min_xrefs=2, use_cache=False)
            assert calls["n"] > first             # bypass → model called again
    asyncio.run(run())


def test_name_globals_disabled(monkeypatch):
    monkeypatch.setenv("SPECTRIDA_GLOBAL_NAMING", "0")

    async def run():
        async with open_demo() as db:
            totals = await db.name_globals(min_xrefs=2)
            assert totals == {"globals": 0, "named": 0, "typed": 0, "dropped": 0}
    asyncio.run(run())
