"""H+I — naming confidence, glossary gating, and the refine pass."""
import asyncio

from spectrida.api import _name_confidence, open_demo
from spectrida.core import demo
from spectrida.core.demo import FUNCTIONS


def test_name_confidence_levels():
    assert _name_confidence("", "pseudocode", {}) == "low"
    assert _name_confidence("process", "pseudocode", {"api_calls": ["x"]}) == "low"   # generic
    assert _name_confidence("decode_aes", "disasm", {}) == "low"                      # no pc, no signal
    assert _name_confidence("decode_aes", "disasm", {"api_calls": ["x"]}) == "medium"
    assert _name_confidence("decode_aes", "pseudocode", {}) == "medium"              # pc, no signal
    assert _name_confidence("decode_aes", "pseudocode", {"strings": ["s"]}) == "high"


def test_low_confidence_name_not_added_to_glossary(monkeypatch):
    async def run():
        async with open_demo() as db:
            addr = next(f["start"] for f in FUNCTIONS if f["name"].startswith("sub_"))

            def generic(pseudocode, lvars, callees, callers, history=None, glossary=""):
                return {"name": "process", "reason": "x", "ret_type": "void", "variables": {}}
            monkeypatch.setattr(demo, "name_function_staged", generic)

            r = await db.name_all(addr, rename=True)
            assert r["confidence"] == "low"
            # gating (I): low-confidence guess must not pollute the glossary
            assert addr not in db._glossary.names

    asyncio.run(run())


def test_refine_pass_re_runs_low_confidence_bypassing_cache(monkeypatch):
    calls = {"n": 0}

    def generic(pseudocode, lvars, callees, callers, history=None, glossary=""):
        calls["n"] += 1
        return {"name": "process", "reason": "x", "ret_type": "void", "variables": {}}
    monkeypatch.setattr(demo, "name_function_staged", generic)

    async def sweep(refine):
        calls["n"] = 0
        async with open_demo() as db:
            totals = await db.batch_name_branches(
                scope="unnamed", revisit_named=False, refine=refine)
        return calls["n"], totals

    async def run():
        c_off, t_off = await sweep(False)
        c_on, t_on = await sweep(True)
        # refine adds a second, cache-bypassing pass over the low-confidence funcs
        assert c_on > c_off
        assert "refined" in t_on

    asyncio.run(run())
