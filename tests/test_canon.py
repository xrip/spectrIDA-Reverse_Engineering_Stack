"""C — name-canonicalisation linter: pure helpers + demo integration."""
import asyncio

from spectrida.api import open_demo
from spectrida.core.canon import (
    build_preferences,
    canonical_name,
    default_preferences,
    is_lintable,
    lint_names,
)


# ── is_lintable ──────────────────────────────────────────────────────────────

def test_is_lintable_true():
    assert is_lintable("send_message")
    assert is_lintable("parse_pe_header")
    assert is_lintable("on_player_death")


def test_is_lintable_false():
    assert not is_lintable("memcpy")            # single token
    assert not is_lintable("recv")              # single token (winsock name)
    assert not is_lintable("__chkstk")          # leading underscore / runtime
    assert not is_lintable("_except_handler")   # leading underscore
    assert not is_lintable("WinMain")           # uppercase
    assert not is_lintable("GameManager$$Update")
    assert not is_lintable("Foo::bar")
    assert not is_lintable("")


# ── canonical_name (defaults) ────────────────────────────────────────────────

def test_canonical_default_abbreviation():
    # with no corpus, defaults abbreviate to the conventional RE form
    assert canonical_name("send_message") == "send_msg"
    assert canonical_name("receive_buffer") == "recv_buf"
    assert canonical_name("calculate_length") == "calc_len"


def test_canonical_typo_fix():
    assert canonical_name("recieve_data") == "recv_data"   # typo→receive→recv
    assert canonical_name("parse_lenght_field") == "parse_len_field"


def test_canonical_non_lintable_untouched():
    assert canonical_name("memcpy") == "memcpy"
    assert canonical_name("__chkstk") == "__chkstk"
    assert canonical_name("WinMain") == "WinMain"


# ── build_preferences (data-driven) ──────────────────────────────────────────

def test_preferences_majority_wins():
    # binary uses "message" 3×, "msg" 1× → canonical is "message"
    corpus = ["send_message", "recv_message", "queue_message", "drop_msg"]
    prefs = build_preferences(corpus)
    assert prefs["msg"] == "message"
    assert prefs["message"] == "message"
    assert canonical_name("drop_msg", prefs) == "drop_message"


def test_preferences_abbrev_majority():
    corpus = ["send_msg", "recv_msg", "queue_msg", "drop_message"]
    prefs = build_preferences(corpus)
    assert prefs["message"] == "msg"
    assert canonical_name("drop_message", prefs) == "drop_msg"


def test_preferences_default_when_absent():
    prefs = build_preferences(["parse_header", "build_packet"])
    # no msg/message present → group default ("msg")
    assert prefs["message"] == "msg"


def test_preferences_only_counts_lintable():
    # single-token / library names don't skew counts
    corpus = ["recv", "receive", "poll_receive", "read_receive"]
    prefs = build_preferences(corpus)
    # "receive" appears twice in lintable multi-token names, "recv" zero → receive
    assert prefs["recv"] == "receive"


# ── lint_names ───────────────────────────────────────────────────────────────

def test_lint_names_normalize_and_generic():
    names = ["send_message", "send_msg", "process"]
    prefs = build_preferences(names)
    out = lint_names(names, prefs)
    reasons = {o["current"]: o for o in out}
    # majority msg(1) vs message(1) tie → default msg; send_message → send_msg
    assert reasons["send_message"]["suggested"] == "send_msg"
    assert reasons["send_message"]["reason"] == "normalize"
    assert reasons["process"]["reason"] == "generic"
    assert reasons["process"]["suggested"] == ""


def test_lint_names_dedups():
    # a typo is always fixed regardless of corpus → a real proposal to dedup
    out = lint_names(["recieve_data", "recieve_data"])
    matches = [o for o in out if o["current"] == "recieve_data"]
    assert len(matches) == 1
    # only "receive" present in the corpus (via the typo fix) → majority keeps it
    assert matches[0]["suggested"] == "receive_data"


# ── demo integration ─────────────────────────────────────────────────────────

def test_canonicalize_names_demo():
    async def run():
        async with open_demo() as db:
            await db.rename(0x1400013A0, "parse_msg_header")
            await db.rename(0x140001600, "build_message_body")
            await db.rename(0x140001820, "send_msg")

            seen = []

            async def progress_cb(done, total, info):
                seen.append(info)

            totals = await db.canonicalize_names(progress_cb=progress_cb)
            # corpus has msg×2, message×1 → message unified to msg
            hit = [i for i in seen if i["current"] == "build_message_body"]
            assert hit and hit[0]["suggested"] == "build_msg_body"
            assert hit[0]["applied"] is True
            assert totals["renamed"] >= 1
            funcs = await db.list_functions()
            assert any(f["name"] == "build_msg_body" for f in funcs)
    asyncio.run(run())


def test_canonicalize_flags_generic():
    async def run():
        async with open_demo() as db:
            await db.rename(0x1400013A0, "process")
            seen = []

            async def progress_cb(done, total, info):
                seen.append(info)

            totals = await db.canonicalize_names(progress_cb=progress_cb)
            assert totals["generic"] >= 1
            assert any(i["reason"] == "generic" and i["current"] == "process"
                       for i in seen)
    asyncio.run(run())


def test_canonicalize_disabled(monkeypatch):
    monkeypatch.setenv("SPECTRIDA_NAME_LINT", "0")

    async def run():
        async with open_demo() as db:
            await db.rename(0x140001600, "build_message_body")
            await db.rename(0x140001820, "send_msg")
            await db.rename(0x1400013A0, "parse_msg_header")
            totals = await db.canonicalize_names()
            assert totals["flagged"] >= 1     # still detected
            assert totals["renamed"] == 0     # but not applied
            funcs = await db.list_functions()
            assert any(f["name"] == "build_message_body" for f in funcs)  # unchanged
    asyncio.run(run())
