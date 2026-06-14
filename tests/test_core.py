import asyncio

from spectrida.core import llamacpp
from spectrida.core.llamacpp import (
    _RE_SYSTEM,
    _build_stream_prompt,
    _hints_block,
    extract_json_object,
    extract_name,
    llamacpp_chat_payload,
    llamacpp_endpoint,
)
from spectrida.tui.widgets.disasm import fmt_size, highlight, is_sub


def test_highlight_keeps_text():
    t = highlight("0x1000", "mov eax, 0x5")
    assert "mov" in t.plain and "eax" in t.plain and "0x5" in t.plain


def test_is_sub():
    assert is_sub("sub_140001000")
    assert is_sub("j_strcpy")
    assert not is_sub("Player$$Update")


def test_fmt_size():
    assert fmt_size(0) == ""
    assert fmt_size(512) == "512b"
    assert fmt_size(2048) == "2kb"


def test_extract_name():
    assert extract_name("NAME: do_thing\nREASON: stuff") == "do_thing"
    assert extract_name("no name here") is None


def test_extract_json_ignores_forced_reasoning_preamble():
    text = (
        'Considering the limited time by the user, I have to give the solution '
        'based on the thinking directly now." ^\n'
        '{"name": "parse_packet", "reason": "parses a packet header"}'
    )
    assert extract_json_object(text)["name"] == "parse_packet"


def test_prompt_uses_text_field():
    # disasm rows are {"address","text"}; the prompt must read 'text'
    p = _build_stream_prompt([{"address": "0x1", "text": "mov eax, 1"}], ["callee"], ["caller"])
    assert "mov eax, 1" in p and "callee" in p and "caller" in p


def test_system_prompt_is_not_game_specific():
    assert "game binaries" not in _RE_SYSTEM.lower()
    assert "native binaries" in _RE_SYSTEM


def test_anthropic_payload_splits_system(monkeypatch):
    monkeypatch.setenv("SPECTRIDA_LLAMACPP_URL", "https://api.anthropic.com")

    payload = llamacpp_chat_payload(
        [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}],
        stream=True,
        max_tokens=123,
    )

    assert llamacpp_endpoint() == "https://api.anthropic.com/v1/messages"
    assert payload["system"] == "sys"
    assert payload["messages"] == [{"role": "user", "content": "hi"}]
    assert payload["max_tokens"] == 123
    assert payload["temperature"] == 0.0
    assert payload["top_p"] == 0.9
    assert payload["top_k"] == 1
    assert "cache_prompt" not in payload
    assert "json_schema" not in payload
    assert "reasoning_format" not in payload


def test_hints_block_renders_rich_metadata():
    text = _hints_block({
        "strings": ["POST /api"],
        "api_calls": ["ws2_32!send(SOCKET,char *,int,int)"],
        "constants": ["0xedb88320"],
        "classified_constants": ["0xedb88320 (CRC32 polynomial)"],
        "function_facts": {"size": 64, "instruction_count": 12,
                           "leaf": False, "calls_out": 2, "callers": 1},
        "callsite_snippets": ["0x1000 -> parse_packet: call parse_packet"],
        "caller_return_usage": ["main+0x20: call sub_1000 ; next: test eax, eax"],
        "globals": ["reads/refs g_config at 0x2000"],
        "field_accesses": ["[rcx+40h] in mov eax, [rcx+40h]"],
    })

    assert "Function facts: size=64" in text
    assert "Recognized constants" in text
    assert "Outgoing call sites" in text
    assert "Caller return/use sites" in text
    assert "Global/data references" in text
    assert "Pointer/field accesses" in text


def test_history_is_reused_across_functions(monkeypatch):
    # single-call naming: one _stream_chat per function, history grows
    # system + (user + assistant) per function and the next call sees prior names.
    calls = []
    responses = iter([
        '{"name": "first_func", "reason": "first", "ret_type": "int", '
        '"params": {"a1": {"name": "buffer", "type": "uint8_t *"}}, '
        '"locals": {"v1": {"name": "score", "type": "int"}}}',
        '{"name": "second_func", "reason": "second", "ret_type": "void", '
        '"params": {"a1": {"name": "entity", "type": "Entity *"}}}',
    ])

    async def fake_stream_chat(messages, **_kwargs):
        calls.append([dict(m) for m in messages])
        return next(responses)

    monkeypatch.setattr(llamacpp, "_stream_chat", fake_stream_chat)
    lvars = [
        {"name": "a1", "type": "void *", "is_arg": True},
        {"name": "v1", "type": "int", "is_arg": False},
    ]
    history = []

    async def run():
        await llamacpp.name_function_staged("int sub_1(void *a1) { int v1; }", lvars, [], [], history=history)
        await llamacpp.name_function_staged("void sub_2(void *a1) { int v1; }", lvars, [], [], history=history)

    asyncio.run(run())

    assert history[0]["role"] == "system"
    assert len(history) == 5            # system + (user+assistant)*2
    assert len(calls) == 2
    assert len(calls[1]) > len(calls[0])
    assert any("first_func" in m["content"] for m in calls[1])
