"""LLM streaming client for function naming.

Uses provider-style stateless Anthropic Messages API: POST /v1/messages.
llama.cpp server supports this route, and Anthropic-compatible gateways can be
used by changing base_url/model/api_key.
"""
from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator

from spectrida.config import (
    llamacpp_api_key,
    llamacpp_anthropic_version,
    llamacpp_model,
    llamacpp_url,
    llm_temperature,
    llm_max_tokens,
    llm_top_k,
    llm_top_p,
    llm_json_mode,
    llm_timeout,
    llm_retries,
)

# ── unified system prompt ─────────────────────────────────────────────────────
# Single stable prefix shared by ALL LLM calls → maximises llama-server KV-cache
# hits (--cache-prompt prefix-matches the token sequence; if this text changes
# between requests the cache is invalidated).  Output-format instructions go in
# the user turn so each call-site can request what it needs.
_RE_SYSTEM = (
    "You are an expert reverse engineer analysing native binaries. "
    "You name functions, parameters, and local variables.\n"
    "Naming rules:\n"
    "  • snake_case only — EXCEPT for library/runtime functions (see below)\n"
    "  • Name WHAT the function does, not HOW: prefer domain verbs "
    "(encrypt, parse, validate, dispatch, serialize, send, recv, alloc, free) "
    "over generic ones (process, handle, do, run, execute)\n"
    "  • If API calls, strings, or constants reveal intent — use them: "
    "e.g. send_udp_packet, decrypt_aes128_cbc, parse_pe_header, on_player_death\n"
    "  • Thunks / single-call wrappers: name after what they forward\n"
    "  • Use concrete C types when the code makes them clear: "
    "'void', 'bool', 'int', 'char *', 'uint8_t *', 'size_t', etc.\n"
    "  • COMPILER / RUNTIME / STDLIB FUNCTIONS: if you recognise a function as "
    "a well-known compiler-generated or library routine — CRT (memcpy, memset, "
    "malloc, free, strlen, __chkstk, __alloca_probe, __security_check_cookie, "
    "_except_handler3/4, __CxxFrameHandler3, __RTDynamicCast, mainCRTStartup, "
    "WinMainCRTStartup, …), Delphi/VCL RTL, MFC, ATL, or any other recognisable "
    "framework runtime — output the CANONICAL library name verbatim, preserving "
    "its original casing and underscores. Do NOT invent a new descriptive name. "
    "If the name is a mangled symbol you can demangle, output the demangled form.\n"
    "  • TYPE PROPAGATION FROM CALLERS: when 'Typed call sites' show callers passing "
    "explicitly-typed or cast arguments (e.g. (Config *)ptr, (PlayerState)n), assign "
    "those exact types to the corresponding parameters. Always prefer existing IDA "
    "struct/typedef/enum names from the binary's type library over generic types like "
    "__int64 or void *. If multiple call sites agree on a type, treat it as confirmed.\n"
    "  • C++ EXCEPTION THROW HELPERS: when a function constructs an exception object "
    "and passes it to CxxThrowException / _CxxThrowException with a ThrowInfo "
    "descriptor (_TI<n>_AV<type>_std__ or _TI<n>_AV<type>@std@@), name it "
    "throw_<type> using the decoded exception class. "
    "Examples: _TI2_AVbad_alloc_std__ → throw_bad_alloc, "
    "_TI1_AVruntime_error_std__ → throw_runtime_error, "
    "_TI3_AVlogic_error_std__ → throw_logic_error. "
    "Do NOT use the generic name cxx_throw_exception."
)

# Per-session binary context — set once when the .i64 is opened, never mutated.
# Identical across every naming call in a session → llama-server KV-cache hits.
_binary_ctx: str = ""


def set_binary_context(ctx: str) -> None:
    global _binary_ctx
    _binary_ctx = ctx.strip()


def _build_system() -> str:
    if not _binary_ctx:
        return _RE_SYSTEM
    return _RE_SYSTEM + "\n\n=== TARGET BINARY ===\n" + _binary_ctx


# Reasoning tag pattern — closing </think> can be absent when reasoning budget
# is exhausted, so every matcher must also accept a block that runs to \Z.
_THINK_RE         = re.compile(r"<think>.*?(?:</think>|\Z)", re.DOTALL)
_THINK_CONTENT_RE = re.compile(r"<think>(.*?)(?:</think>|\Z)", re.DOTALL)

# MSVC ThrowInfo descriptor: _TI<n>_AV<classname>_std__  or  _TI<n>_AV<classname>@std@@
_THROWINFO_RE = re.compile(r"_TI\d+_AV([A-Za-z_][A-Za-z0-9_]*)(?:_std__|@std@@|@)")


# ── HTTP / SDK helpers ────────────────────────────────────────────────────────

def llamacpp_headers() -> dict[str, str]:
    key = llamacpp_api_key()
    headers = {"Content-Type": "application/json"}
    if key:
        headers["x-api-key"] = key
    headers["anthropic-version"] = llamacpp_anthropic_version()
    return headers


def _endpoint() -> str:
    return f"{llamacpp_url().rstrip('/')}/v1/messages"


def llamacpp_endpoint() -> str:
    return _endpoint()


def _client():
    from anthropic import AsyncAnthropic
    import httpx

    t = llm_timeout()
    return AsyncAnthropic(
        api_key=llamacpp_api_key() or "not-needed",
        base_url=llamacpp_url().rstrip("/"),
        default_headers={"anthropic-version": llamacpp_anthropic_version()},
        timeout=httpx.Timeout(connect=10.0, read=t, write=30.0, pool=10.0),
    )


def _anthropic_split_messages(messages: list[dict]) -> tuple[str, list[dict]]:
    system_parts = []
    out = []
    for msg in messages:
        role = msg.get("role")
        content = msg.get("content", "")
        if role == "system":
            system_parts.append(str(content))
        elif role in ("user", "assistant"):
            out.append({"role": role, "content": str(content)})
    return "\n\n".join(system_parts), out


def _message_kwargs(messages: list[dict], *, temperature: float | None,
                    max_tokens: int | None, json_mode: bool = False) -> dict:
    max_out = max_tokens if max_tokens is not None else llm_max_tokens()
    temp = llm_temperature() if temperature is None else temperature
    system, msgs = _anthropic_split_messages(messages)
    kwargs: dict = {
        "model":       llamacpp_model(),
        "messages":    msgs,
        "temperature": temp,
        "max_tokens":  max_out,
    }
    top_p = llm_top_p()
    if top_p is not None:
        kwargs["top_p"] = top_p
    top_k = llm_top_k()
    if top_k is not None:
        kwargs["top_k"] = top_k
    if system:
        kwargs["system"] = system
    if json_mode:
        kwargs["extra_body"] = {"response_format": {"type": "json_object"}}
    return kwargs


def llamacpp_chat_payload(messages: list[dict], *, stream: bool = True,
                          temperature: float | None = None,
                          max_tokens: int | None = None) -> dict:
    payload = _message_kwargs(messages, temperature=temperature, max_tokens=max_tokens)
    payload["stream"] = stream
    return payload


async def _stream_text(messages: list[dict], *, temperature: float | None = None,
                       max_tokens: int | None = None,
                       json_mode: bool = False) -> AsyncIterator[str]:
    client = _client()
    async with client.messages.stream(
        **_message_kwargs(messages, temperature=temperature, max_tokens=max_tokens,
                          json_mode=json_mode)
    ) as stream:
        async for text in stream.text_stream:
            if text:
                yield text


def llamacpp_stream_text(messages: list[dict], *, temperature: float | None = None,
                         max_tokens: int | None = None) -> AsyncIterator[str]:
    return _stream_text(messages, temperature=temperature, max_tokens=max_tokens)


async def llamacpp_ping() -> bool:
    try:
        client = _client()
        await client.messages.create(
            **_message_kwargs(
                [{"role": "user", "content": "hi"}],
                temperature=0.0,
                max_tokens=1,
            )
        )
        return True
    except Exception:
        return False


def _is_retryable(exc: BaseException) -> bool:
    """Return True for transient errors worth retrying."""
    import httpx
    if isinstance(exc, (httpx.ConnectError, httpx.TimeoutException,
                        httpx.RemoteProtocolError, httpx.ReadError)):
        return True
    try:
        from anthropic import APIConnectionError, APIStatusError
        if isinstance(exc, APIConnectionError):
            return True
        if isinstance(exc, APIStatusError) and exc.status_code in (429, 502, 503, 504):
            return True
    except ImportError:
        pass
    return False


async def _stream_chat(messages: list[dict], *, temperature: float | None = None,
                       max_tokens: int | None = None,
                       json_mode: bool = False) -> str:
    """Collect a full response, retrying on transient connection errors."""
    import asyncio
    max_tries = llm_retries() + 1
    delay = 1.0
    last_exc: BaseException = RuntimeError("no attempts made")
    for attempt in range(max_tries):
        try:
            return "".join([
                tok async for tok in _stream_text(
                    messages, temperature=temperature, max_tokens=max_tokens,
                    json_mode=json_mode)
            ])
        except BaseException as e:
            if not _is_retryable(e) or attempt == max_tries - 1:
                raise
            last_exc = e
            print(f"[llamacpp] attempt {attempt + 1}/{max_tries - 1} failed "
                  f"({type(e).__name__}: {e}), retrying in {delay:.0f}s…",
                  flush=True)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30.0)
    raise last_exc


# ── prompt helpers ────────────────────────────────────────────────────────────

def _insn_line(i: dict) -> str:
    # disasm rows are {"address", "text"}; fall back to mnemonic/op_str if present
    text = i.get("text") or f"{i.get('mnemonic', '')}  {i.get('op_str', '')}".strip()
    return f"  {i.get('address', ''):>16}  {text}"


def _ctx_block(label: str, items: list[str]) -> str:
    """Render a call-chain section. Already-named neighbours with full signatures
    (e.g. 'void apply_fall_damage(Entity *a1, float *a2)') give the model real
    semantic context."""
    items = [i for i in items if i][:8]
    if not items:
        return f"{label}: none\n"
    return f"{label}:\n" + "".join(f"  - {i}\n" for i in items)


def _hint_lines(label: str, values: list, limit: int) -> str:
    vals = [str(v) for v in (values or []) if v][:limit]
    if not vals:
        return ""
    return label + ":\n" + "".join(f"  - {v}\n" for v in vals)


def _hints_block(hints: dict | None) -> str:
    """Render compact naming signals from IDA.

    Order: API calls (richest semantic signal) → strings → recognised constants
    → function facts → call sites → caller usage → globals → field accesses.
    Raw numeric constants come last — they rarely disambiguate on their own.
    """
    if not hints:
        return ""
    out = ""
    apis       = [s for s in (hints.get("api_calls") or []) if s][:12]
    strings    = [s for s in (hints.get("strings") or []) if s][:12]
    classified = [s for s in (hints.get("classified_constants") or []) if s][:10]
    consts     = [s for s in (hints.get("constants") or []) if s][:8]
    facts      = hints.get("function_facts") or {}

    if apis:
        out += "Calls to known APIs/imports: " + ", ".join(apis) + "\n"
    if strings:
        out += "Referenced strings:\n" + "".join(f'  - "{s}"\n' for s in strings)
    if classified:
        out += _hint_lines("Recognized constants", classified, 10)
    if facts:
        fact_bits = []
        for key, label in (
            ("size", "size"), ("instruction_count", "insns"),
            ("calls_out", "calls_out"), ("callers", "callers"),
        ):
            if key in facts:
                fact_bits.append(f"{label}={facts[key]}")
        if "leaf" in facts:
            fact_bits.append(f"leaf={bool(facts['leaf'])}")
        if fact_bits:
            out += "Function facts: " + ", ".join(fact_bits) + "\n"
    out += _hint_lines("Outgoing call sites",    hints.get("callsite_snippets") or [],   8)
    out += _hint_lines("Caller return/use sites", hints.get("caller_return_usage") or [], 6)
    globals_ = hints.get("globals") or []
    if globals_:
        out += _hint_lines("Global/data references", globals_, 8)
        # Decode any ThrowInfo descriptors and surface them explicitly
        ti_decoded = [
            f"{g} → std::{_decode_throwinfo([g])}"
            for g in globals_
            if _THROWINFO_RE.search(g) and _decode_throwinfo([g])
        ]
        if ti_decoded:
            out += "C++ ThrowInfo (exception type): " + ", ".join(ti_decoded) + "\n"
    out += _hint_lines("Pointer/field accesses",  hints.get("field_accesses") or [],      8)
    if consts:
        out += "Notable constants: " + ", ".join(consts) + "\n"
    typed_sites = [s for s in (hints.get("typed_call_sites") or []) if s]
    if typed_sites:
        out += "Typed call sites (infer parameter types from these):\n"
        for s in typed_sites[:5]:
            out += f"  {s}\n"
    return out


def _lvar_list(lvars: list[dict]) -> str:
    return ", ".join(
        f"{lv['name']}" + (f" ({lv['type']})" if lv.get("type") else "")
        for lv in lvars
    ) or "none"


def _code_section(pseudocode: str, insns: list[dict] | None,
                  pseudo_limit: int = 5000, asm_limit: int = 80) -> str:
    """Return the best available code for a prompt.

    Prefers real decompiler pseudocode; falls back to raw disassembly when
    Hex-Rays is unavailable (pseudocode is empty or starts with a '//' error
    comment). When neither is available the model still has API calls, strings,
    and call-chain context to work with.
    """
    s = (pseudocode or "").strip()
    if s and not s.startswith("//"):
        return f"Pseudocode:\n{s[:pseudo_limit]}"
    if insns:
        asm = "\n".join(_insn_line(i) for i in insns[:asm_limit])
        return f"Assembly (no decompiler available):\n{asm}"
    return "(no code available — use API calls, strings, and call-chain context)"


def _build_stream_prompt(insns: list[dict], callees: list[str], callers: list[str],
                          pseudocode: str = "") -> str:
    """Prompt for the streaming TUI name preview (NAME:/REASON: text format)."""
    code = _code_section(pseudocode, insns, pseudo_limit=4000)
    return (
        f"{_ctx_block('Calls', callees)}"
        f"{_ctx_block('Called by', callers)}\n"
        f"{code}\n\n"
        "Name this function.\n"
        "Reply:\nNAME: <snake_case_name>\nREASON: <1-3 sentences>"
    )


def _single_stage_prompt(pseudocode: str, lvars: list[dict],
                          callees: list[str], callers: list[str],
                          hints: dict | None,
                          insns: list[dict] | None = None,
                          glossary: str = "") -> str:
    """Single-turn prompt that requests ALL naming outputs in one JSON reply.

    Using actual variable names in the schema (a1, v3, …) lets the model map
    its answer directly to the IDA lvar names without any guessing.

    *glossary* (optional) is a project-wide vocabulary / already-assigned-names
    block prepended so the model keeps naming consistent across the binary. It
    rides in the user turn so the cached system prefix is untouched.
    """
    args    = [lv for lv in lvars if lv.get("is_arg")]
    locals_ = [lv for lv in lvars if not lv.get("is_arg")]
    code    = _code_section(pseudocode, insns)

    params_schema = ", ".join(
        f'"{lv["name"]}":{{"name":"...","type":"..."}}'
        for lv in args[:8]
    )
    locals_schema = ", ".join(
        f'"{lv["name"]}":{{"name":"...","type":"..."}}'
        for lv in locals_[:12]
    )
    schema = '{"name":"...","reason":"...","ret_type":"..."'
    if params_schema:
        schema += f', "params":{{{params_schema}}}'
    if locals_schema:
        schema += f', "locals":{{{locals_schema}}}'
    schema += "}"

    return (
        (f"{glossary}\n\n" if glossary else "")
        + f"{_ctx_block('Calls', callees)}"
        f"{_ctx_block('Called by', callers)}"
        f"{_hints_block(hints)}"
        + (f"Parameters: {_lvar_list(args)}\n" if args else "")
        + (f"Locals: {_lvar_list(locals_)}\n" if locals_ else "")
        + f"\n{code}\n\n"
        f"Reply ONLY with one JSON object (omit params/locals if none):\n{schema}"
    )


# ── streaming name (TUI live display) ────────────────────────────────────────

async def stream_name(
    insns: list[dict],
    callees: list[str],
    callers: list[str],
    *,
    pseudocode: str = "",
) -> AsyncIterator[str]:
    """Yield response tokens as the model writes (TUI live preview).

    Uses pseudocode when available; falls back to raw disassembly when Hex-Rays
    is not installed or decompilation failed.

    llama-server with --reasoning on may put the answer in delta.reasoning_content
    instead of delta.content when --reasoning-budget-message triggers mid-think.
    We yield content tokens live (clean for display) and buffer reasoning tokens;
    if no content arrived at all we emit the buffered reasoning wrapped in
    <think></think> so extract_name can still find NAME: inside it.
    """
    messages = [
        {"role": "system", "content": _build_system()},
        {"role": "user",   "content": _build_stream_prompt(insns, callees, callers, pseudocode)},
    ]
    content_seen = False
    async for text in _stream_text(messages, temperature=None, max_tokens=llm_max_tokens()):
        content_seen = True
        yield text

    if not content_seen:
        return


async def name_function(insns: list[dict], callees: list[str], callers: list[str],
                        *, pseudocode: str = "") -> str:
    """Non-streaming convenience — returns the extracted name (batch / API use)."""
    full = "".join([
        tok async for tok in stream_name(insns, callees, callers, pseudocode=pseudocode)
    ])
    return extract_name(full) or ""


# ── variable naming (standalone path) ────────────────────────────────────────

def _filter_var_map(raw: dict, lvars: list[dict]) -> dict[str, dict]:
    """Normalise the model's variable map to {old: {"name": str, "type": str}}.

    Accepts both the rich form {"a1": {"name":.., "type":..}} and the legacy flat
    form {"a1": "new_name"}. Keeps only entries targeting a real lvar with a valid
    new identifier; type is optional (empty string when absent)."""
    valid = {lv["name"] for lv in lvars}
    out: dict[str, dict] = {}
    if not isinstance(raw, dict):
        return out
    for k, v in raw.items():
        if k not in valid:
            continue
        if isinstance(v, dict):
            nm = v.get("name") or ""
            ty = v.get("type") or ""
        else:
            nm, ty = v, ""
        # Include the entry when the name changes OR when a type is provided —
        # so type-only changes (e.g. keeping the name "this" but setting CGump *)
        # are not silently dropped.
        if isinstance(nm, str) and nm.isidentifier() and (nm != k or ty):
            out[k] = {"name": nm, "type": ty if isinstance(ty, str) else ""}
    return out


async def correct_types(pseudocode: str, failed: list[dict]) -> dict[str, str]:
    """Ask the model to REPLACE types that were rejected as unknown.

    *failed* = [{"var", "type"}] — variables whose proposed type named a
    struct/enum/typedef absent from this binary's type library. The model picks a
    replacement that's either a primitive or an existing type (the binary context
    already lists the available structs/enums). Returns {var: new_type_str}.
    Use "<return>" as a var name for the function return type.
    """
    if not failed:
        return {}
    lines = "\n".join(f'  - {f.get("var", "")}: rejected "{f.get("type", "")}"'
                      for f in failed)
    user_msg = (
        "Some types you proposed could not be applied because the named type does "
        "NOT exist in this binary's type library:\n"
        f"{lines}\n\n"
        "For each variable choose a REPLACEMENT type that is either a primitive C "
        "type (e.g. int, unsigned int, void *, char *, uint8_t *, size_t) or an "
        "EXISTING struct/enum/typedef from this binary (see the type list above). "
        "Do not invent new type names.\n"
        'Reply ONLY with JSON mapping name→type: {"buf": "uint8_t *", ...}. '
        "Omit any variable you are unsure about.\n\n"
        f"Pseudocode:\n{pseudocode[:5000]}\n\nJSON:"
    )
    raw = await _stream_chat([
        {"role": "system", "content": _build_system()},
        {"role": "user",   "content": user_msg},
    ], json_mode=llm_json_mode())
    obj = extract_json_object(raw)
    out: dict[str, str] = {}
    for k, v in obj.items():
        if isinstance(v, dict):
            v = v.get("type", "")
        if isinstance(v, str) and v.strip():
            out[str(k)] = v.strip()
    return out


async def name_struct(layout: list[dict], snippets: str, *,
                      glossary: str = "") -> dict:
    """Name a recovered struct and its fields (F — struct recovery).

    *layout* = the reconciled field list ``[{offset, size, type, flags}, …]`` whose
    offsets/sizes are FIXED (observed, not negotiable). *snippets* are a few
    pseudocode lines showing how the base pointer is used, for naming context.

    Returns ``{"struct_name": str, "fields": {hex_offset: {"name","type"}},
    "reason": str}``. The model may refine a field's scalar type (e.g. ``_DWORD``
    → ``BOOL``, ``void *`` → ``Player *``) but MUST keep offsets/sizes; the host
    re-checks every type in IDA and drops mismatches.
    """
    if not layout:
        return {"struct_name": "", "fields": {}, "reason": ""}
    rows = []
    for f in layout:
        if "padding" in (f.get("flags") or []):
            continue
        rows.append('  - offset 0x%X, %d bytes, current type %s'
                    % (int(f["offset"]), int(f["size"]), f.get("type", "?")))
    fields_block = "\n".join(rows)
    user_msg = (
        (f"{glossary}\n\n" if glossary else "")
        + "You are recovering a C struct from the field accesses observed on a "
        "pointer parameter across the binary. The OFFSETS and SIZES below are fixed "
        "(observed from real accesses) — do NOT change them. Give the struct a "
        "descriptive PascalCase name and name each field in snake_case. You may "
        "refine a field's type when the usage makes it clear (a pointer, an existing "
        "struct/enum from this binary, BOOL, float, etc.), but the type's width must "
        "match the field size.\n\n"
        f"Observed fields:\n{fields_block}\n\n"
        f"How the pointer is used:\n{(snippets or '')[:4000]}\n\n"
        'Reply ONLY with JSON: {"struct_name": "PlayerState", '
        '"fields": {"0x40": {"name": "health", "type": "float"}, …}, '
        '"reason": "one sentence"}'
    )
    raw = await _stream_chat([
        {"role": "system", "content": _build_system()},
        {"role": "user",   "content": user_msg},
    ], json_mode=llm_json_mode())
    obj = extract_json_object(raw)
    name = obj.get("struct_name") or obj.get("name") or ""
    if not (isinstance(name, str) and name.isidentifier()):
        name = ""
    fields_raw = obj.get("fields") or {}
    fields: dict[str, dict] = {}
    if isinstance(fields_raw, dict):
        for k, v in fields_raw.items():
            if isinstance(v, dict):
                fields[str(k)] = {"name": str(v.get("name", "") or ""),
                                  "type": str(v.get("type", "") or "")}
            elif isinstance(v, str):
                fields[str(k)] = {"name": v, "type": ""}
    reason = obj.get("reason") or obj.get("reasoning") or ""
    return {"struct_name": name, "fields": fields,
            "reason": reason if isinstance(reason, str) else ""}


async def name_global(global_info: dict, sites: list[dict], *,
                      glossary: str = "") -> dict:
    """Name + type a global variable (G — global naming) from its best-understood
    use sites.

    *global_info* = {name, size, cur_type}. *sites* = the top-K referencing
    functions, each {func_name, proto, access, snippet}. Returns
    ``{"name": str, "type": str, "reason": str}``; the host validates the type in
    IDA and drops it (without renaming) if it doesn't apply.
    """
    if not sites:
        return {"name": "", "type": "", "reason": ""}
    blocks = []
    for s in sites[:8]:
        acc = ", ".join(s.get("access") or []) or "read"
        head = s.get("proto") or s.get("func_name") or hex(s.get("func_ea", 0))
        snippet = (s.get("snippet") or "").strip()
        blocks.append("In %s  [%s]:\n%s" % (head, acc, snippet[:800]))
    sites_block = "\n\n".join(blocks)
    g = global_info or {}
    user_msg = (
        (f"{glossary}\n\n" if glossary else "")
        + "Name and type a GLOBAL variable from how the best-understood functions "
        "use it. Current name %r, size %s bytes, current type %r.\n\n"
        % (g.get("name", ""), g.get("size", 0), g.get("cur_type", "") or "unknown")
        + "Use sites (most informative first):\n%s\n\n" % sites_block
        + "Give a descriptive snake_case name (prefix g_ for a mutable global, "
        "k_ / no prefix for a const table) and a concrete C type consistent with "
        "the size and usage. Prefer an existing struct/enum from this binary over a "
        "bare scalar; if the evidence is one-sided, fall back to a size-matched "
        "scalar (e.g. int for 4 bytes). Do NOT invent a struct that isn't in the "
        "binary.\n"
        'Reply ONLY with JSON: {"name": "g_player_count", "type": "int", '
        '"reason": "one sentence"}'
    )
    raw = await _stream_chat([
        {"role": "system", "content": _build_system()},
        {"role": "user",   "content": user_msg},
    ], json_mode=llm_json_mode())
    obj = extract_json_object(raw)
    name = obj.get("name") or ""
    if not (isinstance(name, str) and name.isidentifier()):
        name = ""
    ty = obj.get("type") or obj.get("c_type") or ""
    reason = obj.get("reason") or obj.get("reasoning") or ""
    return {"name": name,
            "type": ty.strip() if isinstance(ty, str) else "",
            "reason": reason if isinstance(reason, str) else ""}


async def name_variables(pseudocode: str, lvars: list[dict]) -> dict[str, str]:
    """Ask the model for a {old_name: {name, type}} mapping for locals + params."""
    if not lvars:
        return {}
    names = _lvar_list(lvars)
    user_msg = (
        f"Name and type these local variables / parameters: {names}\n\n"
        "For each, suggest a descriptive snake_case NAME and, when the code makes "
        "it clear, a concrete C TYPE. "
        'Reply ONLY with JSON: {"a1": {"name": "buffer", "type": "uint8_t *"}, ...}\n'
        "Omit any variable you can’t confidently name.\n\n"
        f"Pseudocode:\n{pseudocode[:6000]}\n\n"
        "JSON mapping:"
    )
    full = await _stream_chat([
        {"role": "system", "content": _build_system()},
        {"role": "user",   "content": user_msg},
    ], json_mode=llm_json_mode())
    return _filter_var_map(extract_json_object(full), lvars)


# ── staged naming: single LLM call → name + types + variables ────────────────

def _camel_to_snake(raw: str) -> str:
    """Convert CamelCase / ALL_CAPS API name to snake_case identifier."""
    raw = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", raw)
    raw = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", raw)
    return re.sub(r"[^a-zA-Z0-9]+", "_", raw).strip("_").lower()


def _decode_throwinfo(globals_: list[str]) -> str | None:
    """Return the snake_case exception class name from a ThrowInfo symbol, or None."""
    for g in (globals_ or []):
        m = _THROWINFO_RE.search(g)
        if m:
            return _camel_to_snake(m.group(1))
    return None


def _fast_name(insns: list[dict] | None, hints: dict | None) -> dict | None:
    """Return a pre-computed result for trivial functions — no LLM call needed.

    Handles two patterns:
    1. Thunks: ≤4 instructions forwarding to exactly one known API import.
    2. C++ throw helpers: any size, calls CxxThrowException with a ThrowInfo global.
    """
    h = hints or {}
    apis     = [a for a in h.get("api_calls", []) if a]
    globals_ = [g for g in h.get("globals", []) if g]

    # C++ throw helper: CxxThrowException + ThrowInfo descriptor → throw_<type>
    throws = [a for a in apis if "cxxthrowexception" in a.lower() or
              "_cxxthrowexception" in a.lower()]
    if throws:
        exc_type = _decode_throwinfo(globals_)
        if exc_type:
            return {
                "name":      f"throw_{exc_type}",
                "reason":    f"C++ throw helper for {exc_type} (ThrowInfo detected)",
                "ret_type":  "void",
                "variables": {},
            }

    # Thunk: ≤4 instructions, exactly 1 API call
    if len(insns or []) <= 4 and len(apis) == 1:
        # Strip prototype signature — keep only the bare function name.
        # Input may be "void __stdcall __noreturn _CxxThrowException(void *a, ...)"
        # or just "_CxxThrowException" — handle both.
        bare = apis[0].split("(")[0].strip()
        raw = (bare.split()[-1] if bare.split() else bare).lstrip("_")
        for pfx in ("ntdll.", "kernel32.", "ucrtbase.", "msvcrt.", "api-ms-win-"):
            if raw.lower().startswith(pfx):
                raw = raw[len(pfx):]
        name = _camel_to_snake(raw)
        if name and name.isidentifier():
            return {
                "name":      name,
                "reason":    f"thunk forwarding to {apis[0]}",
                "ret_type":  "",
                "variables": {},
            }
    return None


def _json_history(obj: dict) -> str:
    return json.dumps(obj if isinstance(obj, dict) else {}, ensure_ascii=False)


def strip_think(text: str) -> str:
    """Drop <think>…</think> (closed OR unclosed-to-end) from a reply — used before
    adding it to history, and by the TUI to render reasoning-free output."""
    return _THINK_RE.sub("", text).strip()


_strip_think = strip_think  # internal alias


async def name_function_staged(
    pseudocode: str,
    lvars: list[dict],
    callees: list[str],
    callers: list[str],
    hints: dict | None = None,
    history: list[dict] | None = None,
    insns: list[dict] | None = None,
    glossary: str = "",
) -> dict:
    """Name + type a function in a SINGLE LLM call.

    Returns {"name", "reason", "ret_type", "variables": {old: {name, type}}}.

    *insns* provides a disassembly fallback when pseudocode is unavailable
    (no Hex-Rays licence or decompilation failure).

    *history* is mutated in-place when provided: it accumulates the full
    conversation across multiple functions in a call branch so each caller sees
    the callee names it just resolved — maximising KV-cache prefix reuse for
    the deep-branch naming flow.

    *glossary* (project vocabulary + assigned names) is injected ONLY on the
    first user turn of a fresh conversation — within a branch the accumulated
    history already carries the resolved names, so we avoid repeating it.
    """
    # Fast path: trivial thunks need no LLM round-trip
    fast = _fast_name(insns, hints)
    if fast is not None:
        return fast

    args    = [lv for lv in lvars if lv.get("is_arg")]
    locals_ = [lv for lv in lvars if not lv.get("is_arg")]

    messages = history if history is not None else []
    fresh = not messages
    if not messages:
        messages.append({"role": "system", "content": _build_system()})

    messages.append({
        "role":    "user",
        "content": _single_stage_prompt(pseudocode, lvars, callees, callers, hints, insns,
                                        glossary=glossary if fresh else ""),
    })
    raw = await _stream_chat(messages, json_mode=llm_json_mode())
    obj = extract_json_object(raw)
    messages.append({"role": "assistant", "content": _json_history(obj)})

    name = obj.get("name") or ""
    if not (isinstance(name, str) and name.isidentifier()):
        name = extract_name(raw) or ""
    reason   = obj.get("reason") or obj.get("reasoning") or ""
    ret_type = (obj.get("ret_type") or obj.get("return_type") or "").strip()

    # Merge params + locals from the single JSON reply into the variables map
    raw_vars: dict = {}
    params_raw = obj.get("params") or {}
    locals_raw = obj.get("locals") or obj.get("variables") or {}
    if isinstance(params_raw, dict):
        raw_vars.update(params_raw)
    if isinstance(locals_raw, dict):
        raw_vars.update(locals_raw)
    variables = _filter_var_map(raw_vars, lvars)

    return {
        "name":      name if (isinstance(name, str) and name.isidentifier()) else "",
        "reason":    reason if isinstance(reason, str) else "",
        "ret_type":  ret_type if isinstance(ret_type, str) else "",
        "variables": variables,
    }


# ── JSON extraction ───────────────────────────────────────────────────────────

def _balanced_objects(text: str) -> list[str]:
    """Return every top-level {...} span, brace-balanced (handles nesting)."""
    objs: list[str] = []
    depth = 0
    start: int | None = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start is not None:
                objs.append(text[start:i + 1])
                start = None
    return objs


def extract_json_object(text: str) -> dict:
    """Return the LAST top-level JSON object in a model response (nested-safe,
    ignores <think> blocks and surrounding prose)."""
    cleaned = _THINK_RE.sub("", text)
    for blob in reversed(_balanced_objects(cleaned) or _balanced_objects(text)):
        try:
            obj = json.loads(blob)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    return {}


def extract_name(full_text: str) -> str | None:
    # Try JSON first — name_function_staged outputs JSON
    obj = extract_json_object(full_text)
    if isinstance(obj.get("name"), str) and obj["name"].isidentifier():
        return obj["name"]

    # Outside <think>: look for NAME: line (stream_name text format)
    outside = _THINK_RE.sub("", full_text)
    for line in outside.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("NAME:"):
            rest = stripped[5:].strip()
            candidate = rest.split()[0] if rest else ""
            if candidate and candidate.isidentifier():
                return candidate

    # Fallback: answer ended up inside <think> (reasoning budget exhausted mid-think).
    # Search the LAST think block in reverse so we pick the final conclusion.
    for block in reversed(_THINK_CONTENT_RE.findall(full_text)):
        for line in reversed(block.splitlines()):
            stripped = line.strip()
            if stripped.upper().startswith("NAME:"):
                rest = stripped[5:].strip()
                candidate = rest.split()[0] if rest else ""
                if candidate and candidate.isidentifier():
                    return candidate

    return None
