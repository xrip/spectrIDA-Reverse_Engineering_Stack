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
)

_SYSTEM = (
    "You are an expert reverse engineer analysing native binaries. "
    "Given x86-64 assembly and call-chain context, output a concise snake_case "
    "function name followed by a SHORT reasoning (3-5 sentences max). "
    "Format:\nNAME: <name>\nREASON: <reasoning>"
)

# Reasoning models emit <think>…</think>. With --reasoning-budget the closing tag
# can be dropped when the budget is hit, so every matcher must also accept a block
# that runs to end-of-string (\Z) — otherwise an unclosed <think> leaks into the
# parsed answer and naming silently fails.
_THINK_RE         = re.compile(r"<think>.*?(?:</think>|\Z)", re.DOTALL)
_THINK_CONTENT_RE = re.compile(r"<think>(.*?)(?:</think>|\Z)", re.DOTALL)

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

    return AsyncAnthropic(
        api_key=llamacpp_api_key() or "not-needed",
        base_url=llamacpp_url().rstrip("/"),
        default_headers={"anthropic-version": llamacpp_anthropic_version()},
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
                    max_tokens: int | None) -> dict:
    max_out = max_tokens if max_tokens is not None else llm_max_tokens()
    temp = llm_temperature() if temperature is None else temperature
    system, msgs = _anthropic_split_messages(messages)
    kwargs = {
        "model": llamacpp_model(),
        "messages": msgs,
        "temperature": temp,
        "max_tokens": max_out,
    }
    top_p = llm_top_p()
    if top_p is not None:
        kwargs["top_p"] = top_p
    top_k = llm_top_k()
    if top_k is not None:
        kwargs["top_k"] = top_k
    if system:
        kwargs["system"] = system
    return kwargs


def llamacpp_chat_payload(messages: list[dict], *, stream: bool = True,
                          temperature: float | None = None,
                          max_tokens: int | None = None) -> dict:
    payload = _message_kwargs(messages, temperature=temperature, max_tokens=max_tokens)
    payload["stream"] = stream
    return payload


async def _stream_text(messages: list[dict], *, temperature: float | None = None,
                       max_tokens: int | None = None) -> AsyncIterator[str]:
    client = _client()
    async with client.messages.stream(
        **_message_kwargs(messages, temperature=temperature, max_tokens=max_tokens)
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


def _insn_line(i: dict) -> str:
    # disasm rows are {"address", "text"}; fall back to mnemonic/op_str if present
    text = i.get("text") or f"{i.get('mnemonic', '')}  {i.get('op_str', '')}".strip()
    return f"  {i.get('address', ''):>16}  {text}"


def _ctx_block(label: str, items: list[str]) -> str:
    """Render a call-chain section. Items may be bare names or full signatures
    (e.g. 'void apply_fall_damage(Entity *a1, float *a2)') — already-named
    neighbours give the model real context to reason from."""
    items = [i for i in items if i][:8]
    if not items:
        return f"{label}: none\n"
    return f"{label}:\n" + "".join(f"  - {i}\n" for i in items)


def _build_prompt(insns: list[dict], callees: list[str], callers: list[str]) -> str:
    asm_lines = "\n".join(_insn_line(i) for i in insns[:80])
    return (
        f"{_ctx_block('Calls', callees)}"
        f"{_ctx_block('Called by', callers)}\n"
        f"Assembly:\n{asm_lines}\n\n"
        "Name this function:"
    )


async def stream_name(
    insns: list[dict],
    callees: list[str],
    callers: list[str],
) -> AsyncIterator[str]:
    """Yield response tokens as the model writes.

    llama-server with --reasoning on may put the answer in delta.reasoning_content
    instead of delta.content when --reasoning-budget-message triggers mid-think.
    We yield content tokens live (clean for display) and buffer reasoning tokens;
    if no content arrived at all, we emit the buffered reasoning wrapped in
    <think></think> so extract_name can still find NAME: inside it.
    """
    messages = [
        {"role": "system", "content": _SYSTEM},
        {"role": "user",   "content": _build_prompt(insns, callees, callers)},
    ]
    content_seen = False
    async for text in _stream_text(
        messages,
        temperature=None,
        max_tokens=llm_max_tokens(),
    ):
        content_seen = True
        yield text

    if not content_seen:
        return


async def name_function(insns: list[dict], callees: list[str], callers: list[str]) -> str:
    """Non-streaming convenience used by batch mode — returns the extracted name."""
    full = "".join([tok async for tok in stream_name(insns, callees, callers)])
    return extract_name(full) or ""


# ── shared streaming helper ──────────────────────────────────────────────────

async def _stream_chat(messages: list[dict], *, temperature: float | None = None,
                       max_tokens: int | None = None) -> str:
    """POST a chat completion using the Anthropic SDK and return the full text."""
    return "".join([
        tok async for tok in _stream_text(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    ])


# ── variable / parameter naming ──────────────────────────────────────────────

_VARS_SYSTEM = (
    "You are an expert reverse engineer. Given decompiler pseudocode with "
    "generic local/parameter names (a1, a2, v1, v3, ...), suggest for each a "
    "descriptive snake_case NAME and, when the code makes it clear, a concrete C "
    "TYPE (e.g. 'int', 'char *', 'uint8_t *', 'size_t'). Reply ONLY with a "
    "single JSON object mapping the ORIGINAL name to {\"name\":..,\"type\":..}. "
    "Use the existing type if you can't improve it; omit a var you can't name. "
    'Example: {"a1": {"name": "buffer", "type": "uint8_t *"}, '
    '"v3": {"name": "damage", "type": "float"}}'
)


def _build_vars_prompt(pseudocode: str, lvars: list[dict]) -> str:
    names = ", ".join(f"{lv['name']}" + (f" ({lv['type']})" if lv.get("type") else "")
                      for lv in lvars) or "none"
    return (
        f"Variables to name: {names}\n\n"
        f"Pseudocode:\n{pseudocode[:6000]}\n\n"
        "Return the JSON mapping now:"
    )


def _filter_var_map(raw: dict, lvars: list[dict]) -> dict[str, dict]:
    """Normalize the model's variable map to {old: {"name": str, "type": str}}.

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
        if isinstance(nm, str) and nm.isidentifier() and nm != k:
            out[k] = {"name": nm, "type": ty if isinstance(ty, str) else ""}
    return out


async def name_variables(pseudocode: str, lvars: list[dict]) -> dict[str, str]:
    """Ask the model for a {old_name: new_name} mapping for locals + params."""
    if not lvars:
        return {}
    full = await _stream_chat([
        {"role": "system", "content": _VARS_SYSTEM},
        {"role": "user",   "content": _build_vars_prompt(pseudocode, lvars)},
    ])
    return _filter_var_map(extract_json_object(full), lvars)


# ── staged conversation: name → params → locals + return, one chat session ──

_STAGED_SYSTEM = (
    "You are an expert reverse engineer analysing native binaries. We will analyse "
    "functions one at a time, each over three stages in this conversation. "
    "Think carefully at each stage and build on what you already concluded, including "
    "earlier functions in the same call branch. At every stage reply with ONLY a "
    "single JSON object and no prose. Use concrete C types when the code makes them "
    "clear (e.g. 'void', 'bool', 'int', 'char *', 'uint8_t *', 'size_t'); leave "
    "a type empty if unsure, and omit any variable you can't confidently name."
)


def _hint_lines(label: str, values: list, limit: int) -> str:
    vals = [str(v) for v in (values or []) if v][:limit]
    if not vals:
        return ""
    return label + ":\n" + "".join(f"  - {v}\n" for v in vals)


def _hints_block(hints: dict | None) -> str:
    """Render compact naming signals collected from IDA."""
    if not hints:
        return ""
    out = ""
    strings = [s for s in (hints.get("strings") or []) if s][:12]
    apis    = [s for s in (hints.get("api_calls") or []) if s][:12]
    consts  = [s for s in (hints.get("constants") or []) if s][:12]
    classified = [s for s in (hints.get("classified_constants") or []) if s][:8]
    facts = hints.get("function_facts") or {}
    if facts:
        fact_bits = []
        for key, label in (
            ("size", "size"),
            ("instruction_count", "insns"),
            ("calls_out", "calls_out"),
            ("callers", "callers"),
        ):
            if key in facts:
                fact_bits.append(f"{label}={facts[key]}")
        if "leaf" in facts:
            fact_bits.append(f"leaf={bool(facts['leaf'])}")
        if fact_bits:
            out += "Function facts: " + ", ".join(fact_bits) + "\n"
    if strings:
        out += "Referenced strings:\n" + "".join(f'  - "{s}"\n' for s in strings)
    if apis:
        out += "Calls to known APIs/imports: " + ", ".join(apis) + "\n"
    if classified:
        out += _hint_lines("Recognized constants", classified, 8)
    if consts:
        out += "Notable constants: " + ", ".join(consts) + "\n"
    out += _hint_lines("Outgoing call sites", hints.get("callsite_snippets") or [], 8)
    out += _hint_lines("Caller return/use sites", hints.get("caller_return_usage") or [], 6)
    out += _hint_lines("Global/data references", hints.get("globals") or [], 8)
    out += _hint_lines("Pointer/field accesses", hints.get("field_accesses") or [], 8)
    return out


def _json_history(obj: dict) -> str:
    return json.dumps(obj if isinstance(obj, dict) else {}, ensure_ascii=False)


def strip_think(text: str) -> str:
    """Drop <think>…</think> (closed OR unclosed-to-end) from a reply — used before
    adding it to history, and by the TUI to render reasoning-free output."""
    return _THINK_RE.sub("", text).strip()


_strip_think = strip_think  # internal alias


def _lvar_list(lvars: list[dict]) -> str:
    return ", ".join(f"{lv['name']}" + (f" ({lv['type']})" if lv.get("type") else "")
                     for lv in lvars) or "none"


def _stage1_prompt(pseudocode: str, lvars: list[dict],
                   callees: list[str], callers: list[str], hints: dict | None) -> str:
    return (
        f"{_ctx_block('Calls', callees)}"
        f"{_ctx_block('Called by', callers)}"
        f"{_hints_block(hints)}"
        f"Variables present: {_lvar_list(lvars)}\n\n"
        f"Pseudocode:\n{pseudocode[:6000]}\n\n"
        "Stage 1 — give this FUNCTION a concise snake_case name and a SHORT reasoning "
        '(1-3 sentences). Reply JSON: {"name": "...", "reason": "..."}'
    )


async def name_function_staged(
    pseudocode: str,
    lvars: list[dict],
    callees: list[str],
    callers: list[str],
    hints: dict | None = None,
    history: list[dict] | None = None,
) -> dict:
    """Name + type a function over a 3-stage CONVERSATION (one chat session):
    1) function name, 2) parameters (name+type), 3) locals (name+type) + return type.
    Each stage sees the model's own prior answers. When *history* is provided, it is
    mutated and reused across multiple functions in the same call branch. Returns the
    same shape the rest of the pipeline consumes:
    {"name", "reason", "ret_type", "variables": {old:{name,type}}}.
    """
    args    = [lv for lv in lvars if lv.get("is_arg")]
    locals_ = [lv for lv in lvars if not lv.get("is_arg")]

    messages = history if history is not None else []
    if not messages:
        messages.append({"role": "system", "content": _STAGED_SYSTEM})

    # ── Stage 1: function name ──
    messages.append({"role": "user",
                     "content": _stage1_prompt(pseudocode, lvars, callees, callers, hints)})
    r1 = await _stream_chat(messages)
    o1 = extract_json_object(r1)
    messages.append({"role": "assistant", "content": _json_history(o1)})
    name = o1.get("name") or ""
    if not (isinstance(name, str) and name.isidentifier()):
        name = extract_name(r1) or ""
    reason = o1.get("reason") or o1.get("reasoning") or ""
    label = name if (isinstance(name, str) and name.isidentifier()) else "this function"

    # ── Stage 2: parameters ──
    arg_map: dict[str, dict] = {}
    if args:
        messages.append({"role": "user", "content": (
            f"Stage 2 — `{label}`. Name AND type its PARAMETERS: {_lvar_list(args)}. "
            'Reply JSON mapping each original name to {"name":..,"type":..}, '
            'e.g. {"a1": {"name": "buffer", "type": "uint8_t *"}}.')})
        r2 = await _stream_chat(messages)
        o2 = extract_json_object(r2)
        messages.append({"role": "assistant", "content": _json_history(o2)})
        arg_map = _filter_var_map(o2, args)

    # ── Stage 3: locals + return type ──
    messages.append({"role": "user", "content": (
        f"Stage 3 — now name AND type the LOCAL variables: {_lvar_list(locals_)}; "
        "and give the function's C RETURN type inferred from what it returns. Reply "
        'JSON: {"variables": {"v1": {"name":..,"type":..}}, "ret_type": "..."}.')})
    r3 = await _stream_chat(messages)
    o3 = extract_json_object(r3)
    messages.append({"role": "assistant", "content": _json_history(o3)})
    local_map = _filter_var_map(o3.get("variables") or o3, locals_)
    ret_type = o3.get("ret_type") or o3.get("return_type") or ""

    return {
        "name": name if (isinstance(name, str) and name.isidentifier()) else "",
        "reason": reason if isinstance(reason, str) else "",
        "ret_type": ret_type.strip() if isinstance(ret_type, str) else "",
        "variables": {**arg_map, **local_map},
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
    # First: search outside <think> blocks (normal case — model answered in content)
    outside = _THINK_RE.sub("", full_text)
    for line in outside.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("NAME:"):
            rest = stripped[5:].strip()
            candidate = rest.split()[0] if rest else ""
            if candidate and candidate.isidentifier():
                return candidate

    # Fallback: answer ended up inside <think> (reasoning budget exhausted mid-think).
    # Search the LAST think block in reverse so we pick the final conclusion, not an
    # intermediate guess from early reasoning.
    for block in reversed(_THINK_CONTENT_RE.findall(full_text)):
        for line in reversed(block.splitlines()):
            stripped = line.strip()
            if stripped.upper().startswith("NAME:"):
                rest = stripped[5:].strip()
                candidate = rest.split()[0] if rest else ""
                if candidate and candidate.isidentifier():
                    return candidate

    return None
