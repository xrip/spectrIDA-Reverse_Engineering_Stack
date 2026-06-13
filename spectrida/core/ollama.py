"""llama.cpp server streaming client for function naming (OpenAI-compatible API)."""
from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator

import httpx

from spectrida.config import ollama_model, ollama_url

_SYSTEM = (
    "You are an expert reverse engineer specialising in C++ game binaries. "
    "Given x86-64 assembly and call-chain context, output a concise snake_case "
    "function name followed by a SHORT reasoning (3-5 sentences max). "
    "Format:\nNAME: <name>\nREASON: <reasoning>"
)

_THINK_RE         = re.compile(r"<think>.*?</think>", re.DOTALL)
_THINK_CONTENT_RE = re.compile(r"<think>(.*?)</think>", re.DOTALL)


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
    payload = {
        "model": ollama_model(),
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user",   "content": _build_prompt(insns, callees, callers)},
        ],
        "stream": True,
        "temperature": 0.2,
        "max_tokens": 2048,
    }
    content_seen = False
    reasoning_buf: list[str] = []

    async with httpx.AsyncClient(timeout=120) as client:
        async with client.stream("POST", f"{ollama_url()}/v1/chat/completions", json=payload) as resp:
            async for line in resp.aiter_lines():
                if not line or not line.startswith("data: "):
                    continue
                data = line[6:]
                if data.strip() == "[DONE]":
                    break
                try:
                    chunk = json.loads(data)
                except json.JSONDecodeError:
                    continue
                delta = (chunk.get("choices") or [{}])[0].get("delta", {})
                content   = delta.get("content")
                reasoning = delta.get("reasoning_content")
                if content:
                    content_seen = True
                    yield content
                elif reasoning:
                    reasoning_buf.append(reasoning)

    # Fallback: model answered inside reasoning_content (budget message triggered).
    # Wrap in think tags so extract_name can locate NAME: as a fallback.
    if not content_seen and reasoning_buf:
        yield "<think>" + "".join(reasoning_buf) + "</think>"


async def name_function(insns: list[dict], callees: list[str], callers: list[str]) -> str:
    """Non-streaming convenience used by batch mode — returns the extracted name."""
    full = "".join([tok async for tok in stream_name(insns, callees, callers)])
    return extract_name(full) or ""


# ── shared streaming helper ──────────────────────────────────────────────────

async def _stream_chat(messages: list[dict], *, temperature: float = 0.2,
                       max_tokens: int = 2048) -> str:
    """POST a chat completion (non-incremental), return the full text.

    Prefers delta.content; falls back to delta.reasoning_content when a reasoning
    model (--reasoning on) put the whole answer inside its thinking instead.
    """
    payload = {
        "model": ollama_model(),
        "messages": messages,
        "stream": True,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    content_seen = False
    content_buf: list[str] = []
    reasoning_buf: list[str] = []
    async with httpx.AsyncClient(timeout=120) as client:
        async with client.stream("POST", f"{ollama_url()}/v1/chat/completions", json=payload) as resp:
            async for line in resp.aiter_lines():
                if not line or not line.startswith("data: "):
                    continue
                data = line[6:]
                if data.strip() == "[DONE]":
                    break
                try:
                    chunk = json.loads(data)
                except json.JSONDecodeError:
                    continue
                delta = (chunk.get("choices") or [{}])[0].get("delta", {})
                if delta.get("content"):
                    content_seen = True
                    content_buf.append(delta["content"])
                elif delta.get("reasoning_content"):
                    reasoning_buf.append(delta["reasoning_content"])
    return "".join(content_buf) if content_seen else "".join(reasoning_buf)


# ── variable / parameter naming ──────────────────────────────────────────────

_VARS_SYSTEM = (
    "You are an expert reverse engineer. Given decompiler pseudocode with "
    "generic local/parameter names (a1, a2, v1, v3, ...), suggest for each a "
    "descriptive snake_case NAME and, when the code makes it clear, a concrete C "
    "TYPE (e.g. 'int', 'char *', 'Player *', 'unsigned int'). Reply ONLY with a "
    "single JSON object mapping the ORIGINAL name to {\"name\":..,\"type\":..}. "
    "Use the existing type if you can't improve it; omit a var you can't name. "
    'Example: {"a1": {"name": "player", "type": "Player *"}, '
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


# ── combined: function name + reasoning + variables in ONE call ──────────────

_COMBINED_SYSTEM = (
    "You are an expert reverse engineer specialising in C++ game binaries. "
    "Given decompiler pseudocode (with generic names a1, v3, ...) plus call-chain "
    "context, produce in ONE response: a concise snake_case FUNCTION name, a SHORT "
    "reasoning (1-3 sentences), the function's C RETURN TYPE inferred from what it "
    "returns (e.g. 'void', 'bool', 'int', 'char *'), and for each local/parameter a "
    "descriptive snake_case NAME plus a concrete C TYPE when the code makes it clear "
    "(e.g. 'char *', 'Player *', 'unsigned int'). Reply ONLY with a single JSON "
    "object, no prose:\n"
    '{"name": "validate_checksum", "reason": "...", "ret_type": "bool", "variables": '
    '{"a1": {"name": "buffer", "type": "char *"}, '
    '"v3": {"name": "crc", "type": "unsigned int"}}}\n'
    "Omit from 'variables' anything you can't confidently name; leave 'type'/"
    "'ret_type' empty if unsure."
)


def _hints_block(hints: dict | None) -> str:
    """Render extra naming signals: referenced strings, API/import calls, constants."""
    if not hints:
        return ""
    out = ""
    strings = [s for s in (hints.get("strings") or []) if s][:12]
    apis    = [s for s in (hints.get("api_calls") or []) if s][:12]
    consts  = [s for s in (hints.get("constants") or []) if s][:12]
    if strings:
        out += "Referenced strings:\n" + "".join(f'  - "{s}"\n' for s in strings)
    if apis:
        out += "Calls to known APIs/imports: " + ", ".join(apis) + "\n"
    if consts:
        out += "Notable constants: " + ", ".join(consts) + "\n"
    return out


def _build_combined_prompt(pseudocode: str, lvars: list[dict],
                           callees: list[str], callers: list[str],
                           hints: dict | None = None) -> str:
    names = ", ".join(f"{lv['name']}" + (f" ({lv['type']})" if lv.get("type") else "")
                      for lv in lvars) or "none"
    return (
        f"{_ctx_block('Calls', callees)}"
        f"{_ctx_block('Called by', callers)}"
        f"{_hints_block(hints)}"
        f"Variables to name: {names}\n\n"
        f"Pseudocode:\n{pseudocode[:6000]}\n\n"
        "Return the JSON now:"
    )


async def name_function_and_vars(
    pseudocode: str,
    lvars: list[dict],
    callees: list[str],
    callers: list[str],
    hints: dict | None = None,
) -> dict:
    """ONE LLM call → {"name", "reason", "ret_type", "variables": {old:{name,type}}}."""
    full = await _stream_chat([
        {"role": "system", "content": _COMBINED_SYSTEM},
        {"role": "user",   "content": _build_combined_prompt(pseudocode, lvars, callees, callers, hints)},
    ])
    obj = extract_json_object(full)
    name = obj.get("name") or ""
    if not (isinstance(name, str) and name.isidentifier()):
        name = extract_name(full) or ""   # fallback: model used NAME: format
    reason = obj.get("reason") or obj.get("reasoning") or ""
    ret_type = obj.get("ret_type") or obj.get("return_type") or ""
    return {
        "name": name if isinstance(name, str) and name.isidentifier() else "",
        "reason": reason if isinstance(reason, str) else "",
        "ret_type": ret_type.strip() if isinstance(ret_type, str) else "",
        "variables": _filter_var_map(obj.get("variables") or {}, lvars),
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
