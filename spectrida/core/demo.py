"""Canned data so the TUI runs with no IDA and no llama.cpp server."""
from __future__ import annotations

import asyncio
import re

# A tiny fake il2cpp-ish database. Some functions are named; the sub_* ones are
# there for you to "name" with the (fake) model during the demo/tutorial.
FUNCTIONS: list[dict] = [
    {"name": "GameManager$$Update",      "start": 0x140001000, "end": 0x1400010C0, "size": 192},
    {"name": "Player$$TakeDamage",       "start": 0x140001100, "end": 0x140001210, "size": 272},
    {"name": "Player$$Respawn",          "start": 0x140001220, "end": 0x1400012E0, "size": 192},
    {"name": "sub_1400013A0",            "start": 0x1400013A0, "end": 0x140001460, "size": 192},
    {"name": "Enemy$$Attack",            "start": 0x140001480, "end": 0x140001560, "size": 224},
    {"name": "sub_140001600",            "start": 0x140001600, "end": 0x1400016A0, "size": 160},
    {"name": "Inventory$$AddItem",       "start": 0x140001700, "end": 0x1400017F0, "size": 240},
    {"name": "sub_140001820",            "start": 0x140001820, "end": 0x1400018B0, "size": 144},
    {"name": "SaveSystem$$Serialize",    "start": 0x140001900, "end": 0x140001A40, "size": 320},
    {"name": "sub_140001A80",            "start": 0x140001A80, "end": 0x140001B20, "size": 160},
    {"name": "NetworkClient$$SendPacket","start": 0x140001B40, "end": 0x140001C80, "size": 320},
    {"name": "sub_140001D00",            "start": 0x140001D00, "end": 0x140001D90, "size": 144},
]

_DISASM = {
    0x1400013A0: [
        ("0x1400013a0", "push    rbp"),
        ("0x1400013a1", "mov     rbp, rsp"),
        ("0x1400013a4", "movss   xmm0, dword ptr [rcx+0x40]"),
        ("0x1400013a9", "subss   xmm0, dword ptr [rdx]"),
        ("0x1400013ad", "movss   dword ptr [rcx+0x40], xmm0"),
        ("0x1400013b2", "comiss  xmm0, dword ptr [rip+0x1c4a]"),
        ("0x1400013ba", "ja      0x1400013d0"),
        ("0x1400013bc", "call    Player$$Respawn"),
        ("0x1400013c1", "xor     eax, eax"),
        ("0x1400013c3", "pop     rbp"),
        ("0x1400013c4", "ret"),
    ],
}
_DEFAULT_DISASM = [
    ("0x140000000", "push    rbp"),
    ("0x140000001", "mov     rbp, rsp"),
    ("0x140000004", "mov     rax, qword ptr [rcx]"),
    ("0x140000007", "test    rax, rax"),
    ("0x14000000a", "je      0x140000020"),
    ("0x14000000c", "call    qword ptr [rax+0x18]"),
    ("0x14000000f", "pop     rbp"),
    ("0x140000010", "ret"),
]

# callee links keyed by function start (proto = signature so the model sees params)
_XREFS_FROM = {
    0x1400013A0: [{"address": "0x140001220", "name": "Player$$Respawn",
                   "proto": "void Player__Respawn(Entity *this)"}],
    0x140001100: [{"address": "0x1400013a0", "name": "sub_1400013A0", "proto": ""}],
    0x140001000: [{"address": "0x140001100", "name": "Player$$TakeDamage",
                   "proto": "void Player__TakeDamage(Entity *this, float amount)"},
                  {"address": "0x140001480", "name": "Enemy$$Attack",
                   "proto": "void Enemy__Attack(Entity *this, Entity *target)"}],
}
_XREFS_TO = {
    0x140001220: [{"address": "0x1400013a0", "name": "sub_1400013A0", "proto": ""}],
    0x1400013A0: [{"address": "0x140001100", "name": "Player$$TakeDamage",
                   "proto": "void Player__TakeDamage(Entity *this, float amount)"}],
    0x140001100: [{"address": "0x140001000", "name": "GameManager$$Update",
                   "proto": "void GameManager__Update(GameManager *this, float dt)"}],
}

# what the (fake) model "decides" sub_* functions should be called
_DEMO_NAMES = {
    0x1400013A0: ("apply_fall_damage",
                  "Subtracts a delta from a float health field at [rcx+0x40], clamps, "
                  "and calls Player$$Respawn when it drops below zero. Classic damage tick."),
    0x140001600: ("normalize_vector3", "Reads three floats, computes inverse sqrt of the sum of squares, scales."),
    0x140001820: ("hash_string_fnv", "FNV-1a loop over a byte buffer — multiply by prime, xor next byte."),
    0x140001A80: ("clamp_health", "min/max guard on a float field, writes it back."),
    0x140001D00: ("crc32_block", "Table-driven CRC over a length-prefixed buffer."),
}


def _norm(addr) -> int:
    if isinstance(addr, int):
        return addr
    return int(addr, 16) if str(addr).startswith("0x") else int(addr)


def disasm(addr) -> list[dict]:
    rows = _DISASM.get(_norm(addr), _DEFAULT_DISASM)
    return [{"address": a, "text": t} for a, t in rows]


def decompile(addr) -> str:
    a = _norm(addr)
    if a in _DEMO_NAMES:
        return ("// (demo) reconstructed pseudocode\n"
                "void __fastcall demo(Entity *e, float *delta) {\n"
                "    e->health -= *delta;\n"
                "    if (e->health < 0.0)\n"
                "        Player__Respawn(e);\n"
                "}\n")
    return "// (demo) no pseudocode for this one — try a sub_ function."


# signatures for the named demo functions (sub_* have none)
_DEMO_PROTOS = {
    0x140001000: "void GameManager__Update(GameManager *this, float dt)",
    0x140001100: "void Player__TakeDamage(Entity *this, float amount)",
    0x140001220: "void Player__Respawn(Entity *this)",
    0x140001480: "void Enemy__Attack(Entity *this, Entity *target)",
    0x140001700: "bool Inventory__AddItem(Inventory *this, Item *item)",
    0x140001900: "int SaveSystem__Serialize(SaveSystem *this, char *buf)",
    0x140001B40: "int NetworkClient__SendPacket(NetworkClient *this, Packet *pkt)",
}


def get_protos(addresses: list) -> dict:
    out = {}
    for x in addresses:
        ea = _norm(x)
        out[hex(ea)] = _DEMO_PROTOS.get(ea, "")
    return out


# naming hints per function for the demo
_DEMO_META = {
    0x1400013A0: {"strings": [], "constants": ["0x0"], "api_calls": [],
                  "function_facts": {"size": 96, "instruction_count": 24,
                                     "leaf": False, "calls_out": 1, "callers": 1},
                  "field_accesses": ["[rcx+40h] in movss xmm0, dword ptr [rcx+40h]"]},
    0x140001820: {"strings": [], "constants": ["0x1000193", "0x811c9dc5"],
                  "classified_constants": ["0x1000193 (FNV-1a prime)",
                                           "0x811c9dc5 (FNV-1a offset basis)"],
                  "api_calls": []},
    0x140001D00: {"strings": [], "constants": ["0xedb88320"],
                  "classified_constants": ["0xedb88320 (CRC32 polynomial)"],
                  "api_calls": []},
    0x140001B40: {"strings": ["POST /api/telemetry"], "constants": [],
                  "api_calls": ["ws2_32!send(SOCKET,char *,int,int)", "ws2_32!htons"],
                  "callsite_snippets": ["0x140001b80 -> send: call cs:send"],
                  "globals": ["reads/refs g_network_client at 0x140030010"]},
}


def get_func_meta(addr) -> dict:
    return _DEMO_META.get(_norm(addr), {"strings": [], "constants": [], "api_calls": []})


def xrefs_from(addr) -> list[dict]:
    return _XREFS_FROM.get(_norm(addr), [])


def xrefs_to(addr) -> list[dict]:
    return _XREFS_TO.get(_norm(addr), [])


async def stream_name(addr):
    """Fake token-by-token model output for the demo model pane."""
    name, reason = _DEMO_NAMES.get(_norm(addr), ("demo_function", "A perfectly cromulent function. (demo mode — no real model running.)"))
    text = f"NAME: {name}\nREASON: {reason}"
    for chunk in text.split(" "):
        await asyncio.sleep(0.03)
        yield chunk + " "


# ── variable naming (demo) ───────────────────────────────────────────────────

# generic pseudocode with a1/v1.. names, keyed by function start
_DEMO_PSEUDO = (
    "void __fastcall sub(Entity *a1, float *a2) {\n"
    "    float v1;\n"
    "    v1 = a1->field_40 - *a2;\n"
    "    a1->field_40 = v1;\n"
    "    if (v1 < 0.0)\n"
    "        Player__Respawn(a1);\n"
    "}\n"
)
_DEMO_LVARS = [
    {"name": "a1", "type": "Entity *", "is_arg": True},
    {"name": "a2", "type": "float *",  "is_arg": True},
    {"name": "v1", "type": "float",    "is_arg": False},
]
# what the (fake) model "decides" each generic var should be called + typed
_DEMO_VAR_NAMES = {"a1": "entity", "a2": "damage_ptr", "v1": "new_health"}
_DEMO_VAR_TYPES = {"a1": "Entity *", "a2": "float *", "v1": "float"}

# per-function live state so demo renames stick + re-render
_demo_var_state: dict[int, dict] = {}


def _demo_state(a: int) -> dict:
    if a not in _demo_var_state:
        _demo_var_state[a] = {
            "pseudocode": _DEMO_PSEUDO,
            "lvars": [dict(lv) for lv in _DEMO_LVARS],
        }
    return _demo_var_state[a]


def get_lvars(addr) -> dict:
    st = _demo_state(_norm(addr))
    return {"pseudocode": st["pseudocode"], "lvars": [dict(lv) for lv in st["lvars"]]}


def name_variables(pseudocode: str, lvars: list[dict]) -> dict:
    return {lv["name"]: {"name": _DEMO_VAR_NAMES[lv["name"]],
                         "type": _DEMO_VAR_TYPES.get(lv["name"], "")}
            for lv in lvars if lv["name"] in _DEMO_VAR_NAMES}


def name_function_staged(pseudocode: str, lvars: list[dict],
                         callees: list, callers: list, history=None) -> dict:
    """Staged demo response — the fake model 'concludes' name + reason + ret_type + vars."""
    return {
        "name": "apply_fall_damage",
        "reason": "Subtracts a delta from a float health field and respawns when it "
                  "drops below zero. (demo mode — no real model running.)",
        "ret_type": "void",
        "variables": name_variables(pseudocode, lvars),
    }


def rename_lvars(addr, names: dict, ret_type: str = "") -> dict:
    st = _demo_state(_norm(addr))
    code = st["pseudocode"]
    renamed = 0
    retyped = 0
    for old, spec in names.items():
        new = spec.get("name", "") if isinstance(spec, dict) else spec
        ty  = spec.get("type", "") if isinstance(spec, dict) else ""
        if new and new != old and new.isidentifier():
            code = re.sub(rf"\b{re.escape(old)}\b", new, code)
            for lv in st["lvars"]:
                if lv["name"] == old:
                    lv["name"] = new
                    if ty:
                        lv["type"] = ty
            renamed += 1
        if ty:
            retyped += 1
    if ret_type:
        # reflect the return type in the demo pseudocode's leading 'void'
        code = re.sub(r"^void\b", ret_type, code, count=1)
        retyped += 1
    st["pseudocode"] = code
    return {"renamed": renamed, "retyped": retyped,
            "ret_type": ret_type, "pseudocode": code}
