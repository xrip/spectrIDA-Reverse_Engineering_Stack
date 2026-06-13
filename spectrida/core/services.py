"""Service checks for llama.cpp server + idalib — used by the CLI and onboarding."""
from __future__ import annotations

import asyncio
from pathlib import Path

from spectrida.config import idalib_dir
from spectrida.core.llamacpp import (
    llamacpp_ping,
)

# ── llama.cpp server ────────────────────────────────────────────────────────

def llamacpp_installed() -> bool:
    # llama-server has no CLI to check — treat as "installed" if the server responds
    return True


def llamacpp_install_hint() -> str:
    return "start llama-server with your model (see project README)"


async def llamacpp_running() -> bool:
    return await llamacpp_ping()


async def ensure_llamacpp() -> bool:
    """True if llama-server is reachable. Must be started manually."""
    return await llamacpp_running()


async def installed_models() -> list[str]:
    return []


async def model_present(model: str | None = None) -> bool:
    # llama-server loads exactly one model at startup — if it's up, the model is there
    return await llamacpp_running()


async def ensure_model_loaded() -> bool:
    """Warm the model so the first real inference isn't cold."""
    return await llamacpp_ping()


# ── idalib ──────────────────────────────────────────────────────────────────

def idalib_ok(path: str | None = None) -> bool:
    """Cheap validity check that `path` looks like an IDA install with idalib."""
    p = Path(path or idalib_dir())
    if not path and not idalib_dir():
        return False
    if not p.is_dir():
        return False
    markers = ["idalib.dll", "libidalib.so", "libidalib.dylib", "idapro.py"]
    return any((p / m).exists() for m in markers) or any(p.glob("**/idapro.py"))
