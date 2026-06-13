"""Service checks for Ollama + idalib — used by the CLI and the onboarding wizard."""
from __future__ import annotations

import asyncio
from pathlib import Path

import httpx

from spectrida.config import idalib_dir, ollama_model, ollama_url

# ── Ollama ──────────────────────────────────────────────────────────────────

def ollama_installed() -> bool:
    # llama-server has no CLI to check — treat as "installed" if the server responds
    return True


def ollama_install_hint() -> str:
    return "start llama-server with your model (see project README)"


async def ollama_running() -> bool:
    try:
        async with httpx.AsyncClient(timeout=2) as c:
            return (await c.get(f"{ollama_url()}/health")).status_code == 200
    except Exception:
        return False


async def ensure_ollama() -> bool:
    """True if llama-server is reachable. Must be started manually."""
    return await ollama_running()


async def installed_models() -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=3) as c:
            data = (await c.get(f"{ollama_url()}/v1/models")).json()
        return [m.get("id", "") for m in data.get("data", [])]
    except Exception:
        return []


async def model_present(model: str | None = None) -> bool:
    # llama-server loads exactly one model at startup — if it's up, the model is there
    return await ollama_running()


async def ensure_model_loaded() -> bool:
    """Warm the model so the first real inference isn't cold."""
    try:
        async with httpx.AsyncClient(timeout=60) as c:
            await c.post(f"{ollama_url()}/v1/chat/completions", json={
                "model": ollama_model(),
                "messages": [{"role": "user", "content": "hi"}],
                "stream": False,
                "max_tokens": 1,
            })
        return True
    except Exception:
        return False


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
