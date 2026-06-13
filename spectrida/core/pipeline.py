"""Wrapper around analysis/parallel_analyze.py — streams log lines to a callback.

The analyzer is a subprocess; we hand it the configured IDA + output paths via
env vars (SPECTRIDA_IDALIB / SPECTRIDA_OUTPUT_DIR) so nothing is hardcoded.
"""
from __future__ import annotations

import asyncio
import os
import re
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path

from spectrida.config import idalib_dir, output_dir, pipeline_script, pipeline_workers

_SAVED_RE = re.compile(r"saved.*?->\s*(.+\.i64)")
_TOTAL_RE = re.compile(r"total wall: ([\d.]+)s for ([\d,]+) funcs")


def _subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    env["SPECTRIDA_IDALIB"] = idalib_dir()
    env["SPECTRIDA_OUTPUT_DIR"] = str(output_dir())
    ida = idalib_dir()
    if ida:
        p = str(Path(ida).resolve())
        env["PATH"] = p + os.pathsep + env.get("PATH", "")
        env["PYTHONPATH"] = p + os.pathsep + env.get("PYTHONPATH", "")
        env["IDADIR"] = p
    return env


async def run_analysis(
    binary: str,
    workers: int | None = None,
    on_line: Callable[[str], Awaitable[None]] | None = None,
) -> dict:
    """Run the parallel analyzer, streaming log lines via on_line.
    Returns {"i64": path, "funcs": N, "elapsed": S} or {"error": msg}."""
    script = pipeline_script()
    if not script.exists():
        return {"error": f"analyzer not found: {script} (set SPECTRIDA_PIPELINE_DIR)"}
    if not idalib_dir():
        return {"error": "idalib not configured — run: spectrida onboard"}

    cmd = [sys.executable, "-u", str(script), binary, "--workers", str(workers or pipeline_workers())]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        cwd=str(script.parent), env=_subprocess_env(),
    )

    async def _emit(line: str) -> None:
        if not line:
            return
        if on_line:
            await on_line(line)
        if (m := _SAVED_RE.search(line)):
            result["i64"] = m.group(1).strip()
        if (m := _TOTAL_RE.search(line)):
            result["elapsed"] = float(m.group(1))
            result["funcs"] = int(m.group(2).replace(",", ""))

    result: dict = {}
    assert proc.stdout
    buf = b""
    while True:
        chunk = await proc.stdout.read(4096)
        if not chunk:
            break
        buf += chunk
        # split on \r\n, \n, or \r — pick whichever comes first
        while True:
            crlf = buf.find(b"\r\n")
            lf   = buf.find(b"\n")
            cr   = buf.find(b"\r")
            candidates = [(i, s) for i, s in [(crlf, b"\r\n"), (lf, b"\n"), (cr, b"\r")] if i >= 0]
            if not candidates:
                break
            pos, sep = min(candidates, key=lambda x: x[0])
            await _emit(buf[:pos].decode("utf-8", errors="replace").strip())
            buf = buf[pos + len(sep):]
    if buf.strip():
        await _emit(buf.decode("utf-8", errors="replace").strip())

    await proc.wait()
    if proc.returncode != 0 and "i64" not in result:
        result["error"] = f"analyzer exited {proc.returncode}"
    return result


def default_i64(binary: str) -> str:
    return str(output_dir() / f"{Path(binary).stem}_parallel.i64")
