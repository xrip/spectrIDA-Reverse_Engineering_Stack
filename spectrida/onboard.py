"""First-run setup — a text flow (rich console, no TUI). Auto-detects IDA and
checks llama.cpp server. Has jokes. Skippable forever."""
from __future__ import annotations

import asyncio
import glob
import os
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from spectrida import config, voice
from spectrida.core import services

_GHOST = r"""[magenta]
        .-.
       (o o)    boo.
       | O |
       '~~~'[/]"""

_MODEL = "hf.co/gdfhhjk/spectrida-re-gguf"


def _detect_ida() -> str:
    """Find an IDA install with idalib, so we can wire it up automatically."""
    roots = [os.environ.get("ProgramFiles", r"C:\Program Files"),
             os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
             "/opt", "/Applications", str(Path.home())]
    cands: list[str] = []
    for r in roots:
        if not r:
            continue
        for pat in ("IDA Professional*", "IDA Pro*", "IDA*", "ida-*"):
            cands += glob.glob(os.path.join(r, pat))
    for c in sorted(set(cands), reverse=True):
        if services.idalib_ok(c):
            return c
    return ""


def run_onboarding(force: bool = False) -> None:
    if config.onboarded() and not force:
        return
    c = Console()
    w = min(c.width - 4, 88)  # leave 2-char margin each side, cap at 88
    c.print(_GHOST)
    c.print(Panel(
        "[b cyan]hey. i'm the ghost.[/]\n\n"
        "I name functions while you get coffee. I shard binaries so IDA doesn't take an "
        "eight-minute nap. I'm not Ghidra — never claimed to be — but the thing I do, I do "
        "[b]fast[/], and I'll be honest when I'm guessing.\n\n"
        "Quick setup. I'll do what I can automatically. [dim](demo mode needs none of it.)[/]",
        border_style="cyan", width=w))

    c.print("\n[b]checking your setup…[/]")
    c.print("  [green]✓[/]  Python — you're running me, so, yeah.")

    # ── IDA: auto-detect + wire up ──
    ida = config.idalib_dir()
    if ida and services.idalib_ok(ida):
        c.print(f"  [green]✓[/]  IDA / idalib — already configured ([dim]{ida}[/]).")
    else:
        found = _detect_ida()
        if found:
            ida = found
            c.print(f"  [green]✓[/]  IDA / idalib — [b]found and wired it up[/]: [dim]{found}[/]")
        else:
            c.print("  [yellow]•[/]  IDA / idalib — couldn't find it. Put the path in "
                    "[b]~/.spectrida/config.toml[/] under [b][ida] idalib[/]. "
                    "[dim](demo works without it.)[/]")

    # write the config now — preserve existing model if user already configured one
    existing_model = config.llamacpp_model()
    model_to_write = existing_model if existing_model and existing_model != "spectrida-re" else "spectrida-re"
    config.write_config(idalib=ida or "", model=model_to_write)

    # ── llama.cpp server + model ──
    async def _llamacpp_state():
        if not services.llamacpp_installed():
            return "missing", False
        running = await services.llamacpp_running() or await services.ensure_llamacpp()
        if not running:
            return "stopped", False
        return "running", await services.model_present()

    state, has_model = asyncio.run(_llamacpp_state())
    if state == "missing":
        c.print(f"  [yellow]•[/]  llama.cpp — not reachable:  [b]{services.llamacpp_install_hint()}[/]")
    elif state == "stopped":
        c.print("  [yellow]•[/]  llama.cpp — server not reachable. Start [b]llama-server[/] yourself.")
        c.print(f"       [dim]example model source: {_MODEL}[/]")
    else:
        c.print("  [green]✓[/]  llama.cpp server — up and awake.")
        if has_model:
            c.print("  [green]✓[/]  the model — loaded and ready. you absolute professional.")
        else:
            c.print("  [yellow]•[/]  the model — /v1/models did not report it.")

    config.set_onboarded()
    c.print()
    c.print(Panel(
        "[b]keys:[/]  [cyan]N[/] name  [cyan]R[/] rename  [cyan]C[/] chain  "
        "[cyan]D[/] decompile  [cyan]/[/] search  [cyan]B[/] batch  [cyan]?[/] help  [cyan]Q[/] quit\n\n"
        f"[dim]{voice.quip('welcome')}[/]\n\n"
        "[b]launching the demo — go ghost through some binaries.[/] 👻",
        border_style="dim cyan", width=w))
