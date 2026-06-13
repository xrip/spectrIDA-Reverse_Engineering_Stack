"""spectrIDA CLI."""
from __future__ import annotations

from pathlib import Path

import typer

app = typer.Typer(add_completion=False, help="Ghost through binaries — parallel IDA analysis + AI naming.")


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    demo: bool = typer.Option(False, "--demo", help="Run the TUI on canned data (no IDA/llama.cpp)."),
    no_onboard: bool = typer.Option(False, "--no-onboard", help="Skip the first-run wizard."),
):
    from spectrida import config
    if not config.onboarded() and not no_onboard:
        from spectrida.onboard import run_onboarding
        run_onboarding()
        if ctx.invoked_subcommand is None:
            demo = True  # first-run bare command → land in the demo
    if ctx.invoked_subcommand is None:
        from spectrida.tui.app import SpectrIDAApp
        SpectrIDAApp(demo=demo).run()


@app.command()
def analyze(
    binary: str = typer.Argument(..., help="Binary to analyze (DLL/EXE/NSO…)."),
    workers: int = typer.Option(None, "-w", "--workers"),
    force: bool = typer.Option(False, "-f", "--force",
        help="Re-analyze without asking, even if a database already exists."),
):
    """Run parallel analysis, then open the browser."""
    p = Path(binary).expanduser()
    if not p.exists():
        typer.echo(f"error: not found: {p}", err=True)
        raise typer.Exit(1)

    from spectrida.tui.app import SpectrIDAApp
    from spectrida.core.pipeline import default_i64

    # Guard: a previous analysis (and any manual renaming you did in it) lives in
    # this .i64. Re-analyzing opens the RAW binary and overwrites it from scratch,
    # discarding that work — so ask first unless --force.
    existing = Path(default_i64(str(p.resolve())))
    if existing.exists() and not force:
        typer.echo(f"\n  a database already exists:\n    {existing}")
        typer.echo("  re-analyzing rebuilds it from the raw binary and DISCARDS any "
                   "names you added there.\n")
        choice = typer.prompt(
            "  [O]pen existing  ·  [R]e-analyze (backs up the old one)  ·  [C]ancel",
            default="O",
        ).strip().lower()[:1]

        if choice == "o":
            SpectrIDAApp(i64=str(existing.resolve())).run()
            return
        if choice != "r":
            typer.echo("  cancelled.")
            raise typer.Exit(0)

        # Re-analyze: back up the old database so the work is never truly lost.
        import time
        backup = existing.with_name(f"{existing.stem}.bak-{time.strftime('%Y%m%d-%H%M%S')}.i64")
        try:
            existing.replace(backup)
            typer.echo(f"  backed up old database -> {backup}")
        except Exception as e:
            typer.echo(f"  warning: could not back up old database: {e}", err=True)

    SpectrIDAApp(binary=str(p.resolve()), workers=workers).run()


@app.command("open")
def open_(i64: str = typer.Argument(..., help="Path to an .i64 database.")):
    """Open an existing .i64 in the browser."""
    p = Path(i64).expanduser()
    if not p.exists():
        typer.echo(f"error: not found: {p}", err=True)
        raise typer.Exit(1)
    from spectrida.tui.app import SpectrIDAApp
    SpectrIDAApp(i64=str(p.resolve())).run()


@app.command()
def onboard():
    """Re-run the setup wizard, then open the demo."""
    from spectrida.onboard import run_onboarding
    run_onboarding(force=True)
    from spectrida.tui.app import SpectrIDAApp
    SpectrIDAApp(demo=True).run()


@app.command()
def export(
    i64:        str = typer.Argument(..., help="Path to .i64 database."),
    output:     str = typer.Option(None, "-o", "--output", help="Output file (default: <stem>.<fmt>)."),
    fmt:        str = typer.Option("json", "-f", "--format", help="json | csv | idc | symbols"),
    named_only: bool = typer.Option(False, "--named-only", help="Skip sub_* functions."),
):
    """Export all function names + addresses to a file."""
    import asyncio
    from spectrida.api import open_i64, loading_line

    p = Path(i64).expanduser()
    if not p.exists():
        typer.echo(f"error: not found: {p}", err=True); raise typer.Exit(1)

    out = Path(output) if output else p.with_suffix(f".{fmt}")
    typer.echo(loading_line())

    async def _run():
        async with open_i64(str(p)) as db:
            result = await db.export(out, fmt=fmt, named_only=named_only)
            funcs = await db.list_functions()
            n = len(funcs) if not named_only else sum(
                1 for f in funcs if not f["name"].lower().startswith("sub_"))
            typer.echo(f"exported {n:,} functions -> {result}")

    asyncio.run(_run())


@app.command()
def overview(
    i64:     str = typer.Argument(..., help="Path to .i64 database."),
    extra:   list[str] = typer.Option([], "-a", "--addr",
                 help="Extra function addresses to include (hex, repeatable)."),
    sample:  int = typer.Option(120, "-n", "--sample", help="Number of functions to sample."),
):
    """Ask the AI to describe what this binary does."""
    import asyncio
    from spectrida.api import open_i64, loading_line

    p = Path(i64).expanduser()
    if not p.exists():
        typer.echo(f"error: not found: {p}", err=True); raise typer.Exit(1)

    addrs = [int(a, 16) if a.startswith("0x") else int(a, 16) for a in extra]
    typer.echo(loading_line())

    async def _run():
        async with open_i64(str(p)) as db:
            it = await db.overview(sample_size=sample, extra_addresses=addrs or None, stream=True)
            async for tok in it:
                typer.echo(tok, nl=False)
        typer.echo()

    asyncio.run(_run())


@app.command()
def serve():
    """Check llama.cpp server + the model are ready."""
    import asyncio

    from spectrida.config import llamacpp_model, llamacpp_url
    from spectrida.core.services import ensure_llamacpp, ensure_model_loaded, model_present

    async def _check():
        if not await ensure_llamacpp():
            typer.echo(f"✗ llama.cpp server not reachable at {llamacpp_url()}", err=True)
            raise typer.Exit(1)
        typer.echo("● llama.cpp server up")
        if await model_present():
            await ensure_model_loaded()
            typer.echo(f"● {llamacpp_model()} ready")
        else:
            typer.echo(f"✗ {llamacpp_model()} did not answer a /v1/messages ping", err=True)

    asyncio.run(_check())


def main() -> None:
    app()


if __name__ == "__main__":
    main()
