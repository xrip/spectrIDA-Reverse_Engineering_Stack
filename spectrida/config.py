"""spectrIDA config — reads ~/.spectrida/config.toml, falls back to env vars.

Every path the tool needs comes from here; nothing is hardcoded. A first-run
marker (``~/.spectrida/.onboarded``) records whether the wizard has run, so it
only auto-launches once.
"""
from __future__ import annotations

import os
from pathlib import Path

try:
    import tomllib
except ImportError:  # py < 3.11
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore

CONFIG_DIR  = Path.home() / ".spectrida"
CONFIG_FILE = CONFIG_DIR / "config.toml"
_ONBOARD_MARKER = CONFIG_DIR / ".onboarded"

_DEFAULT = {
    "ida":      {"idalib": "", "output_dir": str(CONFIG_DIR / "output")},
    "ollama":   {"base_url": "http://localhost:8080", "model": "spectrida-re"},
    "pipeline": {"workers": 16, "batch_concurrency": 1},
}


def _load() -> dict:
    if tomllib is None or not CONFIG_FILE.exists():
        return {k: dict(v) for k, v in _DEFAULT.items()}
    try:
        with open(CONFIG_FILE, "rb") as f:
            raw = f.read()
        # strip BOM if present (written by some Windows editors)
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        user = tomllib.loads(raw.decode("utf-8", errors="replace"))
        result = {k: dict(v) for k, v in _DEFAULT.items()}
        for section, values in user.items():
            if isinstance(result.get(section), dict) and isinstance(values, dict):
                result[section].update(values)
            else:
                result[section] = values
        return result
    except Exception:
        return {k: dict(v) for k, v in _DEFAULT.items()}


_cfg = _load()


def get(section: str, key: str, env_var: str | None = None) -> str:
    if env_var and os.environ.get(env_var):
        return os.environ[env_var]
    return str(_cfg.get(section, {}).get(key, ""))


# ── path / service accessors ────────────────────────────────────────────────

def idalib_dir() -> str:
    return get("ida", "idalib", "SPECTRIDA_IDALIB")


def output_dir() -> Path:
    p = Path(get("ida", "output_dir", "SPECTRIDA_OUTPUT_DIR") or (CONFIG_DIR / "output"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def ollama_url() -> str:
    return get("ollama", "base_url", "SPECTRIDA_OLLAMA_URL") or "http://localhost:8080"


def ollama_model() -> str:
    return get("ollama", "model", "SPECTRIDA_MODEL") or "spectrida-re"


def pipeline_workers() -> int:
    try:
        return int(get("pipeline", "workers", "SPECTRIDA_WORKERS") or 16)
    except ValueError:
        return 16


def batch_concurrency() -> int:
    """How many AI naming requests to run in parallel during batch (1 = sequential).

    Clamped to 1..4. Parallelism only helps if llama-server was started with
    multiple slots (e.g. --parallel 4); otherwise requests queue server-side.
    """
    try:
        n = int(get("pipeline", "batch_concurrency", "SPECTRIDA_BATCH_CONCURRENCY") or 1)
    except ValueError:
        n = 1
    return max(1, min(4, n))


def pipeline_script() -> Path:
    """parallel_analyze.py — bundled in the package, or overridden by env."""
    env = os.environ.get("SPECTRIDA_PIPELINE_DIR", "")
    base = Path(env) if env else Path(__file__).parent / "analysis"
    return base / "parallel_analyze.py"


# ── onboarding flag ─────────────────────────────────────────────────────────

def onboarded() -> bool:
    """True once the wizard has completed/skipped. Env forces a skip for CI/scripts."""
    if os.environ.get("SPECTRIDA_NO_ONBOARD"):
        return True
    return _ONBOARD_MARKER.exists()


def set_onboarded() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _ONBOARD_MARKER.touch()


# ── starter config ──────────────────────────────────────────────────────────

def write_config(idalib: str = "", model: str = "spectrida-re") -> Path:
    """Write config.toml with concrete values (used by onboarding auto-setup)."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    ida_line = (f'idalib = "{Path(idalib).as_posix()}"\n' if idalib
                else '# idalib = "C:/Program Files/IDA Professional 9.1"\n')
    CONFIG_FILE.write_text(
        "# spectrIDA configuration - https://github.com/ggfuchsi-oss/spectrIDA\n\n"
        f"[ida]\n{ida_line}"
        f'output_dir = "{output_dir().as_posix()}"\n\n'
        "[ollama]\n"
        'base_url = "http://localhost:8080"\n'
        f'model = "{model}"\n\n'
        "[pipeline]\nworkers = 16\n"
        "# parallel AI naming requests in batch (1..4; needs llama-server --parallel N)\n"
        "# batch_concurrency = 1\n",
        encoding="utf-8",
    )
    return CONFIG_FILE


def write_default_config() -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(
            "# spectrIDA configuration - https://github.com/ggfuchsi-oss/spectrIDA\n\n"
            "[ida]\n"
            '# Path to the IDA install dir containing idalib.dll / libidalib.so\n'
            '# idalib = "C:/Program Files/IDA Professional 9.1"\n'
            f'output_dir = "{output_dir().as_posix()}"\n\n'
            "[ollama]\n"
            'base_url = "http://localhost:8080"\n'
            "# run: ollama pull hf.co/gdfhhjk/spectrida-re-gguf\n"
            'model = "spectrida-re"\n\n'
            "[pipeline]\n"
            "workers = 16\n"
            "# parallel AI naming requests in batch (1..4; needs llama-server --parallel N)\n"
            "# batch_concurrency = 1\n",
            encoding="utf-8",
        )
    return CONFIG_FILE
