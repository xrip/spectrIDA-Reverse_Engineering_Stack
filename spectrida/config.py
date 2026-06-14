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
    "llamacpp": {"base_url": "http://localhost:8080", "model": "spectrida-re"},
    "pipeline": {"workers": 16, "batch_concurrency": 1},
}

_CONFIG_ERROR = ""


def _load() -> dict:
    global _CONFIG_ERROR
    _CONFIG_ERROR = ""
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
    except Exception as e:
        _CONFIG_ERROR = f"{CONFIG_FILE}: {e}"
        return {k: dict(v) for k, v in _DEFAULT.items()}


_cfg = _load()


def reload_config() -> None:
    global _cfg
    _cfg = _load()


def config_error() -> str:
    return _CONFIG_ERROR


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


def llamacpp_url() -> str:
    return get("llamacpp", "base_url", "SPECTRIDA_LLAMACPP_URL") or "http://localhost:8080"


def llamacpp_model() -> str:
    return get("llamacpp", "model", "SPECTRIDA_LLAMACPP_MODEL") or "spectrida-re"


def pipeline_workers() -> int:
    try:
        return int(get("pipeline", "workers", "SPECTRIDA_WORKERS") or 16)
    except ValueError:
        return 16


def llm_max_tokens() -> int:
    """Max tokens for a naming reply. MUST exceed the llama-server --reasoning-budget,
    or the model spends its whole output thinking and the answer gets truncated
    (an unclosed <think> with no name). Default 8192 leaves room after a 4096 budget.
    """
    try:
        n = int(get("llamacpp", "max_tokens", "SPECTRIDA_LLAMACPP_MAX_TOKENS") or 8192)
    except ValueError:
        n = 8192
    return max(512, n)


def llm_temperature() -> float:
    try:
        t = float(get("llamacpp", "temperature", "SPECTRIDA_LLAMACPP_TEMPERATURE") or 0.0)
    except ValueError:
        t = 0.0
    return max(0.0, min(2.0, t))


def llm_top_p() -> float | None:
    raw = get("llamacpp", "top_p", "SPECTRIDA_LLAMACPP_TOP_P").strip()
    if not raw:
        return 0.9
    try:
        p = float(raw)
    except ValueError:
        return 0.9
    return max(0.0, min(1.0, p))


def llm_top_k() -> int | None:
    raw = get("llamacpp", "top_k", "SPECTRIDA_LLAMACPP_TOP_K").strip()
    if not raw:
        return 1
    try:
        k = int(raw)
    except ValueError:
        return 1
    return max(0, k)


def llamacpp_anthropic_version() -> str:
    return (
        get("llamacpp", "anthropic_version", "SPECTRIDA_LLAMACPP_ANTHROPIC_VERSION").strip()
        or "2023-06-01"
    )


def llamacpp_api_key() -> str:
    return get("llamacpp", "api_key", "SPECTRIDA_LLAMACPP_API_KEY").strip()


def llm_timeout() -> float:
    """HTTP timeout in seconds for a single LLM request.

    Must exceed the longest expected reasoning + generation time.
    Default 300 s (5 min). Override with SPECTRIDA_LLAMACPP_TIMEOUT or
    [llamacpp] timeout = 600.
    """
    try:
        return float(
            get("llamacpp", "timeout", "SPECTRIDA_LLAMACPP_TIMEOUT") or 300
        )
    except ValueError:
        return 300.0


def llm_retries() -> int:
    """How many times to retry a failed LLM request (connection errors, timeouts, 5xx).
    Default 3. Set SPECTRIDA_LLAMACPP_RETRIES=0 to disable."""
    try:
        return max(0, int(get("llamacpp", "retries", "SPECTRIDA_LLAMACPP_RETRIES") or 3))
    except ValueError:
        return 3


def llm_json_mode() -> bool:
    """Force JSON output via response_format=json_object.

    Works with llama-server b3805+. Set SPECTRIDA_LLAMACPP_JSON_MODE=0
    (or [llamacpp] json_mode = false) to disable for older servers.
    """
    raw = get("llamacpp", "json_mode", "SPECTRIDA_LLAMACPP_JSON_MODE").strip().lower()
    return raw not in ("0", "false", "no", "off")


def type_retry_enabled() -> bool:
    """One corrective LLM retry for types dropped as unknown_type (default OFF).

    When a proposed type names a struct/enum that isn't in the binary's type
    library, ask the model once for a replacement from existing/primitive types.
    Enable with SPECTRIDA_TYPE_RETRY=1 (or [pipeline] type_retry = true).
    """
    raw = get("pipeline", "type_retry", "SPECTRIDA_TYPE_RETRY").strip().lower()
    return raw in ("1", "true", "yes", "on")


def type_propagation_enabled() -> bool:
    """Push a function's pointer/struct return type onto caller variables that
    receive it (default ON). Disable with SPECTRIDA_TYPE_PROPAGATION=0.
    """
    raw = get("pipeline", "type_propagation", "SPECTRIDA_TYPE_PROPAGATION").strip().lower()
    return raw not in ("0", "false", "no", "off")


def name_cache_enabled() -> bool:
    """Cache naming results by normalized function content (default on).

    Gives identical functions identical names and makes re-runs cheap/stable.
    Disable with SPECTRIDA_NAME_CACHE=0 (or [pipeline] name_cache = false).
    """
    raw = get("pipeline", "name_cache", "SPECTRIDA_NAME_CACHE").strip().lower()
    return raw not in ("0", "false", "no", "off")


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
        "[llamacpp]\n"
        'base_url = "http://localhost:8080"\n'
        f'model = "{model}"\n'
        "# Anthropic Messages API: POST /v1/messages\n"
        "# must exceed server-side reasoning budget, or answers get truncated\n"
        "max_tokens = 8192\n"
        "# strict coding-agent sampling defaults\n"
        "temperature = 0.0\n"
        "top_p = 0.9\n"
        "top_k = 1\n"
        "# optional token for llama-server --api-key or compatible gateways\n"
        '# api_key = ""\n'
        'anthropic_version = "2023-06-01"\n\n'
        "[pipeline]\nworkers = 16\n"
        "# parallel AI naming requests in batch (1..4; needs llama-server --parallel N)\n"
        "# batch_concurrency = 1\n",
        encoding="utf-8",
    )
    reload_config()
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
            "[llamacpp]\n"
            'base_url = "http://localhost:8080"\n'
            "# Anthropic Messages API: POST /v1/messages\n"
            'model = "spectrida-re"\n\n'
            "# must exceed server-side reasoning budget, or answers get truncated\n"
            "max_tokens = 8192\n"
            "# strict coding-agent sampling defaults\n"
            "temperature = 0.0\n"
            "top_p = 0.9\n"
            "top_k = 1\n"
            '# api_key = ""\n'
            'anthropic_version = "2023-06-01"\n\n'
            "[pipeline]\n"
            "workers = 16\n"
            "# parallel AI naming requests in batch (1..4; needs llama-server --parallel N)\n"
            "# batch_concurrency = 1\n",
            encoding="utf-8",
        )
        reload_config()
    return CONFIG_FILE
