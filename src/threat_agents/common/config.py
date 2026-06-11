"""Minimal, dependency-free .env loader.

Loads a project `.env` into `os.environ` (existing env wins via setdefault). The Anthropic SDK
reads ANTHROPIC_API_KEY / ANTHROPIC_BASE_URL from the environment automatically, so calling
`load_env()` before constructing `AnthropicLLM` is all that's needed. Never commit `.env`.
"""

from __future__ import annotations

import os
import pathlib


def find_dotenv(start: pathlib.Path | None = None) -> pathlib.Path | None:
    start = start or pathlib.Path.cwd()
    for cand in [start, *start.parents]:
        p = cand / ".env"
        if p.exists():
            return p
    return None


def load_env(path: str | pathlib.Path | None = None) -> dict[str, str]:
    p = pathlib.Path(path) if path else find_dotenv()
    if not p or not p.exists():
        return {}
    loaded: dict[str, str] = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)
        loaded[key] = val
    return loaded


def anthropic_default_model(fallback: str = "claude-sonnet-4-6") -> str:
    return os.environ.get("ANTHROPIC_DEFAULT_MODEL", fallback)
