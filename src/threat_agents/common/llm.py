"""LLM access behind a narrow Protocol.

The architecture's first principle: *the framework is the control flow; the LLM only fills
bounded nodes.* So graphs depend on `LLMClient`, never on a concrete SDK, and never let the
model decide routing. `StubLLM` is an offline, deterministic double that mirrors the JSON
contract, which is what makes graph topology and the deterministic critics testable with no
API key. `CRITIC_MODEL` differs from `DEFAULT_MODEL` on purpose — a *different model* is one
of the critic independence levers (05 §2.4 / C5).
"""

from __future__ import annotations

import json
import re
from typing import Callable, Optional, Protocol, runtime_checkable

DEFAULT_MODEL = "claude-opus-4-8"   # most-capable Claude for bounded drafting/classification
CRITIC_MODEL = "claude-sonnet-4-6"  # different model = a critic independence lever (C5)


@runtime_checkable
class LLMClient(Protocol):
    def complete(self, system: str, user: str, *, model: Optional[str] = None) -> str: ...


class AnthropicLLM:
    """Production client. Requires ANTHROPIC_API_KEY. Used only inside bounded nodes."""

    def __init__(self, default_model: str = DEFAULT_MODEL, max_tokens: int = 1024):
        import anthropic  # lazy: keeps offline/test paths import-clean

        self._client = anthropic.Anthropic()
        self._default_model = default_model
        self._max_tokens = max_tokens

    def complete(self, system: str, user: str, *, model: Optional[str] = None) -> str:
        msg = self._client.messages.create(
            model=model or self._default_model,
            max_tokens=self._max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", None) == "text")


class StubLLM:
    """Offline deterministic test double. `responder(system, user) -> str` mirrors the JSON contract."""

    def __init__(self, responder: Callable[[str, str], str]):
        self._responder = responder

    def complete(self, system: str, user: str, *, model: Optional[str] = None) -> str:
        return self._responder(system, user)


def parse_json(text: str):
    """Parse a model's JSON output, tolerating ```json fences."""
    t = text.strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", t, re.DOTALL)
    if m:
        t = m.group(1).strip()
    return json.loads(t)
