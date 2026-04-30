"""Target protocol that all provider adapters must satisfy."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from llm_security_scanner.models import TargetResponse


@runtime_checkable
class Target(Protocol):
    """A pluggable LLM target.

    Implementations wrap a specific provider (Anthropic, OpenAI, Ollama, a
    generic HTTP endpoint, etc.) and translate a single prompt into a
    :class:`TargetResponse`. The scanner core depends only on this protocol.
    """

    name: str

    async def send(self, prompt: str) -> TargetResponse:
        """Send ``prompt`` to the underlying provider and return its response.

        Args:
            prompt: The fully-rendered payload text.

        Returns:
            A :class:`TargetResponse` capturing the model output, latency, and
            any provider-specific raw payload.

        Raises:
            TargetError: If the provider is unreachable or returns an
                unparseable response.
        """
        ...
