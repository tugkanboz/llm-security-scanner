"""Reporter protocol that all output renderers must satisfy."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from llm_security_scanner.models import ScanResult


@runtime_checkable
class Reporter(Protocol):
    """A pluggable renderer that turns a :class:`ScanResult` into output bytes.

    Implementations include Markdown, HTML, JSON, and SARIF reporters.
    """

    name: str

    def render(self, result: ScanResult) -> str:
        """Render ``result`` and return the rendered text.

        Args:
            result: The scan result to render.

        Returns:
            The rendered output as a string. Binary formats should return a
            base64-encoded string or be implemented as a separate method.

        Raises:
            ReporterError: If rendering fails.
        """
        ...
