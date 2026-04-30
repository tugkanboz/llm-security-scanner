"""JSON reporter producing a stable, machine-readable scan summary."""

from __future__ import annotations

from llm_security_scanner.exceptions import ReporterError
from llm_security_scanner.models import ScanResult


class JSONReporter:
    """Render a :class:`ScanResult` as a JSON document.

    The output is delegated to Pydantic so the schema stays in lockstep with
    the model definitions. Use this reporter when you want to pipe results
    into downstream tooling, store them as artefacts, or diff scans across
    runs.

    Args:
        indent: Number of spaces to indent nested structures. Pass ``None``
            for the most compact representation.
        name: Identifier surfaced when the reporter is registered in a
            multi-reporter setup.
    """

    def __init__(self, *, indent: int | None = 2, name: str = "json") -> None:
        self.indent = indent
        self.name = name

    def render(self, result: ScanResult) -> str:
        """Return the JSON-encoded scan result."""
        try:
            return result.model_dump_json(indent=self.indent)
        except (TypeError, ValueError) as exc:
            raise ReporterError(f"Failed to render scan result as JSON: {exc}") from exc
