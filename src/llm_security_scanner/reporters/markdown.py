"""Markdown reporter rendering a human-friendly scan summary."""

from __future__ import annotations

from collections import Counter

from llm_security_scanner.models import Finding, ScanResult, Severity


class MarkdownReporter:
    """Render a :class:`ScanResult` as a Markdown report.

    The output is suitable for pasting into a GitHub issue, a PR comment,
    or a CI artefact. It surfaces a header summary, a severity breakdown,
    and a per-finding table that highlights the vulnerable rows first.

    Args:
        max_response_chars: Per-row response excerpt length used in the
            Findings table. Long responses are truncated with an ellipsis.
        name: Identifier surfaced when the reporter is registered.
    """

    def __init__(self, *, max_response_chars: int = 160, name: str = "markdown") -> None:
        if max_response_chars < 1:
            raise ValueError("max_response_chars must be >= 1")
        self.max_response_chars = max_response_chars
        self.name = name

    def render(self, result: ScanResult) -> str:
        lines: list[str] = []
        lines.extend(self._header(result))
        lines.append("")
        lines.extend(self._summary(result))
        lines.append("")
        lines.extend(self._findings_table(result))
        return "\n".join(lines).rstrip() + "\n"

    @staticmethod
    def _header(result: ScanResult) -> list[str]:
        return [
            f"# Scan report — `{result.target_name}`",
            "",
            f"- **Started:** {result.started_at.isoformat()}",
            f"- **Finished:** {result.finished_at.isoformat()}",
            f"- **Duration:** {(result.finished_at - result.started_at).total_seconds():.2f}s",
            f"- **Total payloads:** {result.total}",
            f"- **Vulnerable:** {result.vulnerable_count}",
        ]

    @staticmethod
    def _summary(result: ScanResult) -> list[str]:
        if not result.findings:
            return ["## Summary", "", "_No payloads were scanned._"]

        by_severity: Counter[Severity] = Counter()
        for finding in result.findings:
            if finding.is_vulnerable:
                by_severity[finding.payload.severity] += 1

        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        rows = [f"| {sev.value} | {by_severity.get(sev, 0)} |" for sev in order]
        return [
            "## Vulnerable findings by severity",
            "",
            "| Severity | Count |",
            "| --- | --- |",
            *rows,
        ]

    def _findings_table(self, result: ScanResult) -> list[str]:
        if not result.findings:
            return []

        ordered = sorted(
            result.findings,
            key=lambda f: (
                not f.is_vulnerable,
                _SEVERITY_RANK[f.payload.severity],
                f.payload.id,
            ),
        )
        rows = [self._row(finding) for finding in ordered]
        return [
            "## Findings",
            "",
            "| Status | Severity | ID | Category | Confidence | Reason | Response |",
            "| --- | --- | --- | --- | --- | --- | --- |",
            *rows,
        ]

    def _row(self, finding: Finding) -> str:
        status = "VULN" if finding.is_vulnerable else "ok"
        excerpt = self._excerpt(finding.response.text)
        reason = _md_escape(finding.evaluation.reason)
        return (
            f"| {status} "
            f"| {finding.payload.severity.value} "
            f"| `{finding.payload.id}` "
            f"| {finding.payload.category.value} "
            f"| {finding.evaluation.confidence:.2f} "
            f"| {reason} "
            f"| {excerpt} |"
        )

    def _excerpt(self, text: str) -> str:
        cleaned = text.replace("\n", " ").strip()
        if len(cleaned) > self.max_response_chars:
            cleaned = cleaned[: self.max_response_chars - 1].rstrip() + "…"
        return _md_escape(cleaned) if cleaned else "_(empty)_"


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("`", "\\`")
