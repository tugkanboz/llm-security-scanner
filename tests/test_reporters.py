"""Tests for the JSON and Markdown reporters."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from llm_security_scanner import (
    Category,
    Evaluation,
    Finding,
    Payload,
    ScanResult,
    Severity,
    SuccessIndicator,
    TargetResponse,
)
from llm_security_scanner.models import IndicatorType
from llm_security_scanner.reporters import JSONReporter, MarkdownReporter, Reporter


def make_finding(
    payload_id: str,
    severity: Severity,
    category: Category,
    *,
    success: bool,
    response_text: str = "ok",
    reason: str = "",
) -> Finding:
    payload = Payload(
        id=payload_id,
        name=payload_id,
        category=category,
        owasp_llm_top10="LLM01",
        severity=severity,
        language="en",
        payload="prompt",
        success_indicators=[SuccessIndicator(pattern="x", type=IndicatorType.SUBSTRING)],
    )
    response = TargetResponse(text=response_text, latency_ms=1.0)
    evaluation = Evaluation(
        success=success,
        confidence=1.0 if success else 0.5,
        reason=reason or ("matched" if success else "no match"),
        evaluator="rule_based",
    )
    return Finding(payload=payload, response=response, evaluation=evaluation)


def make_result(*findings: Finding, target_name: str = "fake") -> ScanResult:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    return ScanResult(
        target_name=target_name,
        started_at=now,
        finished_at=now,
        findings=list(findings),
    )


class TestJSONReporter:
    def test_satisfies_protocol(self) -> None:
        assert isinstance(JSONReporter(), Reporter)

    def test_round_trip_through_json(self) -> None:
        result = make_result(
            make_finding("p1", Severity.HIGH, Category.DIRECT_INJECTION, success=True)
        )
        rendered = JSONReporter().render(result)
        parsed = json.loads(rendered)
        assert parsed["target_name"] == "fake"
        assert len(parsed["findings"]) == 1
        assert parsed["findings"][0]["payload"]["id"] == "p1"
        assert parsed["findings"][0]["evaluation"]["success"] is True

    def test_indent_none_produces_compact_output(self) -> None:
        result = make_result()
        rendered = JSONReporter(indent=None).render(result)
        assert "\n" not in rendered
        json.loads(rendered)

    def test_empty_scan_renders(self) -> None:
        rendered = JSONReporter().render(make_result())
        parsed = json.loads(rendered)
        assert parsed["findings"] == []


class TestMarkdownReporter:
    def test_satisfies_protocol(self) -> None:
        assert isinstance(MarkdownReporter(), Reporter)

    def test_rejects_zero_max_chars(self) -> None:
        with pytest.raises(ValueError, match=">= 1"):
            MarkdownReporter(max_response_chars=0)

    def test_header_includes_target_and_counts(self) -> None:
        result = make_result(
            make_finding("p1", Severity.HIGH, Category.JAILBREAK, success=True),
            make_finding("p2", Severity.LOW, Category.JAILBREAK, success=False),
            target_name="claude-test",
        )
        rendered = MarkdownReporter().render(result)
        assert "# Scan report — `claude-test`" in rendered
        assert "**Total payloads:** 2" in rendered
        assert "**Vulnerable:** 1" in rendered

    def test_severity_table_lists_known_levels(self) -> None:
        result = make_result(
            make_finding("p1", Severity.CRITICAL, Category.JAILBREAK, success=True),
            make_finding("p2", Severity.HIGH, Category.JAILBREAK, success=True),
            make_finding("p3", Severity.HIGH, Category.JAILBREAK, success=False),
        )
        rendered = MarkdownReporter().render(result)
        assert "| critical | 1 |" in rendered
        assert "| high | 1 |" in rendered
        assert "| medium | 0 |" in rendered
        assert "| low | 0 |" in rendered

    def test_findings_table_orders_vulnerable_first(self) -> None:
        result = make_result(
            make_finding("p_low_ok", Severity.LOW, Category.JAILBREAK, success=False),
            make_finding("p_high_vuln", Severity.HIGH, Category.JAILBREAK, success=True),
            make_finding("p_med_ok", Severity.MEDIUM, Category.JAILBREAK, success=False),
        )
        rendered = MarkdownReporter().render(result)
        rows = [
            line
            for line in rendered.splitlines()
            if line.startswith("| VULN") or line.startswith("| ok")
        ]
        assert rows[0].startswith("| VULN")
        assert "p_high_vuln" in rows[0]
        assert "p_low_ok" in rows[-1] or "p_med_ok" in rows[-1]

    def test_response_excerpt_truncates_and_collapses_newlines(self) -> None:
        long = "line1\n" + ("a" * 200)
        result = make_result(
            make_finding("p1", Severity.HIGH, Category.JAILBREAK, success=True, response_text=long)
        )
        rendered = MarkdownReporter(max_response_chars=50).render(result)
        # Collapsed newline shows up as space; long text ends with ellipsis.
        assert "line1 a" in rendered
        assert "…" in rendered

    def test_md_escape_pipe_in_reason_or_response(self) -> None:
        result = make_result(
            make_finding(
                "p1",
                Severity.HIGH,
                Category.JAILBREAK,
                success=True,
                response_text="contains | pipe",
                reason="rule | fired",
            )
        )
        rendered = MarkdownReporter().render(result)
        assert "contains \\| pipe" in rendered
        assert "rule \\| fired" in rendered

    def test_empty_scan_renders_summary_placeholder(self) -> None:
        rendered = MarkdownReporter().render(make_result())
        assert "_No payloads were scanned._" in rendered
        assert "## Findings" not in rendered
