"""Tests for the Scanner orchestration layer."""

from __future__ import annotations

import asyncio

import pytest

from llm_security_scanner import (
    Category,
    Payload,
    Scanner,
    Severity,
    SuccessIndicator,
    TargetResponse,
)
from llm_security_scanner.evaluators import RuleBasedEvaluator
from llm_security_scanner.exceptions import EvaluatorError, TargetError
from llm_security_scanner.models import Evaluation, IndicatorType


def make_payload(payload_id: str, indicators: list[SuccessIndicator] | None = None) -> Payload:
    return Payload(
        id=payload_id,
        name=payload_id,
        category=Category.JAILBREAK,
        owasp_llm_top10="LLM01",
        severity=Severity.HIGH,
        language="en",
        payload=f"prompt-{payload_id}",
        success_indicators=indicators or [],
    )


class EchoTarget:
    name = "echo"

    async def send(self, prompt: str) -> TargetResponse:
        return TargetResponse(text=f"echo:{prompt}", latency_ms=1.0)


class FlakyTarget:
    name = "flaky"

    def __init__(self, failing_ids: set[str]) -> None:
        self.failing_ids = failing_ids

    async def send(self, prompt: str) -> TargetResponse:
        for pid in self.failing_ids:
            if pid in prompt:
                raise TargetError(f"simulated transport failure for {pid}")
        return TargetResponse(text=f"echo:{prompt}", latency_ms=1.0)


class CrashingEvaluator:
    name = "crash"

    async def evaluate(self, payload: Payload, response: TargetResponse) -> Evaluation:
        raise EvaluatorError("simulated evaluator crash")


class TestScanner:
    def test_rejects_zero_concurrency(self) -> None:
        with pytest.raises(ValueError, match="concurrency must be >= 1"):
            Scanner(target=EchoTarget(), evaluator=RuleBasedEvaluator(), concurrency=0)

    async def test_runs_each_payload_once_and_preserves_order(self) -> None:
        payloads = [
            make_payload(
                "p1",
                [SuccessIndicator(pattern="prompt-p1", type=IndicatorType.SUBSTRING)],
            ),
            make_payload(
                "p2",
                [SuccessIndicator(pattern="will-not-match", type=IndicatorType.SUBSTRING)],
            ),
            make_payload(
                "p3",
                [SuccessIndicator(pattern="prompt-p3", type=IndicatorType.SUBSTRING)],
            ),
        ]
        scanner = Scanner(target=EchoTarget(), evaluator=RuleBasedEvaluator())
        result = await scanner.scan(payloads)

        assert result.target_name == "echo"
        assert result.total == 3
        assert result.vulnerable_count == 2
        assert [f.payload.id for f in result.findings] == ["p1", "p2", "p3"]
        assert result.started_at <= result.finished_at

    async def test_target_error_becomes_failed_finding(self) -> None:
        payloads = [make_payload("ok"), make_payload("boom")]
        scanner = Scanner(
            target=FlakyTarget(failing_ids={"boom"}),
            evaluator=RuleBasedEvaluator(),
        )
        result = await scanner.scan(payloads)

        assert result.total == 2
        assert result.vulnerable_count == 0
        boom = next(f for f in result.findings if f.payload.id == "boom")
        assert boom.evaluation.success is False
        assert boom.evaluation.evaluator == "scanner"
        assert "target error" in boom.evaluation.reason
        assert boom.response.text == ""

    async def test_evaluator_error_becomes_failed_finding(self) -> None:
        scanner = Scanner(target=EchoTarget(), evaluator=CrashingEvaluator())
        result = await scanner.scan([make_payload("p1")])
        finding = result.findings[0]
        assert finding.evaluation.success is False
        assert "evaluator error" in finding.evaluation.reason
        assert finding.response.text == "echo:prompt-p1"  # target call still succeeded

    async def test_concurrency_limit_is_respected(self) -> None:
        in_flight = 0
        peak = 0
        lock = asyncio.Lock()

        class CountingTarget:
            name = "counting"

            async def send(self, prompt: str) -> TargetResponse:
                nonlocal in_flight, peak
                async with lock:
                    in_flight += 1
                    peak = max(peak, in_flight)
                try:
                    await asyncio.sleep(0.01)
                    return TargetResponse(text="ok", latency_ms=10.0)
                finally:
                    async with lock:
                        in_flight -= 1

        payloads = [make_payload(f"p{i}") for i in range(8)]
        scanner = Scanner(
            target=CountingTarget(),
            evaluator=RuleBasedEvaluator(),
            concurrency=3,
        )
        result = await scanner.scan(payloads)
        assert result.total == 8
        assert peak <= 3
        assert peak >= 2  # confirm we actually parallelised
