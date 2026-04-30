"""Smoke tests verifying that minimal in-memory implementations satisfy the base protocols."""

from __future__ import annotations

from llm_security_scanner.evaluators import Evaluator
from llm_security_scanner.models import (
    Category,
    Evaluation,
    Payload,
    ScanResult,
    Severity,
    TargetResponse,
)
from llm_security_scanner.reporters import Reporter
from llm_security_scanner.targets import Target


class _DummyTarget:
    name = "dummy"

    async def send(self, prompt: str) -> TargetResponse:
        return TargetResponse(text=f"echo: {prompt}", latency_ms=1.0)


class _DummyEvaluator:
    name = "dummy"

    async def evaluate(self, payload: Payload, response: TargetResponse) -> Evaluation:
        return Evaluation(
            success="echo:" in response.text,
            confidence=1.0,
            reason="contains echo prefix",
            evaluator=self.name,
        )


class _DummyReporter:
    name = "dummy"

    def render(self, result: ScanResult) -> str:
        return f"{result.target_name}: {result.vulnerable_count}/{result.total}"


def test_dummy_target_satisfies_protocol() -> None:
    assert isinstance(_DummyTarget(), Target)


def test_dummy_evaluator_satisfies_protocol() -> None:
    assert isinstance(_DummyEvaluator(), Evaluator)


def test_dummy_reporter_satisfies_protocol() -> None:
    assert isinstance(_DummyReporter(), Reporter)


async def test_dummy_target_and_evaluator_round_trip() -> None:
    target = _DummyTarget()
    evaluator = _DummyEvaluator()
    payload = Payload(
        id="t-001",
        name="echo probe",
        category=Category.DIRECT_INJECTION,
        owasp_llm_top10="LLM01",
        severity=Severity.LOW,
        language="en",
        payload="ping",
    )
    response = await target.send(payload.payload)
    verdict = await evaluator.evaluate(payload, response)
    assert response.text == "echo: ping"
    assert verdict.success is True
    assert verdict.evaluator == "dummy"
