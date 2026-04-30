"""Scanner orchestration: dispatch payloads at a target and score the responses."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone

from llm_security_scanner.evaluators.base import Evaluator
from llm_security_scanner.exceptions import EvaluatorError, TargetError
from llm_security_scanner.models import (
    Evaluation,
    Finding,
    Payload,
    ScanResult,
    TargetResponse,
)
from llm_security_scanner.targets.base import Target


class Scanner:
    """Compose a :class:`Target` and an :class:`Evaluator` into a runnable scan.

    The scanner is provider-agnostic: it depends only on the two protocols.
    Per-payload errors (transport failures, evaluator crashes) are captured
    and surfaced as non-vulnerable :class:`Finding`s so reporters can render
    a uniform output and downstream tooling can decide how to react.

    Args:
        target: The LLM endpoint under test.
        evaluator: The strategy that judges each response.
        concurrency: Maximum number of payloads dispatched in flight at once.
            Defaults to ``1`` (sequential) to play nicely with rate-limited
            providers; raise it for local models or when you have headroom.
    """

    def __init__(
        self,
        *,
        target: Target,
        evaluator: Evaluator,
        concurrency: int = 1,
    ) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        self.target = target
        self.evaluator = evaluator
        self.concurrency = concurrency

    async def scan(self, payloads: Iterable[Payload]) -> ScanResult:
        """Run every payload in ``payloads`` against the target and aggregate findings.

        Findings are returned in input order, regardless of completion order
        when ``concurrency > 1``.
        """
        ordered: Sequence[Payload] = list(payloads)
        started_at = datetime.now(timezone.utc)

        semaphore = asyncio.Semaphore(self.concurrency)

        async def run_one(payload: Payload) -> Finding:
            async with semaphore:
                return await self._run_single(payload)

        findings = await asyncio.gather(*(run_one(p) for p in ordered))
        finished_at = datetime.now(timezone.utc)

        return ScanResult(
            target_name=self.target.name,
            started_at=started_at,
            finished_at=finished_at,
            findings=list(findings),
        )

    async def _run_single(self, payload: Payload) -> Finding:
        try:
            response = await self.target.send(payload.payload)
        except TargetError as exc:
            return Finding(
                payload=payload,
                response=TargetResponse(text="", latency_ms=0.0),
                evaluation=Evaluation(
                    success=False,
                    confidence=0.0,
                    reason=f"target error: {exc}",
                    evaluator="scanner",
                ),
            )

        try:
            evaluation = await self.evaluator.evaluate(payload, response)
        except EvaluatorError as exc:
            evaluation = Evaluation(
                success=False,
                confidence=0.0,
                reason=f"evaluator error: {exc}",
                evaluator="scanner",
            )

        return Finding(payload=payload, response=response, evaluation=evaluation)
