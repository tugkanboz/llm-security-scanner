"""Evaluator protocol that all evaluation strategies must satisfy."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from llm_security_scanner.models import Evaluation, Payload, TargetResponse


@runtime_checkable
class Evaluator(Protocol):
    """A pluggable strategy for judging whether a payload succeeded.

    Concrete implementations include rule-based matchers (regex/substring),
    LLM-as-judge scorers, and custom domain-specific evaluators.
    """

    name: str

    async def evaluate(self, payload: Payload, response: TargetResponse) -> Evaluation:
        """Score a single payload/response pair.

        Args:
            payload: The payload that was sent to the target.
            response: The target's response.

        Returns:
            An :class:`Evaluation` with a success flag, confidence, and short
            rationale.

        Raises:
            EvaluatorError: If the evaluator fails to produce a verdict.
        """
        ...
