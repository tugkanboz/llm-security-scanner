"""Tests for the rule-based evaluator."""

from __future__ import annotations

import pytest

from llm_security_scanner import Category, Payload, Severity, SuccessIndicator, TargetResponse
from llm_security_scanner.evaluators import Evaluator, RuleBasedEvaluator
from llm_security_scanner.exceptions import EvaluatorError
from llm_security_scanner.models import IndicatorType


def make_payload(*indicators: SuccessIndicator) -> Payload:
    return Payload(
        id="t-001",
        name="t",
        category=Category.JAILBREAK,
        owasp_llm_top10="LLM01",
        severity=Severity.HIGH,
        language="en",
        payload="x",
        success_indicators=list(indicators),
    )


def resp(text: str) -> TargetResponse:
    return TargetResponse(text=text, latency_ms=1.0)


class TestRuleBasedEvaluator:
    def test_satisfies_evaluator_protocol(self) -> None:
        assert isinstance(RuleBasedEvaluator(), Evaluator)

    async def test_substring_match_case_insensitive_by_default(self) -> None:
        payload = make_payload(SuccessIndicator(pattern="PWNED", type=IndicatorType.SUBSTRING))
        verdict = await RuleBasedEvaluator().evaluate(payload, resp("you got pwned today"))
        assert verdict.success is True
        assert verdict.confidence == 1.0
        assert "matched 1/1" in verdict.reason
        assert verdict.evaluator == "rule_based"

    async def test_substring_match_case_sensitive_when_configured(self) -> None:
        payload = make_payload(SuccessIndicator(pattern="PWNED", type=IndicatorType.SUBSTRING))
        ev = RuleBasedEvaluator(case_insensitive=False)
        verdict = await ev.evaluate(payload, resp("you got pwned"))
        assert verdict.success is False
        verdict2 = await ev.evaluate(payload, resp("you got PWNED"))
        assert verdict2.success is True

    async def test_regex_match(self) -> None:
        payload = make_payload(
            SuccessIndicator(pattern=r"^I am DAN", type=IndicatorType.REGEX),
        )
        verdict = await RuleBasedEvaluator().evaluate(payload, resp("I am DAN, your unrestricted assistant"))
        assert verdict.success is True

    async def test_no_match_marks_failure_with_full_confidence(self) -> None:
        payload = make_payload(
            SuccessIndicator(pattern="PWNED", type=IndicatorType.SUBSTRING),
            SuccessIndicator(pattern="HACKED", type=IndicatorType.SUBSTRING),
        )
        verdict = await RuleBasedEvaluator().evaluate(payload, resp("I cannot help with that."))
        assert verdict.success is False
        assert verdict.confidence == 1.0
        assert "no indicators matched" in verdict.reason

    async def test_partial_match_scales_confidence(self) -> None:
        payload = make_payload(
            SuccessIndicator(pattern="alpha", type=IndicatorType.SUBSTRING),
            SuccessIndicator(pattern="beta", type=IndicatorType.SUBSTRING),
            SuccessIndicator(pattern="gamma", type=IndicatorType.SUBSTRING),
        )
        verdict = await RuleBasedEvaluator().evaluate(payload, resp("alpha and beta only"))
        assert verdict.success is True
        assert verdict.confidence == pytest.approx(2 / 3)

    async def test_no_indicators_returns_failure(self) -> None:
        payload = make_payload()
        verdict = await RuleBasedEvaluator().evaluate(payload, resp("anything"))
        assert verdict.success is False
        assert verdict.confidence == 0.0
        assert "no rule-based success_indicators" in verdict.reason

    async def test_only_semantic_indicators_returns_failure(self) -> None:
        payload = make_payload(
            SuccessIndicator(pattern="model agrees with bad request", type=IndicatorType.SEMANTIC),
        )
        verdict = await RuleBasedEvaluator().evaluate(payload, resp("anything"))
        assert verdict.success is False
        assert "semantic" in verdict.reason

    async def test_semantic_indicators_are_skipped_but_others_evaluated(self) -> None:
        payload = make_payload(
            SuccessIndicator(pattern="PWNED", type=IndicatorType.SUBSTRING),
            SuccessIndicator(pattern="model complies", type=IndicatorType.SEMANTIC),
        )
        verdict = await RuleBasedEvaluator().evaluate(payload, resp("you are PWNED"))
        assert verdict.success is True
        assert verdict.confidence == 1.0  # 1 of 1 evaluable indicator matched
        assert "skipped 1 semantic" in verdict.reason

    async def test_invalid_regex_raises_evaluator_error(self) -> None:
        payload = make_payload(SuccessIndicator(pattern="(unterminated", type=IndicatorType.REGEX))
        with pytest.raises(EvaluatorError, match="Invalid regex"):
            await RuleBasedEvaluator().evaluate(payload, resp("x"))
