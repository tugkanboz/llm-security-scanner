"""Core Pydantic models shared across the scanner.

These models define the canonical data shapes for payloads, target responses,
evaluations, and scan results. They are deliberately decoupled from any
specific provider so that the scanner core can stay provider-agnostic.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    """Severity rating assigned to a payload or finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(str, Enum):
    """Attack category aligned with OWASP LLM Top 10 themes."""

    JAILBREAK = "jailbreak"
    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    SYSTEM_PROMPT_LEAK = "sys_prompt_leak"
    DATA_EXFIL = "data_exfil"
    TOOL_ABUSE = "tool_abuse"
    MULTI_TURN = "multi_turn"


class IndicatorType(str, Enum):
    """How a success indicator should be matched against a response."""

    REGEX = "regex"
    SUBSTRING = "substring"
    SEMANTIC = "semantic"


class SuccessIndicator(BaseModel):
    """A rule-based hint describing what a successful exploit looks like."""

    model_config = ConfigDict(frozen=True)

    pattern: str = Field(..., description="Regex, substring, or semantic prompt to match.")
    type: IndicatorType = Field(default=IndicatorType.SUBSTRING)


class Payload(BaseModel):
    """An attack payload loaded from the on-disk payload library."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Stable, kebab-case identifier (e.g. 'jb-tr-001').")
    name: str = Field(..., description="Short human-readable name.")
    category: Category
    owasp_llm_top10: str = Field(..., description="OWASP LLM Top 10 mapping (e.g. 'LLM01').")
    severity: Severity
    language: str = Field(..., min_length=2, max_length=5, description="ISO 639-1 code.")
    payload: str = Field(..., min_length=1, description="The prompt text sent to the target.")
    success_indicators: list[SuccessIndicator] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class TargetResponse(BaseModel):
    """Raw response captured from a target after sending a payload."""

    text: str
    latency_ms: float = Field(..., ge=0)
    raw: dict[str, Any] = Field(default_factory=dict, description="Provider-specific raw payload.")


class Evaluation(BaseModel):
    """Verdict produced by an evaluator for a single payload/response pair."""

    success: bool = Field(..., description="True if the payload appears to have succeeded.")
    confidence: float = Field(..., ge=0.0, le=1.0)
    reason: str = Field(default="", description="Short rationale for the verdict.")
    evaluator: str = Field(..., description="Name of the evaluator that produced this verdict.")


class Finding(BaseModel):
    """A single payload run with its response and evaluation."""

    payload: Payload
    response: TargetResponse
    evaluation: Evaluation
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_vulnerable(self) -> bool:
        """Convenience flag: True when the evaluator marked the run as a successful exploit."""
        return self.evaluation.success


class ScanResult(BaseModel):
    """Aggregate result of a scan across many payloads."""

    target_name: str
    started_at: datetime
    finished_at: datetime
    findings: list[Finding] = Field(default_factory=list)

    @property
    def total(self) -> int:
        """Number of payloads attempted in this scan."""
        return len(self.findings)

    @property
    def vulnerable_count(self) -> int:
        """Number of findings marked as successful exploits."""
        return sum(1 for f in self.findings if f.is_vulnerable)
