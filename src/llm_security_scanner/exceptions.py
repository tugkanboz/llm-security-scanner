"""Exception hierarchy for llm-security-scanner.

All errors raised by the library inherit from :class:`LLMScannerError` so
callers can catch a single base class when integrating the scanner into a
larger system.
"""

from __future__ import annotations


class LLMScannerError(Exception):
    """Base class for all errors raised by llm-security-scanner."""


class PayloadError(LLMScannerError):
    """Raised when a payload file fails to load or validate."""


class TargetError(LLMScannerError):
    """Raised when a target (LLM provider adapter) cannot be reached or returns an invalid response."""


class EvaluatorError(LLMScannerError):
    """Raised when an evaluator fails to score a response."""


class ReporterError(LLMScannerError):
    """Raised when a reporter fails to render a scan result."""


class ConfigurationError(LLMScannerError):
    """Raised when scanner configuration is invalid or incomplete."""
