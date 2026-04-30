"""Target adapters that send payloads to specific LLM providers."""

from llm_security_scanner.targets.base import Target
from llm_security_scanner.targets.http import HTTPTarget

__all__ = ["HTTPTarget", "Target"]
