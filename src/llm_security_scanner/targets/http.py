"""Generic HTTP target adapter.

A declarative wrapper around any HTTP endpoint that accepts a prompt and
returns a JSON response. Users describe the request shape (URL, method,
headers, body template) and how to extract the model's text from the
response (a path of keys / indices), and the adapter handles transport,
timeouts, and error mapping.

Example::

    target = HTTPTarget(
        name="local-ollama",
        url="http://localhost:11434/api/generate",
        body_template={"model": "llama3", "prompt": "{prompt}", "stream": False},
        response_path=["response"],
    )
    response = await target.send("hello")

The string ``"{prompt}"`` in any leaf of ``body_template`` is replaced with
the actual prompt text before the request is sent. Templating happens after
the dict is constructed but before JSON serialisation, so callers do not
need to worry about escaping.
"""

from __future__ import annotations

import time
from typing import Any, Literal

import httpx

from llm_security_scanner.exceptions import TargetError
from llm_security_scanner.models import TargetResponse

PROMPT_PLACEHOLDER = "{prompt}"

HTTPMethod = Literal["GET", "POST", "PUT", "PATCH"]


class HTTPTarget:
    """A configurable HTTP-based :class:`Target`.

    Args:
        name: Human-readable identifier surfaced in scan reports.
        url: Full request URL.
        body_template: A JSON-serialisable mapping. Any string leaf equal to
            or containing ``"{prompt}"`` has the placeholder replaced with
            the actual prompt before the request is dispatched. Pass an
            empty dict for ``GET`` requests with no body.
        response_path: Sequence of dict keys or list indices used to walk
            the response JSON down to the model's text output. For example,
            ``["choices", 0, "message", "content"]`` extracts an OpenAI-style
            assistant reply.
        method: HTTP verb to use. Defaults to ``"POST"``.
        headers: Optional request headers (auth tokens, content-type, etc.).
        timeout: Request timeout in seconds. Defaults to 30.
        client: Optional pre-configured ``httpx.AsyncClient``. When provided
            the caller owns its lifecycle; otherwise a fresh client is
            created per request.

    Raises:
        TargetError: On connection failure, non-2xx response, invalid JSON,
            or when ``response_path`` cannot be resolved against the body.
    """

    def __init__(
        self,
        *,
        name: str,
        url: str,
        body_template: dict[str, Any] | None = None,
        response_path: list[str | int] | None = None,
        method: HTTPMethod = "POST",
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.name = name
        self.url = url
        self.body_template = body_template or {}
        self.response_path = response_path or []
        self.method = method
        self.headers = headers or {}
        self.timeout = timeout
        self._client = client

    async def send(self, prompt: str) -> TargetResponse:
        """Send ``prompt`` to the configured endpoint and return the parsed response."""
        body = _render_template(self.body_template, prompt) if self.body_template else None

        start = time.perf_counter()
        try:
            if self._client is not None:
                http_response = await self._client.request(
                    self.method,
                    self.url,
                    json=body,
                    headers=self.headers,
                    timeout=self.timeout,
                )
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    http_response = await client.request(
                        self.method,
                        self.url,
                        json=body,
                        headers=self.headers,
                    )
        except httpx.HTTPError as exc:
            raise TargetError(f"HTTP request to {self.url} failed: {exc}") from exc

        latency_ms = (time.perf_counter() - start) * 1000.0

        if http_response.status_code >= 400:
            raise TargetError(
                f"HTTP {http_response.status_code} from {self.url}: {http_response.text[:200]}"
            )

        try:
            raw: dict[str, Any] = http_response.json()
        except ValueError as exc:
            raise TargetError(f"Response from {self.url} is not valid JSON: {exc}") from exc

        text = _extract_text(raw, self.response_path, self.url)
        return TargetResponse(text=text, latency_ms=latency_ms, raw=raw)


def _render_template(template: dict[str, Any], prompt: str) -> dict[str, Any]:
    """Return a deep copy of ``template`` with the prompt placeholder substituted."""

    def render(node: Any) -> Any:
        if isinstance(node, str):
            return node.replace(PROMPT_PLACEHOLDER, prompt)
        if isinstance(node, dict):
            return {k: render(v) for k, v in node.items()}
        if isinstance(node, list):
            return [render(item) for item in node]
        return node

    rendered = render(template)
    assert isinstance(rendered, dict)
    return rendered


def _extract_text(payload: Any, path: list[str | int], url: str) -> str:
    """Walk ``path`` through ``payload`` and return the leaf as a string."""
    cursor: Any = payload
    for step in path:
        try:
            cursor = cursor[step]
        except (KeyError, IndexError, TypeError) as exc:
            raise TargetError(
                f"Could not extract response text from {url}: "
                f"path {path!r} failed at {step!r} ({type(exc).__name__})."
            ) from exc

    if not isinstance(cursor, str):
        raise TargetError(
            f"Response value at path {path!r} from {url} is not a string "
            f"(got {type(cursor).__name__})."
        )
    return cursor
