"""Tests for the generic HTTP target adapter."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from llm_security_scanner.exceptions import TargetError
from llm_security_scanner.targets import HTTPTarget, Target
from llm_security_scanner.targets.http import _render_template


def make_client(handler: httpx.MockTransport | Any) -> httpx.AsyncClient:
    if not isinstance(handler, httpx.MockTransport):
        handler = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=handler)


class TestRenderTemplate:
    def test_replaces_placeholder_in_strings(self) -> None:
        out = _render_template({"prompt": "{prompt}"}, "hello")
        assert out == {"prompt": "hello"}

    def test_replaces_recursively_in_lists_and_dicts(self) -> None:
        template = {
            "messages": [
                {"role": "user", "content": "{prompt}"},
                {"role": "assistant", "content": "static"},
            ],
            "model": "x",
            "temperature": 0.0,
        }
        out = _render_template(template, "ping")
        assert out["messages"][0]["content"] == "ping"
        assert out["messages"][1]["content"] == "static"
        assert out["temperature"] == 0.0

    def test_does_not_mutate_input(self) -> None:
        template = {"prompt": "{prompt}"}
        _render_template(template, "x")
        assert template == {"prompt": "{prompt}"}

    def test_partial_replacement_in_string(self) -> None:
        out = _render_template({"q": "Q: {prompt}\nA:"}, "why?")
        assert out["q"] == "Q: why?\nA:"


class TestHTTPTargetSend:
    def test_satisfies_target_protocol(self) -> None:
        t = HTTPTarget(name="x", url="http://x/", response_path=["text"])
        assert isinstance(t, Target)

    async def test_happy_path_extracts_text(self) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["method"] = request.method
            captured["body"] = json.loads(request.content)
            captured["headers"] = dict(request.headers)
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": "hi there"}}]},
            )

        async with make_client(handler) as client:
            target = HTTPTarget(
                name="openai-like",
                url="http://api.test/v1/chat",
                body_template={
                    "model": "test",
                    "messages": [{"role": "user", "content": "{prompt}"}],
                },
                response_path=["choices", 0, "message", "content"],
                headers={"Authorization": "Bearer test"},
                client=client,
            )
            response = await target.send("ping")

        assert response.text == "hi there"
        assert response.latency_ms >= 0
        assert response.raw["choices"][0]["message"]["content"] == "hi there"
        assert captured["method"] == "POST"
        assert captured["body"]["messages"][0]["content"] == "ping"
        assert captured["headers"]["authorization"] == "Bearer test"

    async def test_non_2xx_raises_target_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="boom")

        async with make_client(handler) as client:
            target = HTTPTarget(
                name="t",
                url="http://api.test/x",
                body_template={"p": "{prompt}"},
                response_path=["text"],
                client=client,
            )
            with pytest.raises(TargetError, match="HTTP 500"):
                await target.send("ping")

    async def test_invalid_json_raises(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"not-json", headers={"content-type": "text/plain"})

        async with make_client(handler) as client:
            target = HTTPTarget(
                name="t",
                url="http://api.test/x",
                body_template={"p": "{prompt}"},
                response_path=["text"],
                client=client,
            )
            with pytest.raises(TargetError, match="not valid JSON"):
                await target.send("ping")

    async def test_response_path_miss_raises(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"unexpected": "shape"})

        async with make_client(handler) as client:
            target = HTTPTarget(
                name="t",
                url="http://api.test/x",
                body_template={"p": "{prompt}"},
                response_path=["choices", 0, "message", "content"],
                client=client,
            )
            with pytest.raises(TargetError, match="Could not extract response text"):
                await target.send("ping")

    async def test_response_value_not_string_raises(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"text": 42})

        async with make_client(handler) as client:
            target = HTTPTarget(
                name="t",
                url="http://api.test/x",
                body_template={"p": "{prompt}"},
                response_path=["text"],
                client=client,
            )
            with pytest.raises(TargetError, match="not a string"):
                await target.send("ping")

    async def test_connection_error_wrapped(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("nope")

        async with make_client(handler) as client:
            target = HTTPTarget(
                name="t",
                url="http://api.test/x",
                body_template={"p": "{prompt}"},
                response_path=["text"],
                client=client,
            )
            with pytest.raises(TargetError, match="HTTP request"):
                await target.send("ping")
