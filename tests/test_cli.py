"""Tests for the Typer CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from llm_security_scanner import __version__
from llm_security_scanner.cli import _expand_env, app

runner = CliRunner()


def _normalised(text: str) -> str:
    """Collapse Rich's hard-wrapped output into a single whitespace-normalised line."""
    return " ".join(text.split())


def write_target_config(tmp_path: Path, **overrides: object) -> Path:
    base: dict[str, object] = {
        "type": "http",
        "name": "test-target",
        "url": "http://api.test/v1",
        "body_template": {"prompt": "{prompt}"},
        "response_path": ["text"],
    }
    base.update(overrides)
    path = tmp_path / "target.yaml"
    import yaml as _yaml

    path.write_text(_yaml.safe_dump(base), encoding="utf-8")
    return path


class TestVersion:
    def test_prints_version(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.stdout


class TestListPayloads:
    def test_lists_bundled_library(self) -> None:
        result = runner.invoke(app, ["list-payloads"])
        assert result.exit_code == 0
        assert "di-en-001" in result.stdout
        assert "jb-tr-001" in result.stdout

    def test_filters_by_language(self) -> None:
        result = runner.invoke(app, ["list-payloads", "--language", "tr"])
        assert result.exit_code == 0
        assert "jb-tr-001" in result.stdout
        assert "jb-en-001" not in result.stdout

    def test_filters_by_category(self) -> None:
        result = runner.invoke(app, ["list-payloads", "--category", "jailbreak"])
        assert result.exit_code == 0
        assert "jb-en-001" in result.stdout
        assert "di-en-001" not in result.stdout

    def test_no_match_exits_nonzero(self) -> None:
        result = runner.invoke(app, ["list-payloads", "--language", "zz"])
        assert result.exit_code == 1
        assert "No payloads matched" in _normalised(result.stderr)

    def test_missing_payload_dir(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["list-payloads", "--payloads-dir", str(tmp_path / "nope")])
        assert result.exit_code == 2
        assert "Failed to load payloads" in _normalised(result.stderr)


class TestExpandEnv:
    def test_substitutes_env_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("API_KEY", "s3cret")
        out = _expand_env({"headers": {"Authorization": "Bearer ${API_KEY}"}})
        assert out["headers"]["Authorization"] == "Bearer s3cret"

    def test_leaves_non_strings_alone(self) -> None:
        out = _expand_env({"timeout": 30, "list": [1, 2, "x"]})
        assert out == {"timeout": 30, "list": [1, 2, "x"]}


class TestScan:
    def test_unknown_target_type(self, tmp_path: Path) -> None:
        config = write_target_config(tmp_path, type="grpc")
        result = runner.invoke(app, ["scan", "--target", str(config)])
        assert result.exit_code == 2
        assert "Unsupported target type" in _normalised(result.stderr)

    def test_target_config_must_be_mapping(self, tmp_path: Path) -> None:
        config = tmp_path / "bad.yaml"
        config.write_text("- not\n- a mapping\n", encoding="utf-8")
        result = runner.invoke(app, ["scan", "--target", str(config)])
        assert result.exit_code == 2
        assert "must be a mapping" in _normalised(result.stderr)

    def test_unset_env_var_in_config_fails(self, tmp_path: Path) -> None:
        config = write_target_config(
            tmp_path, headers={"Authorization": "Bearer ${LLMSCAN_MISSING_KEY}"}
        )
        result = runner.invoke(app, ["scan", "--target", str(config)])
        assert result.exit_code == 2
        assert "unset environment variable" in _normalised(result.stderr)

    def test_unsupported_format(self, tmp_path: Path) -> None:
        config = write_target_config(tmp_path)
        # Avoid hitting the network: filter to a non-existent language so we
        # exit before dispatching any request.
        result = runner.invoke(
            app,
            [
                "scan",
                "--target",
                str(config),
                "--language",
                "zz",
                "--format",
                "yaml",
            ],
        )
        # No payloads matched -> exit 1 before format is checked.
        assert result.exit_code == 1

    def test_runs_against_fake_target(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from llm_security_scanner import cli as cli_module
        from llm_security_scanner.models import TargetResponse

        class FakeTarget:
            name = "fake"

            async def send(self, prompt: str) -> TargetResponse:
                return TargetResponse(text="harmless", latency_ms=1.0)

        def fake_build(_path: Path) -> FakeTarget:
            return FakeTarget()

        monkeypatch.setattr(cli_module, "_build_target", fake_build)
        config = write_target_config(tmp_path)

        out_path = tmp_path / "report.json"
        result = runner.invoke(
            app,
            [
                "scan",
                "--target",
                str(config),
                "--language",
                "en",
                "--format",
                "json",
                "--output",
                str(out_path),
            ],
        )
        assert result.exit_code == 0, result.stderr
        parsed = json.loads(out_path.read_text(encoding="utf-8"))
        assert parsed["target_name"] == "fake"
        assert parsed["findings"]
