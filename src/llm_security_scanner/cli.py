"""Command-line interface for llm-security-scanner.

Two thin commands sit on top of the library:

- ``list-payloads``: surface the bundled (or a custom) payload library,
  optionally filtered by language and category.
- ``scan``: run a target described by a small YAML config against a set of
  payloads and render the result with one of the bundled reporters.

The CLI is deliberately a thin wrapper — every interesting decision lives
in the library so library users get the same behaviour without going
through the CLI.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
from pathlib import Path
from typing import Any

import typer
import yaml
from rich.console import Console
from rich.table import Table

from llm_security_scanner import (
    Category,
    Payload,
    Scanner,
    __version__,
    load_payloads,
)
from llm_security_scanner.evaluators import RuleBasedEvaluator
from llm_security_scanner.exceptions import LLMScannerError
from llm_security_scanner.reporters import JSONReporter, MarkdownReporter
from llm_security_scanner.targets import HTTPTarget
from llm_security_scanner.targets.base import Target

app = typer.Typer(
    name="llm-sec-scan",
    help="Red-team toolkit for testing LLM applications.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

_ENV_VAR_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"llm-sec-scan {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Print the installed version and exit.",
    ),
) -> None:
    """Top-level entrypoint hook for global options."""


@app.command("list-payloads")
def list_payloads_command(
    payloads_dir: Path | None = typer.Option(
        None,
        "--payloads-dir",
        "-p",
        help="Directory of payload YAML files. Defaults to the bundled library.",
    ),
    language: list[str] = typer.Option(
        [],
        "--language",
        "-l",
        help="ISO 639-1 language code; pass repeatedly to allow multiple.",
    ),
    category: Category | None = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter to a single category.",
    ),
) -> None:
    """List payloads from the bundled or a custom library."""
    payloads = _safe_load_payloads(payloads_dir, language)
    if category is not None:
        payloads = [p for p in payloads if p.category is category]

    if not payloads:
        err_console.print("[yellow]No payloads matched the given filters.[/yellow]")
        raise typer.Exit(code=1)

    table = Table(title=f"{len(payloads)} payload(s)")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Lang")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("OWASP")
    table.add_column("Name")
    for p in payloads:
        table.add_row(
            p.id,
            p.language,
            p.category.value,
            p.severity.value,
            p.owasp_llm_top10,
            p.name,
        )
    console.print(table)


@app.command("scan")
def scan_command(
    target_config: Path = typer.Option(
        ...,
        "--target",
        "-t",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="YAML file describing the target endpoint.",
    ),
    payloads_dir: Path | None = typer.Option(
        None,
        "--payloads-dir",
        "-p",
        help="Directory of payload YAML files. Defaults to the bundled library.",
    ),
    language: list[str] = typer.Option(
        [],
        "--language",
        "-l",
        help="ISO 639-1 language filter; pass repeatedly to allow multiple.",
    ),
    category: Category | None = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter to a single category.",
    ),
    output_format: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Reporter to use for the output.",
        case_sensitive=False,
    ),
    output_path: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the rendered report to this file instead of stdout.",
    ),
    concurrency: int = typer.Option(
        1,
        "--concurrency",
        min=1,
        help="Maximum number of in-flight requests.",
    ),
) -> None:
    """Run a scan and render the result."""
    target = _build_target(target_config)
    payloads = _safe_load_payloads(payloads_dir, language)
    if category is not None:
        payloads = [p for p in payloads if p.category is category]
    if not payloads:
        err_console.print("[yellow]No payloads matched the given filters.[/yellow]")
        raise typer.Exit(code=1)

    err_console.print(
        f"[dim]Scanning [bold]{target.name}[/bold] with {len(payloads)} payload(s)…[/dim]"
    )

    scanner = Scanner(
        target=target,
        evaluator=RuleBasedEvaluator(),
        concurrency=concurrency,
    )
    try:
        result = asyncio.run(scanner.scan(payloads))
    except LLMScannerError as exc:
        err_console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    rendered = _render_result(result, output_format)
    if output_path is None:
        sys.stdout.write(rendered)
    else:
        output_path.write_text(rendered, encoding="utf-8")
        err_console.print(f"[green]Report written to {output_path}[/green]")

    if result.vulnerable_count > 0:
        raise typer.Exit(code=1)


def _safe_load_payloads(
    payloads_dir: Path | None,
    languages: list[str],
) -> list[Payload]:
    try:
        return load_payloads(payloads_dir, languages=languages or None)
    except LLMScannerError as exc:
        err_console.print(f"[red]Failed to load payloads:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _build_target(config_path: Path) -> Target:
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        err_console.print(f"[red]Invalid YAML in {config_path}:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if not isinstance(raw, dict):
        err_console.print(f"[red]Target config {config_path} must be a mapping.[/red]")
        raise typer.Exit(code=2)

    expanded = _expand_env(raw)
    target_type = expanded.pop("type", "http")
    if target_type != "http":
        err_console.print(
            f"[red]Unsupported target type {target_type!r}; only 'http' is built in today.[/red]"
        )
        raise typer.Exit(code=2)

    try:
        return HTTPTarget(**expanded)
    except TypeError as exc:
        err_console.print(f"[red]Invalid target config:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _expand_env(node: Any) -> Any:
    """Recursively replace ``${VAR}`` tokens in string leaves with environment values."""
    if isinstance(node, str):
        return _ENV_VAR_PATTERN.sub(_lookup_env, node)
    if isinstance(node, dict):
        return {k: _expand_env(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_expand_env(item) for item in node]
    return node


def _lookup_env(match: re.Match[str]) -> str:
    name = match.group(1)
    value = os.environ.get(name)
    if value is None:
        err_console.print(
            f"[red]Target config references unset environment variable ${{{name}}}.[/red]"
        )
        raise typer.Exit(code=2)
    return value


def _render_result(result: Any, output_format: str) -> str:
    fmt = output_format.lower()
    if fmt == "markdown":
        return MarkdownReporter().render(result)
    if fmt == "json":
        return JSONReporter().render(result)
    err_console.print(
        f"[red]Unsupported format {output_format!r}; choose 'markdown' or 'json'.[/red]"
    )
    raise typer.Exit(code=2)


if __name__ == "__main__":  # pragma: no cover
    app()
