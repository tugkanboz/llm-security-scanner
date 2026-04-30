"""Load and validate payloads from on-disk YAML files.

Payloads live as data files under a directory tree (one file per category or
per language) so non-developers can contribute via PRs. Each file must
contain a YAML list of payload entries; each entry is validated against the
:class:`Payload` Pydantic model. Duplicate payload IDs across the loaded set
are treated as a configuration error.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from llm_security_scanner.exceptions import PayloadError
from llm_security_scanner.models import Payload

DEFAULT_PAYLOAD_DIR: Path = Path(__file__).resolve().parents[3] / "payloads"
"""Path to the bundled payload library at the repository root."""

_YAML_SUFFIXES = frozenset({".yaml", ".yml"})


def load_payload_file(path: Path | str) -> list[Payload]:
    """Load and validate a single YAML file containing a list of payloads.

    Args:
        path: Path to a ``.yaml`` or ``.yml`` file.

    Returns:
        The parsed payloads in the order they appeared in the file.

    Raises:
        PayloadError: If the file is missing, malformed YAML, not a list, or
            contains an entry that fails Pydantic validation.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise PayloadError(f"Payload file not found: {file_path}")

    try:
        raw = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PayloadError(f"Invalid YAML in {file_path}: {exc}") from exc

    if raw is None:
        return []
    if not isinstance(raw, list):
        raise PayloadError(
            f"Payload file {file_path} must contain a YAML list at the top level, "
            f"got {type(raw).__name__}."
        )

    payloads: list[Payload] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise PayloadError(
                f"Payload entry #{index} in {file_path} must be a mapping, "
                f"got {type(entry).__name__}."
            )
        try:
            payloads.append(Payload.model_validate(entry))
        except ValidationError as exc:
            raise PayloadError(f"Invalid payload entry #{index} in {file_path}:\n{exc}") from exc

    return payloads


def load_payloads(
    root: Path | str | None = None,
    *,
    languages: Iterable[str] | None = None,
) -> list[Payload]:
    """Recursively load all payload YAML files under ``root``.

    Args:
        root: Directory to scan. Defaults to :data:`DEFAULT_PAYLOAD_DIR`
            (the bundled library at the repository root).
        languages: Optional iterable of ISO 639-1 codes. When provided, only
            payloads whose ``language`` field matches one of these codes are
            returned.

    Returns:
        All validated payloads found, sorted by ``id`` for stable ordering.

    Raises:
        PayloadError: If the directory is missing, a file fails to validate,
            or duplicate payload IDs are detected across the loaded set.
    """
    root_path = Path(root) if root is not None else DEFAULT_PAYLOAD_DIR
    if not root_path.is_dir():
        raise PayloadError(f"Payload directory not found: {root_path}")

    lang_filter = {lang.lower() for lang in languages} if languages is not None else None

    collected: list[Payload] = []
    for file_path in sorted(root_path.rglob("*")):
        if file_path.is_file() and file_path.suffix.lower() in _YAML_SUFFIXES:
            collected.extend(load_payload_file(file_path))

    if lang_filter is not None:
        collected = [p for p in collected if p.language.lower() in lang_filter]

    _check_unique_ids(collected)
    collected.sort(key=lambda p: p.id)
    return collected


def _check_unique_ids(payloads: list[Payload]) -> None:
    seen: dict[str, Any] = {}
    duplicates: list[str] = []
    for p in payloads:
        if p.id in seen:
            duplicates.append(p.id)
        else:
            seen[p.id] = p
    if duplicates:
        raise PayloadError("Duplicate payload IDs detected: " + ", ".join(sorted(set(duplicates))))
