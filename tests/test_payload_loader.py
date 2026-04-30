"""Tests for the YAML payload loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from llm_security_scanner import Payload, load_payload_file, load_payloads
from llm_security_scanner.exceptions import PayloadError
from llm_security_scanner.payloads.loader import DEFAULT_PAYLOAD_DIR

VALID_ENTRY = """
- id: jb-en-test-001
  name: "Test entry"
  category: jailbreak
  owasp_llm_top10: LLM01
  severity: medium
  language: en
  payload: "test prompt"
  success_indicators:
    - pattern: "ok"
      type: substring
"""


class TestLoadPayloadFile:
    def test_loads_valid_file(self, tmp_path: Path) -> None:
        f = tmp_path / "p.yaml"
        f.write_text(VALID_ENTRY, encoding="utf-8")
        result = load_payload_file(f)
        assert len(result) == 1
        assert isinstance(result[0], Payload)
        assert result[0].id == "jb-en-test-001"

    def test_empty_file_returns_empty_list(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.yaml"
        f.write_text("", encoding="utf-8")
        assert load_payload_file(f) == []

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(PayloadError, match="not found"):
            load_payload_file(tmp_path / "nope.yaml")

    def test_malformed_yaml_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.yaml"
        f.write_text("- id: x\n  name: [unterminated", encoding="utf-8")
        with pytest.raises(PayloadError, match="Invalid YAML"):
            load_payload_file(f)

    def test_top_level_must_be_list(self, tmp_path: Path) -> None:
        f = tmp_path / "dict.yaml"
        f.write_text("id: jb-en-001\nname: x\n", encoding="utf-8")
        with pytest.raises(PayloadError, match="must contain a YAML list"):
            load_payload_file(f)

    def test_entry_must_be_mapping(self, tmp_path: Path) -> None:
        f = tmp_path / "scalar.yaml"
        f.write_text("- just a string\n", encoding="utf-8")
        with pytest.raises(PayloadError, match="must be a mapping"):
            load_payload_file(f)

    def test_invalid_entry_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.yaml"
        f.write_text(
            "- id: x\n  name: x\n  category: not_a_real_category\n"
            "  owasp_llm_top10: LLM01\n  severity: medium\n  language: en\n"
            "  payload: x\n",
            encoding="utf-8",
        )
        with pytest.raises(PayloadError, match="Invalid payload entry"):
            load_payload_file(f)


class TestLoadPayloads:
    def test_loads_recursively(self, tmp_path: Path) -> None:
        (tmp_path / "en").mkdir()
        (tmp_path / "en" / "a.yaml").write_text(VALID_ENTRY, encoding="utf-8")
        (tmp_path / "en" / "b.yml").write_text(
            VALID_ENTRY.replace("jb-en-test-001", "jb-en-test-002"), encoding="utf-8"
        )
        # Non-YAML file should be ignored.
        (tmp_path / "README.md").write_text("# notes", encoding="utf-8")
        result = load_payloads(tmp_path)
        assert [p.id for p in result] == ["jb-en-test-001", "jb-en-test-002"]

    def test_missing_dir_raises(self, tmp_path: Path) -> None:
        with pytest.raises(PayloadError, match="directory not found"):
            load_payloads(tmp_path / "nope")

    def test_language_filter(self, tmp_path: Path) -> None:
        (tmp_path / "en.yaml").write_text(VALID_ENTRY, encoding="utf-8")
        tr_entry = VALID_ENTRY.replace("jb-en-test-001", "jb-tr-test-001").replace(
            "language: en", "language: tr"
        )
        (tmp_path / "tr.yaml").write_text(tr_entry, encoding="utf-8")
        result = load_payloads(tmp_path, languages=["tr"])
        assert [p.id for p in result] == ["jb-tr-test-001"]

    def test_duplicate_ids_raise(self, tmp_path: Path) -> None:
        (tmp_path / "a.yaml").write_text(VALID_ENTRY, encoding="utf-8")
        (tmp_path / "b.yaml").write_text(VALID_ENTRY, encoding="utf-8")
        with pytest.raises(PayloadError, match="Duplicate payload IDs"):
            load_payloads(tmp_path)

    def test_default_payload_dir_loads(self) -> None:
        """The bundled payload library at the repo root must always be valid."""
        assert DEFAULT_PAYLOAD_DIR.is_dir()
        result = load_payloads()
        assert len(result) >= 10
        assert all(isinstance(p, Payload) for p in result)
        ids = [p.id for p in result]
        assert ids == sorted(ids)
        assert len(set(ids)) == len(ids)

    def test_default_has_turkish_and_english(self) -> None:
        result = load_payloads()
        languages = {p.language for p in result}
        assert "tr" in languages
        assert "en" in languages

    def test_default_covers_expected_languages(self) -> None:
        """The bundled library ships parallel payload sets for every supported language."""
        result = load_payloads()
        languages = {p.language for p in result}
        assert {"en", "tr", "de", "es", "fr"} <= languages
