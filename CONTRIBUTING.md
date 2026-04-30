# Contributing to llm-security-scanner

Thanks for your interest in contributing! This project welcomes contributions
of all sizes — bug fixes, new payloads, additional language coverage,
provider adapters, documentation, and more.

By submitting a contribution you agree that your work will be licensed under
the project's [MIT licence](LICENSE).

## Quick start

```bash
git clone https://github.com/tugkanboz/llm-security-scanner.git
cd llm-security-scanner
uv pip install -e ".[dev]"   # or: pip install -e ".[dev]"

pytest           # tests
ruff check .     # lint
mypy             # type check
```

## What we welcome most

1. **New payloads**, especially in languages we don't yet cover. See the
   payload schema below.
2. **Native-speaker review** of the AI-translated DE/ES/FR sets currently
   in `payloads/`.
3. **Provider adapters** for Anthropic, OpenAI, Ollama, vLLM, etc.
4. **Reporters**: SARIF, HTML, JUnit XML.
5. **Bug reports** with a minimal reproducer.

## Contributing payloads

Payloads live as YAML data under `payloads/<lang>/<category>.yaml`. Every
entry is validated against the `Payload` Pydantic model on load.

```yaml
- id: jb-tr-007                 # unique, kebab-case, lang-prefixed
  name: "Short human-readable name"
  category: jailbreak           # jailbreak | direct_injection
                                # | indirect_injection | sys_prompt_leak
                                # | data_exfil | tool_abuse | multi_turn
  owasp_llm_top10: LLM01        # OWASP LLM Top 10 (2025) mapping
  severity: high                # low | medium | high | critical
  language: tr                  # ISO 639-1
  payload: |
    The actual prompt text.
  success_indicators:
    - pattern: "canary token"
      type: substring           # substring | regex | semantic
  references:
    - "https://example.com/source-paper"
  tags: [optional, free-form]
```

Rules:

- **Keep payloads representative, not weaponised.** For genuinely dangerous
  techniques, reference the source rather than reproducing it.
- **Preserve the responsible-use framing.** This is a defensive testing
  toolkit.
- **Add at least one rule-based success indicator** so the existing
  evaluator can score your payload.
- Run `pytest tests/test_payload_loader.py` to verify your YAML loads.

## Pull request checklist

Before opening a PR, please make sure:

- [ ] `pytest` passes locally.
- [ ] `ruff check .` is clean.
- [ ] `mypy` is clean (we run in strict mode for the public API).
- [ ] New behaviour has at least one test.
- [ ] Public API changes are documented in the README.
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/),
      e.g. `feat(payloads): add Italian jailbreak set`.

## Reporting security issues

Please do **not** open public issues for vulnerabilities in the toolkit
itself or in any system you discover via it. See [SECURITY.md](SECURITY.md)
for the responsible-disclosure path.

## Code of conduct

By participating in this project you agree to abide by the
[Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
