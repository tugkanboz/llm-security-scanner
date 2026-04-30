# llm-security-scanner

[![CI](https://github.com/tugkanboz/llm-security-scanner/actions/workflows/test.yml/badge.svg)](https://github.com/tugkanboz/llm-security-scanner/actions/workflows/test.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/ruff-checked-brightgreen)](https://docs.astral.sh/ruff/)

> Red-team toolkit for testing LLM applications against prompt injection,
> jailbreaks, data exfiltration, and tool abuse — with first-class Turkish
> payload support.

`llm-security-scanner` is an open-source security testing framework for
applications built on top of large language models. Think of it as
"OWASP ZAP for LLM apps": a pluggable engine that fires curated payloads at a
target, evaluates whether the model misbehaved, and produces actionable
reports. The project ships a Turkish payload library alongside English to
serve the Turkish-speaking developer community.

> ⚠️ **Responsible use.** This toolkit is intended for defensive research,
> red-teaming systems you own or have authorisation to test, and educational
> exploration of LLM failure modes. Do not use it to attack systems you do
> not have permission to test.

## Status

Early development. APIs are unstable until v1.0.

## Why another scanner?

| Project       | Differentiator of `llm-security-scanner`                                |
| ------------- | ----------------------------------------------------------------------- |
| Garak         | Turkish payload library + OWASP LLM Top 10 alignment baked into models  |
| PromptFoo     | Security-first focus rather than general eval harness                   |
| Giskard       | Standalone CLI + library, no platform lock-in                           |

## Architecture

The scanner is built around four pluggable abstractions, all defined as
runtime-checkable `Protocol`s in `src/llm_security_scanner/`:

- **`Target`** (`targets/base.py`) — adapter for an LLM provider (Anthropic,
  OpenAI, Ollama, generic HTTP). Translates a prompt into a `TargetResponse`.
- **`Evaluator`** (`evaluators/base.py`) — judges whether a payload
  succeeded. Implementations include rule-based matchers and LLM-as-judge.
- **`Reporter`** (`reporters/base.py`) — renders a `ScanResult` as Markdown,
  HTML, JSON, or SARIF.
- **Payloads** (`payloads/`) — YAML data files validated by the Pydantic
  `Payload` model. Non-developers can contribute payloads via PRs.

The core scanner depends only on these protocols, so the engine never knows
which provider, evaluator, or output format is in use.

## Payload schema

Every payload conforms to this schema (validated on load):

```yaml
- id: jb-tr-001
  name: "Turkish DAN variant"
  category: jailbreak           # jailbreak | direct_injection | indirect_injection
                                # | sys_prompt_leak | data_exfil | tool_abuse | multi_turn
  owasp_llm_top10: LLM01
  severity: high                # low | medium | high | critical
  language: tr                  # ISO 639-1
  payload: |
    ...prompt text...
  success_indicators:
    - pattern: "DAN:"
      type: substring           # substring | regex | semantic
  references:
    - "https://..."
  tags: [role-play, dan]
```

## CLI

`llm-sec-scan` ships with two commands:

```bash
# Browse the bundled payload library
llm-sec-scan list-payloads --language tr --category jailbreak

# Run a scan from a target config and write a Markdown report
llm-sec-scan scan \
  --target ./examples/ollama.yaml \
  --language tr \
  --format markdown \
  --output report.md
```

A target config is a small YAML file. `${VAR}` references are expanded
from the environment so secrets stay out of disk:

```yaml
type: http
name: openai-chat
url: https://api.openai.com/v1/chat/completions
headers:
  Authorization: "Bearer ${OPENAI_API_KEY}"
  Content-Type: application/json
body_template:
  model: "gpt-4o-mini"
  messages:
    - role: user
      content: "{prompt}"
response_path: ["choices", 0, "message", "content"]
```

`scan` exits with code `1` whenever at least one vulnerable finding is
detected, so it slots cleanly into CI.

## Quick example

Run the bundled Turkish payloads against a local Ollama endpoint, score
each response with the rule-based evaluator, and print a summary:

```python
import asyncio

from llm_security_scanner import Scanner, load_payloads
from llm_security_scanner.evaluators import RuleBasedEvaluator
from llm_security_scanner.targets import HTTPTarget


async def main() -> None:
    target = HTTPTarget(
        name="local-ollama",
        url="http://localhost:11434/api/generate",
        body_template={"model": "llama3", "prompt": "{prompt}", "stream": False},
        response_path=["response"],
    )
    scanner = Scanner(
        target=target,
        evaluator=RuleBasedEvaluator(),
        concurrency=2,
    )
    result = await scanner.scan(load_payloads(languages=["tr"]))

    print(f"{result.target_name}: {result.vulnerable_count}/{result.total} vulnerable")
    for finding in result.findings:
        flag = "VULN" if finding.is_vulnerable else "ok  "
        print(f"  [{flag}] {finding.payload.id} — {finding.evaluation.reason}")


asyncio.run(main())
```

## Development

Requirements: Python 3.10+ and [`uv`](https://docs.astral.sh/uv/) (or `pip`).

```bash
# Clone and install
git clone https://github.com/tugkanboz/llm-security-scanner.git
cd llm-security-scanner
uv pip install -e ".[dev]"

# Run tests
pytest

# Lint and type-check
ruff check .
mypy
```

## Roadmap

- [x] Project skeleton: tooling, base protocols, core models
- [x] Payload loader with YAML validation
- [x] Seed payload library (5 languages × 3 categories: EN, TR, DE, ES, FR)
- [x] Generic HTTP target adapter
- [x] Rule-based evaluator (substring + regex)
- [x] Scanner core orchestration with bounded concurrency
- [x] Reporters: Markdown and JSON
- [x] CLI (`llm-sec-scan`) with `scan` and `list-payloads`
- [x] CI: lint, type-check, tests on every PR
- [ ] Native-speaker review of DE/ES/FR payload sets
- [ ] Provider adapters: Anthropic, OpenAI, Ollama
- [ ] LLM-as-judge evaluator
- [ ] Reporters: SARIF and HTML
- [ ] v1.0 stabilisation and PyPI release

## Translation note

The Turkish (`tr`) payloads are author-written. The German (`de`),
Spanish (`es`), and French (`fr`) sets were initially produced with AI
assistance and have **not yet been reviewed by native speakers**. PRs
improving phrasing, idiom, or success-indicator regexes from native
speakers are very welcome — see `CONTRIBUTING.md`.

## Contributing

Contributions are welcome — payloads especially. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines and the payload
schema. Security issues should follow [`SECURITY.md`](SECURITY.md);
participation is governed by the [code of conduct](CODE_OF_CONDUCT.md).

## Türkçe

`llm-security-scanner`, LLM uygulamalarını prompt injection, jailbreak ve veri
sızdırma saldırılarına karşı test eden açık kaynaklı bir red-team aracıdır.
Türkçe payload kütüphanesiyle Türkçe konuşan geliştirici topluluğunu
hedefler. Proje aktif geliştirme aşamasındadır; katkılara — özellikle Türkçe
payload katkılarına — açıktır.

## Licence

MIT — see [`LICENSE`](LICENSE).
