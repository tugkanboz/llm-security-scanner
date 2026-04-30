# Security policy

`llm-security-scanner` is a defensive red-team toolkit. We take both the
security of the toolkit itself and the responsible use of the techniques
it exercises seriously.

## Reporting a vulnerability in this project

If you discover a security issue in the scanner code, the bundled
payloads, or any supporting infrastructure (CI, releases, packaging),
**please do not open a public GitHub issue.**

Instead, report it privately by emailing:

> tgkn.boz@gmail.com

Include:

- A description of the issue and its impact.
- Steps to reproduce.
- The version or commit affected.
- Any proof-of-concept code, ideally minimal.

We will acknowledge receipt within **5 business days** and aim to provide
a fix or mitigation timeline within **14 days** of acknowledgement. We
will credit reporters in the release notes unless they prefer to remain
anonymous.

## Supported versions

The project is in active early development. Until v1.0, only the latest
release on `main` is supported.

| Version  | Supported        |
| -------- | ---------------- |
| `0.1.x`  | :white_check_mark: |
| `< 0.1`  | :x:              |

## Responsible-use policy

The payloads in this repository are **representative, defanged examples**
of publicly documented attack techniques. They exist so defenders can
verify that their LLM applications have baseline guardrails.

You **must** only run scans against systems you own or have explicit
written authorisation to test. Running this toolkit against third-party
systems without permission may violate computer-misuse laws in your
jurisdiction.

If you discover that a third-party LLM application is vulnerable to one
of the bundled payloads, please follow that vendor's responsible
disclosure process — not ours.

## Out of scope

- Attacks against systems you do not own.
- Payloads designed to maximise real-world harm rather than detect
  missing guardrails. PRs adding such payloads will be rejected.
