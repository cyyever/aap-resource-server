# Open Agent Auth — AAP fork baseline

This repository is the upstream baseline being trimmed into an
**Agent Auth Protocol (AAP)** fork.

- Spec: [`cyyever/authentication_plan`](https://github.com/cyyever/authentication_plan) — single source `agent_auth_protocol.tex`
- Scope: authentication-only, single algorithm **Ed25519 + SHA-512** (`alg=EdDSA`), two wire messages — CT (delegation) and DPoP (per-request), JWS compact serialization, HTTPS only.
- Not provided: authorization, consent UI, CA / X.509, OAuth 2.0 / OIDC flows, W3C VC.

The README will be rewritten once the M1 patches (~250 LoC: `alg` lock,
DPoP module, PIC cascade, CRL anti-rollback, JSONL error events, header
whitelist) settle. The original upstream content has been removed
because it described features (5-layer validator, AOA, MCP adapter,
consent pages, etc.) that the AAP trim removed.

Licensed under the Apache License 2.0 — see [LICENSE](LICENSE).
