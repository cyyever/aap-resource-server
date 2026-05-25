# Open Agent Auth — AAP fork baseline

This repository is the upstream baseline being trimmed into an
**Agent Auth Protocol (AAP)** fork.

- Spec: [`cyyever/authentication_plan`](https://github.com/cyyever/authentication_plan) — single source `agent_auth_protocol.tex`. Vendored at `spec/` as a submodule for offline browsing; spec PRs go to the spec repo, not here.
- Scope: authentication-only, single algorithm **Ed25519 + SHA-512** (`alg=EdDSA`), two wire messages — CT (delegation) and DPoP (per-request), JWS compact serialization, HTTPS only.
- Not provided: authorization, consent UI, CA / X.509, OAuth 2.0 / OIDC flows, W3C VC.

## Module

Single Maven module `open-agent-auth-core`. Protocol primitives (JWS
sign/verify, key management, JWKS provider, trust roots, CT/DPoP under
`core.protocol.{ct,dpop}`) plus the server-side actor (`ResourceServer`,
`DefaultResourceServer`, request/result models) under
`ai.shao.openagentauth.core.server.*`. Pure Java, no Spring.

The module requires **Java 21 LTS** (or later). Only direct deps are
[Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt),
Jackson, and SLF4J. Spring Boot is no longer required — consumers
(Spring Boot apps, Quarkus, Helidon, plain `main`) wire `CtValidator`
+ `DpopValidator` + `DefaultResourceServer` directly, usually in ~20
lines.

## Status

- Trim phase done (commits `c8f7c95` through current `HEAD`).
- M1 #1–#3 landed: `alg=EdDSA` lock, JOSE header whitelist, CT/DPoP
  rename (package `core.protocol.{ct,dpop}`, classes `CredentialToken`
  / `DpopToken`).
- **M1 tail pending** (~130 LoC): PIC cascade revocation, CRL
  anti-rollback, JSONL error events, HTTP header whitelist enforcer.

Licensed under the Apache License 2.0 — see [LICENSE](LICENSE).
