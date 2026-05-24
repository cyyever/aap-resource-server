# Open Agent Auth — AAP fork baseline

This repository is the upstream baseline being trimmed into an
**Agent Auth Protocol (AAP)** fork.

- Spec: [`cyyever/authentication_plan`](https://github.com/cyyever/authentication_plan) — single source `agent_auth_protocol.tex`
- Scope: authentication-only, single algorithm **Ed25519 + SHA-512** (`alg=EdDSA`), two wire messages — CT (delegation) and DPoP (per-request), JWS compact serialization, HTTPS only.
- Not provided: authorization, consent UI, CA / X.509, OAuth 2.0 / OIDC flows, W3C VC.

## Module

Single Maven module `open-agent-auth-core`. Protocol primitives (JWS
sign/verify, key management, JWKS provider, trust roots, WIT/WPT →
CT/DPoP after M1) plus the server-side actor (`ResourceServer`,
`DefaultResourceServer`, request/result models) under
`com.alibaba.openagentauth.core.server.*`. Pure Java, no Spring.

The module requires **Java 21 LTS** (or later). Only direct deps are
[Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt),
Jackson, and SLF4J. Spring Boot is no longer required — consumers
(Spring Boot apps, Quarkus, Helidon, plain `main`) wire `WitValidator`
+ `WptValidator` + `DefaultResourceServer` directly, usually in ~20
lines.

## Status

- Trim phase done (commits `c8f7c95` through current `HEAD`)
- **M1 retrofit pending**: ~250 LoC of patches — lock `alg=EdDSA`,
  strict JOSE header whitelist, DPoP module, PIC cascade revocation,
  CRL anti-rollback, JSONL error events.
- README, package layout (`core.protocol.wimse.*`), and class names
  (`WIT`, `WPT`) will be renamed to spec terms (`CT`, `DPoP`) during M1.

Licensed under the Apache License 2.0 — see [LICENSE](LICENSE).
