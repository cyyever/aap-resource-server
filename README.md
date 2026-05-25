# AAP Resource Server (Java)

Java reference implementation of the **resource-server (RP) side** of the
[Agent Auth Protocol](https://github.com/cyyever/authentication_plan) (AAP).
Parses and verifies the two wire messages (CT for delegation, DPoP per
request), validates them against a configured trust domain + JWKS, and
returns a typed [`TokenValidationResult`](aap-resource-server-core/src/main/java/ai/shao/aap/rs/core/token/common/TokenValidationResult.java)
ADT — `Success<T>` or `Failure<String>`.

The spec is vendored at `spec/` as a git submodule; spec PRs go to the
spec repo, not here.

## Scope

- Single algorithm: **Ed25519 + SHA-512** (`alg=EdDSA`). Everything else
  rejected with `MALFORMED`.
- Two wire messages: **CT** (delegation, signed by `sk_P`) and **DPoP**
  (per-request, signed by `sk_S`). JWS compact serialization.
- JOSE header whitelist: `{alg, typ}` only (DPoP also permits `jwk`).
- HTTPS only. **No** AuthZ, consent UI, CA / X.509, OAuth 2.0 / OIDC,
  W3C VC.

## Module

Single Maven module `aap-resource-server-core` under
`ai.shao.aap.rs.core.*`. Pure Java 21. Direct deps: Nimbus JOSE+JWT,
Jackson, SLF4J, JSpecify. No Spring — consumers (Spring Boot, Quarkus,
plain `main`) wire `CtValidator` + `DpopValidator` +
`DefaultResourceServer` in ~20 lines of their own DI.

## Build & quality gates

```bash
mvn -B test                     # unit tests (293 / 293)
mvn -P errorprone clean compile # Error Prone + NullAway @ ERROR, 0 findings
mvn -P spotbugs verify          # SpotBugs + FindSecBugs, 0 findings
mvn -P format spotless:apply    # google-java-format AOSP, in-place
mvn -P coverage verify          # JaCoCo report at target/site/jacoco/
```

CI runs the four lint/test profiles plus CodeQL (`security-extended`)
and dependency-review on every push and PR. Java 21 LTS is the minimum.

## Status

- **M1 #1–#3 landed**: `alg=EdDSA` lock, JOSE header whitelist, CT/DPoP
  package + class rename (`core.protocol.{ct,dpop}`, `CredentialToken`,
  `DpopToken`).
- **M1 tail pending** (~330–390 LoC after spec v0.9.4/v0.9.5 re-scope):
  DPoP claims (`htm`/`htu`/`iat`/`jti`/`ath`), registry keyset + trust
  set with trial-verify, CRL ingest + anti-rollback + cascade, PIC
  fetch, operator-supplied `pk_R` blacklist, JSONL error events, HTTP
  header whitelist enforcer.

Licensed under the Apache License 2.0 — see [LICENSE](LICENSE).
