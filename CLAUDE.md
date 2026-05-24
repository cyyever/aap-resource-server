# Working on this repo with Claude Code

This file is loaded into Claude Code's context on every session. Keep it
short and concrete — capture project-level rules, never per-task state.

## What this repo is

The upstream baseline for an **AAP (Agent Auth Protocol) fork**. AAP spec
lives at [`cyyever/authentication_plan`](https://github.com/cyyever/authentication_plan)
— single source `agent_auth_protocol.tex`. Roadmap is in spec §9, SDK
details in §10.

The trim phase is mostly done. The remaining work is the **M1 retrofit
(~250 LoC of patches)** — see [Pending → M1](#m1-retrofit-pending).

## Hard rules from the spec

Do not relax any of these without a spec change:

- **Java 21 LTS** baseline. Spec previously said Java 17+; bumped to
  21 LTS+ in 2026-05 (spec commit `c9b3a42`) for downstream-customer
  compatibility + JaCoCo / tooling support. This repo briefly ran 26
  mid-trim — that was never spec-mandated.
- Algorithm whitelist: **`alg=EdDSA` only** (Ed25519 + SHA-512). Reject
  `alg=none`, key-confusion, anything else → MALFORMED.
- JOSE header whitelist: `{alg, typ}` only (DPoP also allows `jwk`).
- Two wire messages only: **CT** (delegation, signed by `sk_P`) and
  **DPoP** (per-request, signed by `sk_S`). JWS compact serialization.
- PIC/CRL are registry HTTPS responses (themselves JWS).
- HTTPS only. **No AuthZ, no consent UI, no CA / X.509, no OAuth 2.0 /
  OIDC, no W3C VC.**

## Module layout

```
open-agent-auth-core/      single module — protocol primitives (JWS,
                           keys, JWKS, trust, WIT/WPT → CT/DPoP after
                           M1) plus the server-side actor (ResourceServer
                           + DefaultResourceServer) under
                           core.server.*. Pure Java.
```

The framework module was folded into core in 2026-05; no Spring Boot
starter, no integration-tests module, no samples. Consumers wire
`WitValidator` + `WptValidator` + `DefaultResourceServer` themselves
in ~20 lines of their own DI.

## Build

```bash
# Linux dev host (system javac already points at Java 21)
mvn -B test
# macOS (Temurin via `brew install --cask temurin@21`)
JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home mvn -B test
```

Any JDK ≥ 21 works; CI runs on Temurin 21. macOS has no system `javac`,
so an explicit `JAVA_HOME` is needed there.

The pom only declares: nimbus-jose-jwt, Jackson (databind/annotations/
jsr310), SLF4J, jakarta.servlet/validation (provided/test), JUnit 5,
Mockito, AssertJ. No Spring. JaCoCo (0.8.13) was re-added after the
Java 21 LTS downgrade — runs as a separate CI job to keep main test
runs fast.

## Coding conventions (project-specific)

- **Don't write `// removed for AAP` / `// see commit X` comments — just
  delete.** Spec authors prefer terse codebases; the git history is the
  audit trail.
- **Don't write javadoc that restates the signature.** Public-API
  protocol contracts deserve a one-liner; everything else doesn't.
- **Don't add new javadoc cross-references** (`@see`/`@link`) for
  in-package types. They become bit-rot during the M1 rename.
- **Records over Builder-classes** for new pure-data types. All four
  model classes (Jwk, AgentIdentity, WorkloadProofToken,
  WorkloadIdentityToken) were converted in this trim and saved ~78% LoC.
  Use compact canonical constructors for REQUIRED-field validation.
  Throw `IllegalStateException` (matches existing test expectations),
  not `NullPointerException` from `Objects.requireNonNull`.
- **Builders allowed only for ergonomic construction** of records with
  many optional fields. Keep them as static inner classes.
- **No new functionality during the trim phase.** If something has zero
  external refs, delete it. Don't preserve it "for future use".

## Conventions when committing

- Conventional Commits with `chore(aap):` or `refactor(aap):` scope. Pattern
  matches recent history (e.g. `chore(aap): drop X`).
- Use HEREDOC for commit messages to preserve formatting.
- Co-author trailer: `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`.
- Push only when the user asks ("push"). Don't push automatically.

## M1 retrofit (pending)

Spec §10.2 — **~250 LoC total**. Order of operations:

1. **`alg=EdDSA` lock** — reject `alg=none` / key-confusion. `WitParser`
   + `WptParser` header check before signature verify. ~10 LoC.
2. **JOSE header whitelist** — `{alg, typ}` only (DPoP +`jwk`). Any
   other JOSE header → MALFORMED. ~15 LoC.
3. **DPoP module** (~60 LoC) — `core/protocol/wimse/wpt/` → new
   `core/protocol/dpop/`. Rename `WorkloadProofToken` → DPoP; add
   `htm`/`htu`/`iat`/`jti`/`ath` claims.
4. **PIC cascade revocation** (~50 LoC) — registry HTTPS responses
   (JWS). Revoking a P invalidates all CTs signed by `sk_P`. New
   `core/registry/`.
5. **CRL anti-rollback** (~30 LoC) — every CRL has monotonic `seq`;
   verifier rejects `seq < lastSeen`.
6. **JSONL error events** (~50 LoC) — replaces the deleted
   `AuditLogEntry`. One line per verification failure, stdout/file/
   env-configurable.
7. **HTTP header whitelist enforcer** — network-side complement to (2).

After M1, also rename:
- package `core.protocol.wimse.{wit,wpt}` → `core.protocol.{ct,dpop}`
- `WorkloadIdentityToken` → `CredentialToken`
- `Workload-Identity-Token` HTTP header → spec term
- `KEY_WIT_VERIFICATION` → `KEY_CT_VERIFICATION`
- Residual `WIMSE` / `AOA` / `AOAT` / `DCR` / `5-layer` / `OIDC` strings
  in javadoc

## Perf hot spots already identified

Audited but not yet fixed (most need M1 rename first):

1. ~~`JwtHashUtil.computeSha256Hash`~~ — **done**. `ThreadLocal<MessageDigest>`
   + static `Base64.Encoder` already in place. JMH baseline (Temurin 26,
   Apple Silicon, 1024-byte JWT): 2.07 ops/μs single-thread, 10.35 ops/μs
   at 8 threads. Bench module: `open-agent-auth-bench` (opt-in `-P bench`).
2. `WptValidator.convertToJWK` — rebuilds Nimbus `JWK` from internal
   `Jwk` every validation (Base64-decode X/Y, new `BigInteger`,
   anonymous `ECPublicKey`). Cache by `Jwk` identity.
3. `JwksConsumerKeyResolver` — no TTL, no async refresh; key-not-found
   refetches synchronously per request (thundering herd).
4. `SignedJWT.parse` called twice per WPT validation (once in parser,
   once in validator). Store parsed `SignedJWT` on the token record.
5. `Token.isExpired/isValid` — `Date.from(Instant.now())` per check
   allocates 2 objects. Switch internal type to `Instant`.

## Bookmarks

- This repo's git history is the long-form record of the trim. Recent
  pattern: 20+ `chore(aap): drop X` commits between `c8f7c95` and
  `5a83240` cleared the upstream OAA scaffolding (~25k LoC net).
- The actual fork branch convention is `aap-main` per spec §10.3;
  the current trim is happening on `main` because no upstream rebase
  is happening yet.
