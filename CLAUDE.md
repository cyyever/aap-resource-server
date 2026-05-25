# Working on this repo with Claude Code

This file is loaded into Claude Code's context on every session. Keep it
short and concrete — capture project-level rules, never per-task state.

## What this repo is

The upstream baseline for an **AAP (Agent Auth Protocol) fork**. AAP spec
lives at [`cyyever/authentication_plan`](https://github.com/cyyever/authentication_plan)
— single source `agent_auth_protocol.tex`. Roadmap is in spec §9, SDK
details in §10.

The trim phase is done. M1 #1–#3 (alg=EdDSA lock, JOSE header whitelist,
DPoP/CT rename) have landed. The remaining work is the **M1 retrofit
tail (~130 LoC)** — see [Pending → M1](#m1-retrofit-pending).

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
                           keys, JWKS, trust, CT/DPoP under
                           core.protocol.{ct,dpop}) plus the
                           server-side actor (ResourceServer +
                           DefaultResourceServer) under
                           core.server.*. Pure Java.
```

The framework module was folded into core in 2026-05; no Spring Boot
starter, no integration-tests module, no samples. Consumers wire
`CtValidator` + `DpopValidator` + `DefaultResourceServer` themselves
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
  model classes (Jwk, AgentIdentity, DpopToken, CredentialToken) were
  converted in this trim and saved ~78% LoC. Use compact canonical
  constructors for REQUIRED-field validation. Throw
  `IllegalStateException` (matches existing test expectations), not
  `NullPointerException` from `Objects.requireNonNull`.
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

Spec §10.2. Status:

1. ~~**`alg=EdDSA` lock**~~ — **done**. `CtParser` + `DpopParser`
   enforce `alg=EdDSA` and `typ=ct+jwt`/`dpop+jwt` before signature
   verify.
2. ~~**JOSE header whitelist**~~ — **done**. `{alg, typ}` only on CT
   (DPoP also allows `jwk`); any other JOSE header → ParseException.
3. ~~**DPoP module**~~ — **done** (commit `643bbfb`).
   `core/protocol/dpop/` lives; `DpopToken` carries `wth`/`ath` claims.
   The `htm`/`htu`/`iat`/`jti` claim sweep is still TODO inside the
   existing module.

Remaining (~130 LoC):

4. **PIC cascade revocation** (~50 LoC) — registry HTTPS responses
   (JWS). Revoking a P invalidates all CTs signed by `sk_P`. New
   `core/registry/`.
5. **CRL anti-rollback** (~30 LoC) — every CRL has monotonic `seq`;
   verifier rejects `seq < lastSeen`.
6. **JSONL error events** (~50 LoC) — replaces the deleted
   `AuditLogEntry`. One line per verification failure, stdout/file/
   env-configurable.
7. **HTTP header whitelist enforcer** — network-side complement to (2).

The "After M1, also rename" sweep (packages, class names, header /
key-id constants, residual `WIMSE` / `AOA` / `AOAT` / `DCR` /
`5-layer` / `OIDC` strings) shipped early — see commits `f37f37b`,
`643bbfb`, `1ebd5f2`.

## Perf hot spots already identified

Audited but not yet fixed (most need M1 rename first):

1. ~~`JwtHashUtil.computeSha256Hash`~~ — **done**. `ThreadLocal<MessageDigest>`
   + static `Base64.Encoder` already in place. JMH baseline (Temurin 26,
   Apple Silicon, 1024-byte JWT): 2.07 ops/μs single-thread, 10.35 ops/μs
   at 8 threads. Bench module: `open-agent-auth-bench` (opt-in `-P bench`).
2. ~~`DpopValidator.convertToJWK`~~ — **done**. `ConcurrentHashMap<Jwk, JWK>`
   keyed by record-value-equality on `Jwk`; first validation per cnf.jwk
   pays the Base64-decode, subsequent ones hit cache.
3. ~~`JwksConsumerKeyResolver`~~ — **done**. TTL + single-flight on cold
   start (`compute`-locked) + key-not-found throttle were already in
   place; stale-while-revalidate added so a TTL-expired entry serves
   the stale value while one background virtual thread refreshes.
   Cold-start fetches still block (correct).
4. ~~`SignedJWT.parse` called twice per DPoP validation~~ — **done**.
   `DpopParser.parse(SignedJWT)` mirrors `CtParser`; `DefaultResourceServer`
   parses once and passes the `SignedJWT` into `DpopValidator.validate`
   for signature verify. The ad-hoc 2-arg `validate(DpopToken, CredentialToken)`
   is kept as back-compat (still parses internally).
5. ~~`Token.isExpired/isValid`~~ — **done**. Now compares
   `expirationTime.getTime()` against `System.currentTimeMillis()` —
   zero allocations. Internal `Date` field kept (the M1 rename of the
   surrounding records may revisit type).

## Bookmarks

- This repo's git history is the long-form record of the trim. Recent
  pattern: 20+ `chore(aap): drop X` commits between `c8f7c95` and
  `5a83240` cleared the upstream OAA scaffolding (~25k LoC net).
- The actual fork branch convention is `aap-main` per spec §10.3;
  the current trim is happening on `main` because no upstream rebase
  is happening yet.
