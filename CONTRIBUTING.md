# Contributing to Open Agent Auth (AAP fork)

This repository is the upstream baseline trimmed into an
**Agent Auth Protocol (AAP)** fork — see [README.md](README.md) and the
spec at [`cyyever/authentication_plan`](https://github.com/cyyever/authentication_plan)
for context.

## Prerequisites

- Java 21 LTS (or later)
- Maven 3.6+
- Git

## Setup

```bash
git clone https://github.com/cyyever/open-agent-auth.git
cd open-agent-auth
mvn clean install
mvn test
```

## Module layout

```
open-agent-auth/
└── aap-resource-server-core/   # protocol primitives + server-side actor
                            #   (core.server.* for ResourceServer /
                            #   DefaultResourceServer / request models)
```

Single Maven module, pure Java (no Spring). Consumers wire
`WitValidator`, `WptValidator`, and `DefaultResourceServer` themselves.

## Commit style

Conventional Commits — `<type>(<scope>): <subject>`. Scopes in active
use: `aap`, `core`. Recent history is a series of `chore(aap): drop X`
commits — keep that style for trim work.

## Coding standards

- Default to writing **no** Javadoc except for public APIs whose contract
  isn't obvious from the signature. Don't restate what the code already
  says.
- Don't add `// removed for AAP` or `// see commit X` comments — just
  delete. The git history is the audit trail.
- Validate inputs at module boundaries. Trust internal code.

## Tests

Run `mvn test`. Coverage report (HTML + summary table) is wired into
the `coverage` CI job and locally via `mvn -P coverage verify`.

## Security

Report vulnerabilities per [SECURITY.md](SECURITY.md).
