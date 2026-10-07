# Contributing to ADAP

This repository contains the open specification and its reference implementations.

- Schema (`PolicySchema`)
- YAML and JSON parser
- Safe condition evaluator
- Policy pin parser
- Authorization Receipt verifier

## Pull requests

1. Policy ids are kebab-case (`my-policy-name`)
2. A rule or grammar change needs a passing fixture and a failing fixture
3. Conditions use the safe evaluator. No `eval()`
4. A policy pin includes `@semver`
5. An unresolved pin fails closed

## Development

```bash
pnpm install
pnpm test
pnpm build
pnpm demo
```

```bash
cd packages/policy-engine
pnpm test
```

Schema changes stay backward compatible inside a major version. A breaking change is a new major version. A published `{policy-id}@{version}` document is not edited in place.
