# Policy pin

**Status:** Public Draft (v0.1)
**Version:** 0.1

## Abstract

A policy pin names one immutable policy document. This draft does not define a URI scheme. The reference form is:

```
{policy-id}@{semver}
```

An implementation may prefix a scheme. That prefix is not normative.

## Syntax

| Component | Rule |
|-----------|------|
| `policy-id` | kebab-case (`basic-agent-authority`) |
| `semver` | `major.minor.patch`, required |

```
basic-agent-authority                      invalid
basic-agent-authority@1.0.0                valid
```

## Immutability

`{policy-id}@{version}` never changes. An update is a new version. A pin of `@1.0.0` does not silently follow `@1.1.0`.

## Resolution

How a pin becomes a document is implementation-defined. A conforming evaluator resolves a pin from a document the caller already has. If the pin cannot be resolved, the decision is `BLOCK`.

This draft does not define a registry, a network API, a default host, or an authentication scheme.

## Reference

The reference evaluator in `packages/policy-engine` exports `parsePolicyPin()`. That code is not part of the pin syntax.
