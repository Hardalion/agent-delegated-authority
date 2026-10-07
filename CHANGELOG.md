# Changelog

## Unreleased

The front of the README is a public draft, not a claim to be a standard. It states the question the draft answers, and what it does not replace: identity, authentication, OAuth, agent communication, and execution runtimes.

The receipt binds `policy.contentHash`, the canonical hash of the policy document that was loaded, and `execution.intentHash`, the intent presented at the execution boundary. `pnpm attacks` runs six refusals: over-delegation, privilege escalation, prompt injection, replay, expiry, and a mutated intent after approval.

The receipt is independently verifiable offline when the issuer public key is available. `adap-receipt` checks the Ed25519 signature only with `--public-key`. `examples/proof/` publishes one reference run a third party can verify with no hosted service. The receipt binds the canonical hash of the policy document.

The Authorization Receipt binds each presented delegation by hash. An agent outside the policy is `BLOCK` (`agent_not_in_scope`). An unmatched call follows `defaultAction`. `executed` records what the governing runtime reported, not an independent observation of an external system. `pnpm demo` runs a synthetic principal-to-agent-to-agent purchase bound: route `ATH-LON`, maximum 500 EUR, a raised child grant refused, and instruction text that does not move the bound.

## 0.1.0 — 2026-10-07

Public Draft of the Agent Delegated Authority Protocol (ADAP).

ADAP is an open protocol for delegated authority between AI agents. An agent should never receive more authority than the principal intended to delegate.

This draft specifies delegation, intent, policy, authorization, and the Authorization Receipt. The reference implementation is in this repository. Ed25519, SHA-256, and canonical JSON are the reference profile. They are not required by the protocol.

The packages `adap`, `adap-policy`, and `adap-receipt` are not currently published to npm in this draft. Clone the repository and build it.
