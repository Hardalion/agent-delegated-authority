# ADAP 0.2.0

Reference packages for the Agent Delegated Authority Protocol. Apache-2.0. This is the first npm release. It is not a hosted authority service, not a certification, and not a claim that an agent cannot reach an API by some other path.

Packages, published together:

| Package | Role |
| --- | --- |
| `adap-receipt` | Offline Authorization Receipt checks |
| `adap-policy` | Deterministic policy evaluation |
| `adap` | Reference authority path: delegation, signed intent, decision, receipt |
| `adap-store-postgres` | Reference Postgres nonce, pending, and policy adapters |
| `adap-gateway` | Reference process that keeps the rail credential out of the agent |

Node 22 or newer.

## What changed since v0.1.0

These are breaking relative to the `v0.1.0` git tag.

- A human approval binds `agent_id`, `delegation_chain_hash`, and `policy_content_hash`. An approval for a different intent, agent, chain, or policy document does not release the action.
- Signed objects may use `adap: 0.2` envelopes. A chain that mixes legacy objects and `0.2` objects is rejected.
- Canonical JSON follows RFC 8785. Hashes computed over integer-like keys in the old order must be re-issued.
- New policy documents accept `ALLOW`, `BLOCK`, and `REQUIRE_HUMAN`. `DEFER` and `SIMULATE` are rejected by the schema.
- The reference gateway does not default `unsafeDevAllowUnconfiguredChecks` to true. A missing audience, approver check, or revocation check does not fall open.
- `receiptId` is unique per emission. Two refusals of the same intent no longer share an id.

## Controls in this release

- The authority path returns `ALLOW`, `REQUIRE_HUMAN`, or `BLOCK`. `BLOCK` and an unresolved `REQUIRE_HUMAN` do not call the executor.
- A child grant cannot raise a parent ceiling. A child may lower `cumulative_<field>`. With `closed: true`, the parameter that ceiling bounds is the one the intent may carry. An extra parameter is refused (#67).
- A missing policy path does not match `in` or `.contains()` (#69).
- On a pin-checked call, the receipt binds `execution.toolDefinitionHash`. A verifier who holds the tool definition recomputes that hash. A definition that changed after the signature does not match.
- Receipts verify offline with the issuer public key. Demo placeholder signatures do not verify as evidence.

The fail-closed gateway default was reported by Ahmed Shacker (@AS2812) and fixed in #47.

## What this release does not prove

- The packages do not hold the operator's rail credential and do not configure the operator's network. If the agent process already has that credential, it can call the API without this path. `THREAT_MODEL.md` states that deployment boundary.
- `executed: true` means the reference executor callback returned. It is not an observation that an external system committed.
- `max_amount` is a per-intent ceiling. A running total is the optional `cumulative_<field>` constraint plus a spend ledger. Without a ledger, a set cumulative ceiling does not execute.

## Known limitations

Ship these as open. Do not treat them as fixed in 0.2.0.

- **#65, targeted for v0.2.1.** If the reference gateway throws before the downstream call, the signed receipt can still say `ALLOW` with `outcome: unknown`. The three sites are execution-state persistence, a canonicalization mismatch, and broker rejection. The same lowercase action rule can refuse a camelCase tool name such as `getCustomer`.
- **#64.** A missing field makes `!=` false. That matches `spec/deterministic-evaluation.md`. A `BLOCK` rule written `args.currency != 'EUR'` does not fire when `currency` is absent.
- **#48 / #52.** An instruction that stays inside the grant is allowed. The receipt does not record which input produced the intent. The fixture is `examples/attacks/07-in-grant-injection.txt`.

## Verify

```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm build
```

Threat model: `THREAT_MODEL.md`. Vulnerability reporting: `SECURITY.md`. Protocol: `spec/`.
