# Signed objects (versioning and domain separation)

A signed authorization must never gain authority when its verifier is upgraded.

## Profiles

| Profile | Envelope fields | Signature preimage | Constraint interpretation |
| --- | --- | --- | --- |
| Legacy v0.1 | Payload + `signature` only | Canonical JSON of the unsigned payload | `max_amount` is a ceiling on `parameters.amount`. Every other constraint key (including `max_quantity`) requires **exact equality** on that parameter name. |
| Signed-object 0.2 | `adap`, `typ`, `alg`, `kid`, payload fields, `signature` | `ADAP/0.2/<typ>\0` + canonical JSON of `{ adap, typ, alg, kid, payload }` | `ceilings-v1`: every canonical `max_<field>` is a ceiling on `parameters.<field>`. |

The reference implementation identifies 0.2 objects when `adap === "0.2"`, `typ` is set, and `kid` is set. Objects without those fields are verified and interpreted as legacy v0.1.

Do not reinterpret a legacy signature as a 0.2 envelope. Do not apply `ceilings-v1` to an unversioned grant.

## Profile consistency (normative)

A conforming verifier MUST use one signed-object profile for the entire authorization context:

| Context | Required profile rule |
| --- | --- |
| Delegation chain | Every link MUST share the same profile. Mixed legacy / 0.2 chains are rejected. |
| Intent | MUST match the chain profile. |
| Human approval | MUST match the chain+intent profile for both `APPROVE` and `DENY`. |

There is no silent migration from legacy to 0.2. A legacy root followed by a 0.2 child is rejected. A 0.2 context cannot be continued with a legacy approval, and a legacy context cannot be continued with a 0.2 approval.

Constraint narrowing is also profile-aware:

- Legacy: only `max_amount` may be reduced as a ceiling; other keys (including `max_quantity`) remain exact-match and cannot be reinterpreted as ceilings by a child.
- 0.2 / `ceilings-v1`: every canonical `max_<field>` may be reduced, never raised.

## Envelope

| Field | Meaning |
| --- | --- |
| `adap` | Signed-object version. Current reference value: `0.2`. |
| `typ` | `delegation` \| `intent` \| `approval` |
| `alg` | Signature algorithm. Reference profile: `Ed25519`. Unsupported algorithms fail closed. |
| `kid` | Key identifier for the signing key. |
| `payload` | Complete unsigned object body. |
| `signature` | Signature over the domain-separated preimage. |

The reference packages flatten the envelope onto the object for transport (`adap`, `typ`, `alg`, `kid` alongside payload fields). Verification rebuilds the envelope and checks the preimage.

## Domain separation

Preimage bytes:

```
ADAP/<adap>/<typ> || 0x00 || JCS({ adap, typ, alg, kid, payload })
```

where `JCS` is RFC 8785 canonical JSON under the ECMAScript Number profile used by this repository.

A signature for one `typ` or `adap` value must not verify for another. Altering `adap`, `typ`, `alg`, `kid`, or `payload` invalidates the signature.

## Key directory

Verification uses an authority directory keyed by `(identityId, kid)`:

- algorithm, public key, status (`active` \| `revoked` \| `expired`)
- optional validity interval and identity kind

Rules:

- Unknown `kid` fails closed.
- Revoked keys cannot authorize new actions.
- Historical objects remain verifiable with their identified key when the trust policy allows historical verify; the reference path rejects revoked keys for live authorization.
- New objects may be signed with a newly active rotated key.
- Legacy maps of `identityId → publicKey` are adapted to a single active fingerprint `kid` per identity. Newly versioned objects must present a resolvable `kid`.

## Reference

`packages/aap/src/signed-object.ts`, `packages/aap/src/directory.ts`, `packages/aap/src/protocol.ts`, `packages/aap/src/validate.ts`, `packages/aap/src/signed-object.test.ts`.
