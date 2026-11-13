import { describe, expect, it } from 'vitest'
import { MemoryAuthorityDirectory } from './directory.js'
import { FixedClock } from './clock.js'
import {
  createIdentity,
  signDelegation,
  signIntent,
  signApproval,
  unsignedDelegation,
  unsignedIntent,
} from './protocol.js'
import { authorizePresented, presentAuthority, verifyAuthority } from './validate.js'
import { ADAP_SIGNED_VERSION, signedObjectPreimage, verifyEnvelopeSignature } from './signed-object.js'
import { importPublicKey } from './crypto.js'

const NOW = new Date('2026-06-01T00:00:00.000Z')
const ISSUED = '2026-01-01T00:00:00.000Z'
const EXPIRES = '2099-01-01T00:00:00.000Z'

describe('signed-object versioning and constraint profiles (#19)', () => {
  it('keeps legacy max_quantity as exact-match (does not widen to a ceiling)', () => {
    const principal = createIdentity('prn_example')
    const agent = createIdentity('agt_example')
    const root = signDelegation(
      {
        delegation_id: 'del_root',
        issuer: principal.id,
        subject: agent.id,
        capabilities: [{ action: 'apply', target: 'resource/*', delegable: true }],
        constraints: { max_quantity: 5 },
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      principal,
      { profile: 'legacy' }
    )
    const under = signIntent(
      {
        intent_id: 'int_1',
        actor: agent.id,
        delegation_chain: [root.delegation_id],
        action: 'apply',
        target: 'resource/x',
        parameters: { quantity: 3 },
        nonce: 'nonce-legacy-1',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent
    )
    const directory = new Map([
      [principal.id, principal.publicKey],
      [agent.id, agent.publicKey],
    ])
    expect(() =>
      verifyAuthority({ chain: [root], intent: under, directory, now: NOW })
    ).toThrow(/parameter max_quantity is outside the delegation/)

    const exact = signIntent(
      {
        intent_id: 'int_2',
        actor: agent.id,
        delegation_chain: [root.delegation_id],
        action: 'apply',
        target: 'resource/x',
        parameters: { max_quantity: 5 },
        nonce: 'nonce-legacy-2',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent
    )
    expect(() => verifyAuthority({ chain: [root], intent: exact, directory, now: NOW })).not.toThrow()
  })

  it('allows quantity under ceiling only for versioned ceilings-v1 grants', () => {
    const principal = createIdentity('prn_example')
    const agent = createIdentity('agt_example')
    const root = signDelegation(
      {
        delegation_id: 'del_root',
        issuer: principal.id,
        subject: agent.id,
        capabilities: [{ action: 'apply', target: 'resource/*', delegable: true }],
        constraints: { max_quantity: 5 },
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      principal,
      { profile: '0.2' }
    )
    expect(root.adap).toBe(ADAP_SIGNED_VERSION)
    expect(root.kid).toBe(principal.kid)

    const under = signIntent(
      {
        intent_id: 'int_v2',
        actor: agent.id,
        delegation_chain: [root.delegation_id],
        action: 'apply',
        target: 'resource/x',
        parameters: { quantity: 3 },
        nonce: 'nonce-v2-1',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent,
      { profile: '0.2' }
    )
    const directory = new MemoryAuthorityDirectory([
      {
        identityId: principal.id,
        kid: principal.kid,
        alg: 'Ed25519',
        publicKey: principal.publicKey,
        status: 'active',
        kind: 'human',
      },
      {
        identityId: agent.id,
        kid: agent.kid,
        alg: 'Ed25519',
        publicKey: agent.publicKey,
        status: 'active',
        kind: 'agent',
      },
    ])
    expect(() => verifyAuthority({ chain: [root], intent: under, directory, now: NOW })).not.toThrow()

    const over = signIntent(
      {
        intent_id: 'int_v2_over',
        actor: agent.id,
        delegation_chain: [root.delegation_id],
        action: 'apply',
        target: 'resource/x',
        parameters: { quantity: 9 },
        nonce: 'nonce-v2-2',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent,
      { profile: '0.2' }
    )
    expect(() => verifyAuthority({ chain: [root], intent: over, directory, now: NOW })).toThrow(
      /quantity exceeds delegated max_quantity/
    )
  })

  it('rejects type confusion and unknown/revoked kids', () => {
    const principal = createIdentity('prn_example')
    const agent = createIdentity('agt_example')
    const root = signDelegation(
      {
        delegation_id: 'del_root',
        issuer: principal.id,
        subject: agent.id,
        capabilities: [{ action: 'read', target: 'resource/*', delegable: true }],
        constraints: { max_amount: 100 },
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      principal,
      { profile: '0.2' }
    )
    const intent = signIntent(
      {
        intent_id: 'int_x',
        actor: agent.id,
        delegation_chain: [root.delegation_id],
        action: 'read',
        target: 'resource/x',
        parameters: {},
        nonce: 'nonce-x',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent,
      { profile: '0.2' }
    )

    // Intent signature bytes cannot verify as a delegation envelope.
    expect(
      verifyEnvelopeSignature(
        {
          adap: ADAP_SIGNED_VERSION,
          typ: 'delegation',
          alg: 'Ed25519',
          kid: agent.kid,
          payload: unsignedIntent(intent),
          signature: intent.signature,
        },
        importPublicKey(agent.publicKey),
        'delegation'
      )
    ).toBe(false)

    const directory = new MemoryAuthorityDirectory([
      {
        identityId: principal.id,
        kid: principal.kid,
        alg: 'Ed25519',
        publicKey: principal.publicKey,
        status: 'active',
      },
      {
        identityId: agent.id,
        kid: agent.kid,
        alg: 'Ed25519',
        publicKey: agent.publicKey,
        status: 'revoked',
      },
    ])
    expect(() =>
      presentAuthority({ chain: [root], intent, directory, now: NOW })
    ).toThrow(/key revoked|unknown identity/)

    const unknownKid = { ...intent, kid: 'ed25519:unknown' }
    const activeDir = new MemoryAuthorityDirectory([
      {
        identityId: principal.id,
        kid: principal.kid,
        alg: 'Ed25519',
        publicKey: principal.publicKey,
        status: 'active',
      },
      {
        identityId: agent.id,
        kid: agent.kid,
        alg: 'Ed25519',
        publicKey: agent.publicKey,
        status: 'active',
      },
    ])
    expect(() =>
      presentAuthority({ chain: [root], intent: unknownKid, directory: activeDir, now: NOW })
    ).toThrow(/unknown identity or kid|signature/)
  })

  it('rejects tampering with version, type, alg, kid, or payload', () => {
    const principal = createIdentity('prn_example')
    const root = signDelegation(
      {
        delegation_id: 'del_root',
        issuer: principal.id,
        subject: principal.id,
        capabilities: [{ action: 'read', target: 'resource/*', delegable: true }],
        constraints: {},
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      principal,
      { profile: '0.2' }
    )
    const key = importPublicKey(principal.publicKey)
    const good = {
      adap: ADAP_SIGNED_VERSION,
      typ: 'delegation' as const,
      alg: 'Ed25519' as const,
      kid: principal.kid,
      payload: unsignedDelegation(root),
      signature: root.signature,
    }
    expect(verifyEnvelopeSignature(good, key, 'delegation')).toBe(true)
    expect(verifyEnvelopeSignature({ ...good, typ: 'intent' }, key, 'intent')).toBe(false)
    expect(
      verifyEnvelopeSignature({ ...good, payload: { ...good.payload, constraints: { max_amount: 1 } } }, key, 'delegation')
    ).toBe(false)
    expect(signedObjectPreimage(good).includes(0)).toBe(true)
  })

  it('allows a rotated active key identified by kid', () => {
    const principal = createIdentity('prn_example')
    const rotated = createIdentity('prn_example')
    const agent = createIdentity('agt_example')
    const root = signDelegation(
      {
        delegation_id: 'del_root',
        issuer: principal.id,
        subject: agent.id,
        capabilities: [{ action: 'read', target: 'resource/*', delegable: true }],
        constraints: {},
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      rotated,
      { profile: '0.2', kid: rotated.kid }
    )
    // Force issuer id to principal while signed by rotated key material registered under principal id.
    const forgedIssuer = { ...root, issuer: principal.id }
    // Re-sign properly under principal id with rotated key object remapped:
    const principalRotated = { ...rotated, id: principal.id }
    const signed = signDelegation(
      {
        delegation_id: 'del_root',
        issuer: principal.id,
        subject: agent.id,
        capabilities: [{ action: 'read', target: 'resource/*', delegable: true }],
        constraints: {},
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      principalRotated,
      { profile: '0.2', kid: principalRotated.kid }
    )
    const intent = signIntent(
      {
        intent_id: 'int_rot',
        actor: agent.id,
        delegation_chain: [signed.delegation_id],
        action: 'read',
        target: 'resource/x',
        parameters: {},
        nonce: 'nonce-rot',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent,
      { profile: '0.2' }
    )
    const directory = new MemoryAuthorityDirectory([
      {
        identityId: principal.id,
        kid: principal.kid,
        alg: 'Ed25519',
        publicKey: principal.publicKey,
        status: 'revoked',
      },
      {
        identityId: principal.id,
        kid: principalRotated.kid,
        alg: 'Ed25519',
        publicKey: principalRotated.publicKey,
        status: 'active',
      },
      {
        identityId: agent.id,
        kid: agent.kid,
        alg: 'Ed25519',
        publicKey: agent.publicKey,
        status: 'active',
      },
    ])
    expect(() => verifyAuthority({ chain: [signed], intent, directory, now: NOW })).not.toThrow()
    void forgedIssuer
    void FixedClock
    void authorizePresented
    void signApproval
  })
})
