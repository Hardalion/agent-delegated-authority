import { describe, expect, it, vi } from 'vitest'
import {
  createIdentity, FixedClock, ImmutablePolicyResolver, NonceLedger,
  signDelegation, signIntent,
} from 'adap'
import { executeAuthorized } from './executor.js'
import { createRootAuthority } from './root-authority.js'
import { STAGING_ALLOW_POLICY, STAGING_ALLOW_URI } from './staging-policies.js'

const now = new Date('2026-11-16T08:00:00.000Z')
const issued_at = now.toISOString()
const expires_at = new Date(now.getTime() + 60_000).toISOString()

describe('gateway root authority conformance', () => {
  it.each([
    ['principal', 'agent', 'resource/example', 'ALLOW'],
    ['agent', 'agent', 'resource/example', 'BLOCK'],
    ['agent', 'other-agent', 'resource/example', 'BLOCK'],
    ['principal', 'agent', 'other/example', 'BLOCK'],
    ['principal', 'agent', 'resource/nested/example', 'BLOCK'],
  ])('%s grants to %s on %s => %s', async (issuerId, subjectId, target, decision) => {
    const identities = new Map(['principal', 'agent', 'other-agent'].map((id) => [id, createIdentity(id)]))
    const issuer = identities.get(issuerId)!
    const agent = identities.get(subjectId)!
    const directory = new Map([...identities].map(([id, identity]) => [id, identity.publicKey]))
    const rootAuthority = createRootAuthority([
      { issuerId: 'principal', action: 'apply', target: 'resource/*' },
    ], directory)
    const root = signDelegation({
      delegation_id: 'root', issuer: issuer.id, subject: agent.id,
      capabilities: [{ action: 'apply', target, delegable: false }],
      constraints: { max_amount: 1000 }, issued_at, expires_at,
    }, issuer)
    const intent = signIntent({
      intent_id: 'intent', actor: agent.id, delegation_chain: [root.delegation_id],
      action: 'apply', target, parameters: { amount: 1000 }, nonce: 'root-authority-test',
      issued_at, expires_at,
    }, agent)
    const policyResolver = new ImmutablePolicyResolver()
    policyResolver.register(STAGING_ALLOW_POLICY, STAGING_ALLOW_URI)
    const resolveHandle = vi.fn(async () => 'test-handle')
    const execute = vi.fn(async () => ({ status: 'completed' as const, correlationId: 'test', body: {} }))
    const result = await executeAuthorized({
      chain: [root], intent, directory, rootAuthority,
      policy: STAGING_ALLOW_POLICY, policyUri: STAGING_ALLOW_URI, policyResolver,
      ledger: new NonceLedger(), signer: createIdentity('runtime'), clock: new FixedClock(now),
      broker: { resolveHandle, execute },
    })
    expect(result.decision).toBe(decision)
    expect(result.executed).toBe(decision === 'ALLOW')
    expect(execute).toHaveBeenCalledTimes(decision === 'ALLOW' ? 1 : 0)
    expect(resolveHandle).toHaveBeenCalledTimes(decision === 'ALLOW' ? 1 : 0)
    if (decision === 'BLOCK') expect(result.ruleId).toBe('root_not_authorized')
  })

  it('requires every capability to be covered, including unused capabilities', () => {
    const authority = createRootAuthority([
      { issuerId: 'principal', action: 'apply', target: 'resource/*' },
    ], new Map([['principal', 'key']]))
    expect(authority.mayIssueRoot({
      issuerId: 'principal', subjectId: 'agent',
      capabilities: [
        { action: 'apply', target: 'resource/*' },
        { action: 'apply', target: 'other/*' },
      ],
    })).toBe(false)
  })

  it.each([
    { configuration: [] },
    { configuration: [{ issuerId: 'unknown', action: 'apply', target: 'resource/*' }] },
    { configuration: [{ issuerId: 'principal', action: 'apply', target: 'resource/../other' }] },
  ])('rejects invalid operator configuration %#', ({ configuration }) => {
    expect(() => createRootAuthority(configuration, new Map([['principal', 'key']]))).toThrow()
  })
})
