import { describe, expect, it, vi } from 'vitest'
import {
  createIdentity, FixedClock, ImmutablePolicyResolver, NonceLedger,
  PendingAuthorizationStore, signDelegation, signIntent,
} from 'adap'
import { createPolicySelector } from './policy-selection.js'
import { executeAuthorized } from './executor.js'
import {
  STAGING_ALLOW_POLICY, STAGING_ALLOW_URI, STAGING_HUMAN_POLICY, STAGING_HUMAN_URI,
} from './staging-policies.js'

function registry() {
  const resolver = new ImmutablePolicyResolver()
  resolver.register(STAGING_ALLOW_POLICY, STAGING_ALLOW_URI)
  resolver.register(STAGING_HUMAN_POLICY, STAGING_HUMAN_URI)
  return resolver
}

const bindings = [
  { principalId: 'principal', action: 'apply', target: 'resource/human', policyUri: STAGING_HUMAN_URI },
  { principalId: 'principal', action: 'apply', target: 'resource/example', policyUri: STAGING_ALLOW_URI },
]

describe('gateway governing policy', () => {
  it('rejects a weaker registered policy on the first request', () => {
    const select = createPolicySelector(bindings, registry())
    const request = { chain: [{ issuer: 'principal' }], intent: { action: 'apply', target: 'resource/human' } }
    expect(() => select(request, STAGING_ALLOW_URI)).toThrow(/differs/)
    expect(select(request, undefined)).toBe(STAGING_HUMAN_URI)
    expect(select(request, STAGING_HUMAN_URI)).toBe(STAGING_HUMAN_URI)
    expect(() => select(request, [STAGING_HUMAN_URI, STAGING_ALLOW_URI])).toThrow()
  })

  it.each([
    ['other', 'apply', 'resource/human'],
    ['principal', 'delete', 'resource/human'],
    ['principal', 'apply', 'resource/unknown'],
  ])('rejects an unbound tuple %s %s %s', (issuer, action, target) => {
    const select = createPolicySelector(bindings, registry())
    expect(() => select({ chain: [{ issuer }], intent: { action, target } }, undefined)).toThrow(/no governing policy/)
  })

  it('rejects ambiguous and unregistered operator bindings at startup', () => {
    expect(() => createPolicySelector([...bindings, bindings[0]], registry())).toThrow(/duplicate/)
    expect(() => createPolicySelector([{ ...bindings[0], policyUri: 'unknown@1' }], registry())).toThrow(/absent/)
    expect(() => createPolicySelector([], registry())).toThrow()
  })

  it.each([
    ['resource/human', false, 'REQUIRE_HUMAN'],
    ['resource/example', false, 'ALLOW'],
    ['resource/human', true, 'BLOCK'],
  ] as const)('authorizes signed target %s (tampered=%s) as %s', async (target, tampered, decision) => {
    const principal = createIdentity('principal')
    const agent = createIdentity('agent')
    const now = new Date('2026-11-16T08:00:00.000Z')
    const issued_at = now.toISOString()
    const expires_at = new Date(now.getTime() + 60_000).toISOString()
    const root = signDelegation({
      delegation_id: 'root', issuer: principal.id, subject: agent.id,
      capabilities: [{ action: 'apply', target: 'resource/*', delegable: false }],
      constraints: { max_amount: 100 }, issued_at, expires_at,
    }, principal)
    const signed = signIntent({
      intent_id: 'intent', actor: agent.id, delegation_chain: [root.delegation_id],
      action: 'apply', target, parameters: { amount: 10 }, nonce: 'policy-selection-test',
      issued_at, expires_at,
    }, agent)
    const intent = tampered ? { ...signed, target: 'resource/example' } : signed
    const request = { chain: [root], intent }
    const policyResolver = registry()
    const select = createPolicySelector(bindings, policyResolver)
    const policyUri = select(request, undefined)
    const execute = vi.fn(async () => ({ status: 'completed' as const, correlationId: 'test', body: {} }))
    const result = await executeAuthorized({
      unsafeDevAllowUnconfiguredChecks: true,
      ...request, directory: new Map([[principal.id, principal.publicKey], [agent.id, agent.publicKey]]),
      policy: policyResolver.resolveByUri(policyUri)!.policy, policyUri, policyResolver,
      ledger: new NonceLedger(), pendingStore: new PendingAuthorizationStore(),
      signer: createIdentity('runtime'), clock: new FixedClock(now),
      broker: { resolveHandle: async () => 'test-handle', execute },
    })
    expect(result.decision).toBe(decision)
    expect(execute).toHaveBeenCalledTimes(decision === 'ALLOW' ? 1 : 0)
  })
})
