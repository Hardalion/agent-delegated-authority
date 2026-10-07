import { readFileSync } from 'node:fs'
import { verifyAuthorizationReceipt, verifyReceiptSignature, type AuthorizationReceiptV1 } from 'adap-receipt'
import { importPublicKey, sha256, verifyObject } from './crypto.js'
import { BASIC_AGENT_AUTHORITY } from './example-policy.js'
import { AuthorityError } from './errors.js'
import { verifyProtocolReceipt } from './path.js'
import { unsignedDelegation, unsignedIntent, type SignedDelegation, type SignedIntent } from './protocol.js'
import { validateDelegationNarrowing } from './validate.js'

interface ProofKeys {
  readonly principal: string
  readonly agentA: string
  readonly agentB: string
  readonly issuer: string
}

/**
 * Checks the files a third party can verify with no hosted service.
 * `examples/receipt.json` is a signed receipt, not an authority chain.
 * `examples/proof/` is one reference run of the refused child grant and the refused instruction.
 * The receipt binds the policy pin, the rule id, and the canonical hash of the policy document.
 */
export function verifyPublishedProof(): string {
  const examples = new URL('../../../examples/', import.meta.url)
  const sampleKey = readFileSync(new URL('issuer-public-key.txt', examples), 'utf8')
  const sample = readJson(new URL('receipt.json', examples)) as AuthorizationReceiptV1
  const sampleCheck = verifyAuthorizationReceipt(sample)
  if (!sampleCheck.valid) throw new Error(sampleCheck.errors.join('; '))
  if (!verifyReceiptSignature(sample, sampleKey)) throw new Error('sample receipt signature')

  const proof = new URL('proof/', examples)
  const keys = readJson(new URL('keys.json', proof)) as ProofKeys
  const policy = readJson(new URL('policy.json', proof)) as { policyName?: string }
  const parent = readJson(new URL('delegation-root.json', proof)) as SignedDelegation
  const child = readJson(new URL('delegation-raised.json', proof)) as SignedDelegation
  const raisedIntent = readJson(new URL('intent-raised.json', proof)) as SignedIntent
  const raisedReceipt = readJson(new URL('receipt-raised.json', proof)) as AuthorizationReceiptV1
  const injectionIntent = readJson(new URL('intent-injection.json', proof)) as SignedIntent
  const injectionReceipt = readJson(new URL('receipt-injection.json', proof)) as AuthorizationReceiptV1

  assertDelegation(parent, keys.principal)
  assertDelegation(child, keys.agentA)
  assertIntent(raisedIntent, keys.agentB)
  assertIntent(injectionIntent, keys.agentA)
  assertRaisedChildRejected(parent, child)
  assertReceipt(raisedReceipt, keys.issuer, [parent, child], 'narrowing')
  assertReceipt(injectionReceipt, keys.issuer, [parent], 'constraint')

  if (policy.policyName !== 'book-flight') throw new Error('policy name')
  if (raisedReceipt.policy.policyUri !== 'book-flight@1.0.0') throw new Error('policy pin')
  if (sample.policy.contentHash !== sha256(BASIC_AGENT_AUTHORITY)) {
    throw new Error('sample receipt policy hash')
  }
  const policyHash = sha256(policy)
  if (raisedReceipt.policy.contentHash !== policyHash || injectionReceipt.policy.contentHash !== policyHash) {
    throw new Error('published receipt policy hash')
  }
  if (raisedReceipt.execution?.intentHash !== sha256(unsignedIntent(raisedIntent))) {
    throw new Error('raised intent hash')
  }
  if (injectionReceipt.execution?.intentHash !== sha256(unsignedIntent(injectionIntent))) {
    throw new Error('injection intent hash')
  }
  if (JSON.stringify(injectionReceipt).includes('privateKey')) throw new Error('private key in published proof')

  return 'published proof verified offline'
}

function assertRaisedChildRejected(parent: SignedDelegation, child: SignedDelegation): void {
  try {
    validateDelegationNarrowing(parent, child)
  } catch (error) {
    if (error instanceof AuthorityError && error.message === 'child raises max_amount') return
    throw error
  }
  throw new Error('raised child was accepted')
}

function assertDelegation(delegation: SignedDelegation, spki: string): void {
  const ok = verifyObject(unsignedDelegation(delegation), delegation.signature, importPublicKey(spki))
  if (!ok) throw new Error(`delegation signature ${delegation.delegation_id}`)
}

function assertIntent(intent: SignedIntent, spki: string): void {
  const ok = verifyObject(unsignedIntent(intent), intent.signature, importPublicKey(spki))
  if (!ok) throw new Error(`intent signature ${intent.intent_id}`)
}

function assertReceipt(
  receipt: AuthorizationReceiptV1,
  issuer: string,
  chain: readonly SignedDelegation[],
  ruleId: string
): void {
  const checked = verifyProtocolReceipt(receipt, importPublicKey(issuer))
  if (!checked.valid) throw new Error(checked.errors.join('; '))
  if (receipt.decision.action !== 'BLOCK') throw new Error('expected BLOCK')
  if (receipt.policy.ruleId !== ruleId) throw new Error(`expected rule ${ruleId}`)
  if (receipt.execution?.executed !== false) throw new Error('expected no reported execution')
  const links = receipt.authority?.chain ?? []
  if (links.length !== chain.length) throw new Error('delegation chain length')
  for (let index = 0; index < chain.length; index += 1) {
    const delegation = chain[index]
    const link = links[index]
    if (!delegation || !link) throw new Error('missing delegation link')
    if (link.delegationId !== delegation.delegation_id) throw new Error('delegation id')
    if (link.hash !== sha256(unsignedDelegation(delegation))) throw new Error('delegation hash')
  }
}

function readJson(url: URL): unknown {
  return JSON.parse(readFileSync(url, 'utf8')) as unknown
}
