import { canonicalJson, importPublicKey, sha256, verifyObject } from './crypto.js'
import { AuthorityError } from './errors.js'
import { assertAmountWithinLimit, assertCanonicalAmount, isMaxAmountKey } from './amount.js'
import { hasOwn, ownEntries } from './safe-object.js'
import {
  assertCanonicalCurrency,
  assertCanonicalTarget,
  assertValidIdentity,
  normalizeConstraints,
  validateHumanApproval,
  validateSignedDelegation,
  validateSignedIntent,
} from './runtime-validate.js'
import type {
  Capability,
  Constraints,
  HumanApproval,
  IntentPayload,
  SignedDelegation,
  SignedIntent,
} from './protocol.js'
import { unsignedDelegation, unsignedIntent } from './protocol.js'
import { cloneSignedDelegation, cloneSignedIntent, deepFreeze } from './snapshot.js'

export function assertNotExpired(issuedAt: string, expiresAt: string, now = new Date()): void {
  const issued = Date.parse(issuedAt)
  const expires = Date.parse(expiresAt)
  const current = now.getTime()
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued) {
    throw new AuthorityError('expired', 'invalid delegation/intent lifetime')
  }
  if (current < issued || current >= expires) {
    throw new AuthorityError('expired', 'expired or not-yet-valid authority')
  }
}

function targetCovered(granted: string | undefined, requested: string | undefined): boolean {
  if (granted === undefined || requested === undefined) return false
  if (granted === requested) return true
  if (granted.endsWith('/*')) {
    const prefix = granted.slice(0, -1)
    const rest = requested.slice(prefix.length)
    return requested.startsWith(prefix) && rest.length > 0 && !rest.includes('/')
  }
  return false
}

function coveringCapability(parent: readonly Capability[], child: Capability): Capability | undefined {
  return parent.find(
    (candidate) => candidate.action === child.action && targetCovered(candidate.target, child.target)
  )
}

export function validateDelegationNarrowing(parent: SignedDelegation, child: SignedDelegation): void {
  if (child.issuer !== parent.subject) {
    throw new AuthorityError('narrowing', 'delegator is not authorized by parent delegation', true)
  }
  if (child.parent_delegation_id !== parent.delegation_id) {
    throw new AuthorityError('narrowing', 'child parent_delegation_id does not match parent', true)
  }
  if (Date.parse(child.issued_at) < Date.parse(parent.issued_at)) {
    throw new AuthorityError('narrowing', 'child starts before parent', true)
  }
  if (Date.parse(child.expires_at) > Date.parse(parent.expires_at)) {
    throw new AuthorityError('narrowing', 'child expires after parent', true)
  }

  for (const capability of child.capabilities) {
    const covered = coveringCapability(parent.capabilities, capability)
    if (!covered) {
      throw new AuthorityError('narrowing', `capability not covered by parent: ${capability.action}`, true)
    }
    if (covered.delegable === false) {
      throw new AuthorityError('narrowing', `capability cannot be re-delegated: ${capability.action}`, true)
    }
  }

  assertConstraintsNarrow(
    normalizeConstraints(parent.constraints, 'parent.constraints'),
    normalizeConstraints(child.constraints, 'child.constraints')
  )
}

function assertConstraintsNarrow(parent: Constraints, child: Constraints): void {
  for (const [key, parentVal] of ownEntries(parent as Record<string, unknown>)) {
    if (!hasOwn(child, key)) {
      throw new AuthorityError('narrowing', `child drops constraint ${key}`, true)
    }
    const childVal = (child as Record<string, unknown>)[key]
    if (typeof parentVal === 'number' && typeof childVal === 'number' && isMaxAmountKey(key)) {
      const parentAmount = assertCanonicalAmount(parentVal, `parent.${key}`)
      const childAmount = assertCanonicalAmount(childVal, `child.${key}`)
      if (childAmount > parentAmount) {
        throw new AuthorityError('narrowing', `child raises ${key}`, true)
      }
      continue
    }
    if (parentVal !== childVal) {
      throw new AuthorityError('narrowing', `child alters constraint ${key}`, true)
    }
  }
}

export function assertIntentWithinDelegation(intent: IntentPayload, delegation: SignedDelegation): void {
  assertValidIdentity(intent.actor, 'intent.actor')
  assertCanonicalTarget(intent.target)
  if (intent.actor !== delegation.subject) {
    throw new AuthorityError('actor', 'intent actor does not match terminal delegate', true)
  }
  const chainIds = intent.delegation_chain
  if (chainIds[chainIds.length - 1] !== delegation.delegation_id) {
    throw new AuthorityError('chain', 'intent is not bound to the terminal delegation', true)
  }
  const covered = coveringCapability(delegation.capabilities, {
    action: intent.action,
    target: intent.target,
  })
  if (!covered) {
    throw new AuthorityError('capability', `capability not granted: ${intent.action}`, true)
  }
  const constraints = normalizeConstraints(delegation.constraints, 'delegation.constraints')
  assertParametersWithin(intent.action, intent.parameters, constraints)
}

function assertParametersWithin(
  action: string,
  parameters: Readonly<Record<string, unknown>>,
  constraints: Constraints
): void {
  for (const [key, bound] of ownEntries(constraints as Record<string, unknown>)) {
    if (key === 'max_amount') {
      const amount = hasOwn(parameters, 'amount') ? parameters.amount : undefined
      if (amount === undefined) {
        if (action === 'read' || action === 'search') continue
        throw new AuthorityError('constraint', 'amount is required', true)
      }
      assertAmountWithinLimit(amount, bound, 'parameters.amount')
      continue
    }
    if (key === 'currency') {
      const presented = parameters[key]
      const expected = assertCanonicalCurrency(bound, 'constraints.currency')
      if (presented === undefined) {
        throw new AuthorityError('constraint', 'currency is required', true)
      }
      if (assertCanonicalCurrency(presented, 'parameters.currency') !== expected) {
        throw new AuthorityError('constraint', 'parameter currency is outside the delegation', true)
      }
      continue
    }
    if (!hasOwn(parameters, key) || parameters[key] !== bound) {
      throw new AuthorityError('constraint', `parameter ${key} is outside the delegation`, true)
    }
  }
}

export interface VerifiedAuthority {
  readonly chain: readonly SignedDelegation[]
  readonly intent: SignedIntent
  readonly intentPayload: IntentPayload
}

function assertDelegationShape(chain: readonly SignedDelegation[], intent: SignedIntent): void {
  if (chain.length === 0) throw new AuthorityError('chain', 'delegation chain is empty')
  if (intent.delegation_chain.length !== chain.length) {
    throw new AuthorityError('chain', 'intent delegation_chain length does not match')
  }
  for (let index = 0; index < chain.length; index += 1) {
    const delegation = chain[index]
    if (!delegation) throw new AuthorityError('chain', 'missing delegation')
    if (intent.delegation_chain[index] !== delegation.delegation_id) {
      throw new AuthorityError('chain', 'intent delegation_chain does not match presented delegations')
    }
  }
}

function assertCanonicalForm(value: unknown, path: string): void {
  try {
    canonicalJson(value)
  } catch {
    throw new AuthorityError('canonicalization', `${path} could not be canonicalized`, false)
  }
}

function verifySignatures(
  chain: readonly SignedDelegation[],
  intent: SignedIntent,
  directory: ReadonlyMap<string, string>
): void {
  for (const delegation of chain) {
    const issuerKey = directory.get(delegation.issuer)
    if (
      !issuerKey ||
      !verifyObject(unsignedDelegation(delegation), delegation.signature, importPublicKey(issuerKey))
    ) {
      throw new AuthorityError('signature_invalid', `delegation signature invalid: ${delegation.delegation_id}`)
    }
  }
  const actorKey = directory.get(intent.actor)
  if (!actorKey || !verifyObject(unsignedIntent(intent), intent.signature, importPublicKey(actorKey))) {
    throw new AuthorityError('signature_invalid', 'intent signature invalid')
  }
}

/**
 * Clone the presented chain and intent, then verify signatures.
 * Failures here are unauthenticated: the nonce must not be consumed.
 * Semantic amount and delegation checks are `authorizePresented`.
 */
export function presentAuthority(input: {
  readonly chain: readonly SignedDelegation[]
  readonly intent: SignedIntent
  readonly directory: ReadonlyMap<string, string>
}): { readonly chain: SignedDelegation[]; readonly intent: SignedIntent } {
  if (!Array.isArray(input.chain)) {
    throw new AuthorityError('schema', 'delegation chain must be an array', false)
  }
  const chain = input.chain.map((delegation, index) =>
    cloneSignedDelegation(delegation, `chain[${index}]`)
  )
  const intent = cloneSignedIntent(input.intent)
  assertDelegationShape(chain, intent)
  chain.forEach((delegation, index) => {
    assertCanonicalForm(unsignedDelegation(delegation), `chain[${index}]`)
  })
  assertCanonicalForm(unsignedIntent(intent), 'intent')
  verifySignatures(chain, intent, input.directory)
  return { chain, intent }
}

/** Semantic checks for an already-authenticated presentation. Failures are authenticated. */
export function authorizePresented(input: {
  readonly chain: readonly SignedDelegation[]
  readonly intent: SignedIntent
  readonly now: Date
}): VerifiedAuthority {
  const { chain, intent, now } = input
  try {
    const validatedIntent = validateSignedIntent(intent)
    const validatedChain = chain.map((delegation, index) =>
      validateSignedDelegation(delegation, `chain[${index}]`)
    )
    if (sha256(unsignedIntent(validatedIntent)) !== sha256(unsignedIntent(intent))) {
      throw new AuthorityError('intent', 'normalized intent diverges from the signed payload', true)
    }
    if (sha256(validatedChain.map(unsignedDelegation)) !== sha256(chain.map(unsignedDelegation))) {
      throw new AuthorityError('chain', 'normalized delegation diverges from the signed payload', true)
    }
    verifyAuthenticated(validatedChain, validatedIntent, now)
    deepFreeze(validatedIntent)
    deepFreeze(validatedChain)
    return {
      chain: validatedChain,
      intent: validatedIntent,
      intentPayload: unsignedIntent(validatedIntent),
    }
  } catch (error) {
    if (error instanceof AuthorityError && !error.authenticated) {
      throw new AuthorityError(error.code, error.message, true)
    }
    throw error
  }
}

export function verifyAuthority(input: {
  readonly chain: readonly SignedDelegation[]
  readonly intent: SignedIntent
  readonly directory: ReadonlyMap<string, string>
  readonly now: Date
}): VerifiedAuthority {
  const presented = presentAuthority(input)
  return authorizePresented({ chain: presented.chain, intent: presented.intent, now: input.now })
}

function verifyAuthenticated(chain: readonly SignedDelegation[], intent: SignedIntent, now: Date): void {
  for (let index = 0; index < chain.length; index += 1) {
    const delegation = chain[index]
    if (!delegation) throw new AuthorityError('chain', 'missing delegation', true)
    assertNotExpired(delegation.issued_at, delegation.expires_at, now)
    if (index === 0) {
      if (delegation.parent_delegation_id) {
        throw new AuthorityError('chain', 'root delegation must not name a parent', true)
      }
    } else {
      const parent = chain[index - 1]
      if (!parent) throw new AuthorityError('chain', 'missing parent delegation', true)
      validateDelegationNarrowing(parent, delegation)
    }
  }

  assertNotExpired(intent.issued_at, intent.expires_at, now)
  const terminal = chain[chain.length - 1]
  if (!terminal) throw new AuthorityError('chain', 'missing terminal delegation', true)
  assertIntentWithinDelegation(intent, terminal)
}

export function verifyHumanApproval(input: {
  readonly approval: HumanApproval
  readonly intentHash: string
  readonly principalId: string
  readonly agentId: string
  readonly delegationChainHash: string
  readonly policyContentHash: string
  readonly matchedRuleId?: string
  readonly intent: IntentPayload
  readonly directory: ReadonlyMap<string, string>
  readonly now: Date
  /** When set, duplicate approval of the same binding is rejected. */
  readonly seenApprovalKeys?: Set<string>
}): void {
  const approval = validateHumanApproval(input.approval)
  const {
    intentHash,
    principalId,
    agentId,
    delegationChainHash,
    policyContentHash,
    matchedRuleId,
    intent,
    directory,
    now,
    seenApprovalKeys,
  } = input

  if (approval.decision !== 'APPROVE') {
    throw new AuthorityError('approval', 'approval decision is not APPROVE', true)
  }
  if (approval.approver_id !== principalId) {
    throw new AuthorityError('approval', 'approver is not the delegating principal', true)
  }
  if (approval.intent_hash !== intentHash) {
    throw new AuthorityError('approval', 'approval is not bound to this intent', true)
  }
  if (approval.agent_id !== agentId) {
    throw new AuthorityError('approval', 'approval is not bound to this agent', true)
  }
  if (approval.delegation_chain_hash !== delegationChainHash) {
    throw new AuthorityError('approval', 'approval is not bound to this delegation chain', true)
  }
  if (approval.policy_content_hash !== policyContentHash) {
    throw new AuthorityError('approval', 'approval is not bound to this policy', true)
  }
  if (
    matchedRuleId != null &&
    approval.matched_rule_id != null &&
    approval.matched_rule_id !== matchedRuleId
  ) {
    throw new AuthorityError('approval', 'approval is not bound to this policy rule', true)
  }

  const approvalKey = [
    approval.intent_hash,
    approval.approver_id,
    approval.agent_id,
    approval.delegation_chain_hash,
    approval.policy_content_hash,
    approval.approved_at,
    approval.signature,
  ].join('|')
  if (seenApprovalKeys?.has(approvalKey)) {
    throw new AuthorityError('approval', 'duplicate approval rejected', true)
  }

  const approverKey = directory.get(approval.approver_id)
  const { signature, ...payload } = approval
  if (!approverKey || !verifyObject(payload, signature, importPublicKey(approverKey))) {
    throw new AuthorityError('approval', 'approval signature invalid', true)
  }
  const approvedAt = Date.parse(approval.approved_at)
  const issued = Date.parse(intent.issued_at)
  const expires = Date.parse(intent.expires_at)
  if (!Number.isFinite(approvedAt) || approvedAt > now.getTime() || approvedAt < issued || approvedAt >= expires) {
    throw new AuthorityError('approval', 'approval is outside the intent lifetime', true)
  }
  // Record only after the signature and lifetime checks. A forged approval must
  // not reserve the slot of a later valid approval with the same binding fields.
  seenApprovalKeys?.add(approvalKey)
}
