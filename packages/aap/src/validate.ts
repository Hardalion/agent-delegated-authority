import { canonicalJson, importPublicKey, sha256, verifyObject } from './crypto.js'
import { AuthorityError } from './errors.js'
import { assertCanonicalAmount, assertWithinCeiling, ceilingField, isMaxAmountKey } from './amount.js'
import {
  assertUsableDirectoryKey,
  resolveAuthorityDirectory,
  type AuthorityDirectory,
} from './directory.js'
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
import {
  isVersionedHumanApproval,
  isVersionedSignedDelegation,
  isVersionedSignedIntent,
  unsignedApproval,
  unsignedDelegation,
  unsignedIntent,
} from './protocol.js'
import {
  ADAP_SIGNED_VERSION,
  constraintProfileForSignedObjectProfile,
  signedObjectProfileOf,
  type ConstraintProfile,
  type SignedObjectProfile,
  verifyEnvelopeSignature,
} from './signed-object.js'
import { cloneSignedDelegation, cloneSignedIntent, deepFreeze } from './snapshot.js'

export type DirectoryInput = AuthorityDirectory | ReadonlyMap<string, string>

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

/**
 * A delegation chain must use one signed-object profile end-to-end.
 * Mixed legacy / 0.2 links are rejected — there is no silent migration that
 * could reinterpret a legacy grant under ceilings-v1.
 */
export function assertChainProfileConsistency(
  chain: readonly SignedDelegation[]
): SignedObjectProfile {
  if (chain.length === 0) {
    throw new AuthorityError('profile', 'delegation chain is empty', true)
  }
  const profile = signedObjectProfileOf(chain[0]!)
  for (let index = 0; index < chain.length; index += 1) {
    const delegation = chain[index]!
    if (signedObjectProfileOf(delegation) !== profile) {
      throw new AuthorityError(
        'profile',
        'delegation chain mixes signed-object profiles',
        true
      )
    }
  }
  return profile
}

export function assertIntentMatchesAuthorityProfile(
  intent: SignedIntent,
  profile: SignedObjectProfile
): void {
  if (signedObjectProfileOf(intent) !== profile) {
    throw new AuthorityError(
      'profile',
      'intent signed-object profile does not match delegation chain',
      true
    )
  }
}

export function assertApprovalMatchesAuthorityProfile(
  approval: HumanApproval,
  profile: SignedObjectProfile
): void {
  if (signedObjectProfileOf(approval) !== profile) {
    throw new AuthorityError(
      'profile',
      'approval signed-object profile does not match authorization context',
      true
    )
  }
}

export function validateDelegationNarrowing(parent: SignedDelegation, child: SignedDelegation): void {
  const parentProfile = signedObjectProfileOf(parent)
  const childProfile = signedObjectProfileOf(child)
  if (parentProfile !== childProfile) {
    throw new AuthorityError(
      'profile',
      'child delegation signed-object profile does not match parent',
      true
    )
  }
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
    normalizeConstraints(child.constraints, 'child.constraints'),
    constraintProfileForSignedObjectProfile(parentProfile)
  )
}

/**
 * Profile-aware constraint narrowing.
 * Legacy: only `max_amount` may be reduced as a ceiling; every other key
 * (including `max_quantity`) must match exactly.
 * ceilings-v1: every canonical `max_<field>` may be reduced, never raised.
 */
function assertConstraintsNarrow(
  parent: Constraints,
  child: Constraints,
  profile: ConstraintProfile
): void {
  for (const [key, parentVal] of ownEntries(parent as Record<string, unknown>)) {
    if (!hasOwn(child, key)) {
      throw new AuthorityError('narrowing', `child drops constraint ${key}`, true)
    }
    const childVal = (child as Record<string, unknown>)[key]
    const reducibleCeiling =
      profile === 'ceilings-v1'
        ? isMaxAmountKey(key)
        : key === 'max_amount'
    if (
      reducibleCeiling &&
      typeof parentVal === 'number' &&
      typeof childVal === 'number'
    ) {
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

export function constraintProfileForDelegation(delegation: SignedDelegation): ConstraintProfile {
  return constraintProfileForSignedObjectProfile(signedObjectProfileOf(delegation))
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
  assertParametersWithin(
    intent.action,
    intent.parameters,
    constraints,
    constraintProfileForDelegation(delegation)
  )
}

/**
 * Legacy v0.1: `max_amount` is a ceiling on `amount`; every other constraint key
 * (including `max_quantity`) requires exact equality on that parameter name.
 * Profile ceilings-v1 (signed-object 0.2): every `max_<field>` is a ceiling on
 * `parameters.<field>`.
 */
function assertParametersWithin(
  action: string,
  parameters: Readonly<Record<string, unknown>>,
  constraints: Constraints,
  profile: ConstraintProfile
): void {
  for (const [key, bound] of ownEntries(constraints as Record<string, unknown>)) {
    if (profile === 'ceilings-v1') {
      const field = ceilingField(key)
      if (field) {
        const presented = hasOwn(parameters, field) ? parameters[field] : undefined
        if (presented === undefined) {
          if (field === 'amount' && (action === 'read' || action === 'search')) continue
          throw new AuthorityError('constraint', `${field} is required`, true)
        }
        assertWithinCeiling(presented, bound, field, key)
        continue
      }
      if (key.startsWith('max_')) {
        throw new AuthorityError('constraint', `constraint ${key} is not a canonical max_<field> ceiling`, true)
      }
    } else if (key === 'max_amount') {
      const amount = hasOwn(parameters, 'amount') ? parameters.amount : undefined
      if (amount === undefined) {
        if (action === 'read' || action === 'search') continue
        throw new AuthorityError('constraint', 'amount is required', true)
      }
      assertWithinCeiling(amount, bound, 'amount', 'max_amount')
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

function verifyDelegationSignature(
  delegation: SignedDelegation,
  directory: AuthorityDirectory,
  now: Date
): void {
  if (isVersionedSignedDelegation(delegation)) {
    const key = assertUsableDirectoryKey(directory.lookup(delegation.issuer, delegation.kid), now, {
      requireKid: delegation.kid,
    })
    const envelope = {
      adap: ADAP_SIGNED_VERSION,
      typ: 'delegation' as const,
      alg: 'Ed25519' as const,
      kid: delegation.kid!,
      payload: unsignedDelegation(delegation),
      signature: delegation.signature,
    }
    if (!verifyEnvelopeSignature(envelope, importPublicKey(key.publicKey), 'delegation')) {
      throw new AuthorityError('signature_invalid', `delegation signature invalid: ${delegation.delegation_id}`)
    }
    return
  }
  const key = assertUsableDirectoryKey(directory.lookup(delegation.issuer), now)
  if (!verifyObject(unsignedDelegation(delegation), delegation.signature, importPublicKey(key.publicKey))) {
    throw new AuthorityError('signature_invalid', `delegation signature invalid: ${delegation.delegation_id}`)
  }
}

function verifyIntentSignature(intent: SignedIntent, directory: AuthorityDirectory, now: Date): void {
  if (isVersionedSignedIntent(intent)) {
    const key = assertUsableDirectoryKey(directory.lookup(intent.actor, intent.kid), now, {
      requireKid: intent.kid,
    })
    const envelope = {
      adap: ADAP_SIGNED_VERSION,
      typ: 'intent' as const,
      alg: 'Ed25519' as const,
      kid: intent.kid!,
      payload: unsignedIntent(intent),
      signature: intent.signature,
    }
    if (!verifyEnvelopeSignature(envelope, importPublicKey(key.publicKey), 'intent')) {
      throw new AuthorityError('signature_invalid', 'intent signature invalid')
    }
    return
  }
  const key = assertUsableDirectoryKey(directory.lookup(intent.actor), now)
  if (!verifyObject(unsignedIntent(intent), intent.signature, importPublicKey(key.publicKey))) {
    throw new AuthorityError('signature_invalid', 'intent signature invalid')
  }
}

function verifySignatures(
  chain: readonly SignedDelegation[],
  intent: SignedIntent,
  directory: AuthorityDirectory,
  now: Date
): void {
  for (const delegation of chain) {
    verifyDelegationSignature(delegation, directory, now)
  }
  verifyIntentSignature(intent, directory, now)
}

function assertTrustedRootIssuer(
  chain: readonly SignedDelegation[],
  trustedRootIssuers: ReadonlySet<string> | readonly string[] | undefined
): void {
  if (trustedRootIssuers == null) return
  const trusted = trustedRootIssuers instanceof Set ? trustedRootIssuers : new Set(trustedRootIssuers)
  const root = chain[0]
  if (!root) throw new AuthorityError('trust', 'delegation chain is empty', false)
  if (!trusted.has(root.issuer)) {
    throw new AuthorityError(
      'trust',
      'root issuer is not an operator-trusted authority',
      false
    )
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
  readonly directory: DirectoryInput
  readonly now?: Date
  /**
   * Optional operator allow-list for root issuers. Checked before the result is
   * treated as authenticated. A directory key alone is not enough.
   */
  readonly trustedRootIssuers?: ReadonlySet<string> | readonly string[]
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
  verifySignatures(chain, intent, resolveAuthorityDirectory(input.directory), input.now ?? new Date())
  assertTrustedRootIssuer(chain, input.trustedRootIssuers)
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
  readonly directory: DirectoryInput
  readonly now: Date
  readonly trustedRootIssuers?: ReadonlySet<string> | readonly string[]
}): VerifiedAuthority {
  const presented = presentAuthority(input)
  return authorizePresented({ chain: presented.chain, intent: presented.intent, now: input.now })
}

function verifyAuthenticated(chain: readonly SignedDelegation[], intent: SignedIntent, now: Date): void {
  const authorityProfile = assertChainProfileConsistency(chain)
  assertIntentMatchesAuthorityProfile(intent, authorityProfile)

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
  readonly directory: DirectoryInput
  readonly now: Date
  /** When set, duplicate approval of the same binding is rejected. */
  readonly seenApprovalKeys?: Set<string>
  /** When set, only this decision is accepted (APPROVE or DENY). */
  readonly expectedDecision?: 'APPROVE' | 'DENY'
  /**
   * Signed-object profile of the authorization context (chain + intent).
   * Required for profile consistency: a v0.2 context rejects a legacy approval
   * and a legacy context rejects a v0.2 approval.
   */
  readonly authorityProfile: SignedObjectProfile
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
    now,
    seenApprovalKeys,
  } = input
  const directory = resolveAuthorityDirectory(input.directory)

  assertApprovalMatchesAuthorityProfile(approval, input.authorityProfile)

  const expected = input.expectedDecision ?? 'APPROVE'
  if (approval.decision !== expected) {
    throw new AuthorityError('approval', `approval decision is not ${expected}`, true)
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
    approval.decision,
    approval.approved_at,
    approval.signature,
  ].join('|')
  if (seenApprovalKeys?.has(approvalKey)) {
    throw new AuthorityError('approval', 'duplicate approval rejected', true)
  }

  if (isVersionedHumanApproval(approval)) {
    const key = assertUsableDirectoryKey(directory.lookup(approval.approver_id, approval.kid), now, {
      requireKid: approval.kid,
    })
    const envelope = {
      adap: ADAP_SIGNED_VERSION,
      typ: 'approval' as const,
      alg: 'Ed25519' as const,
      kid: approval.kid!,
      payload: unsignedApproval(approval),
      signature: approval.signature,
    }
    if (!verifyEnvelopeSignature(envelope, importPublicKey(key.publicKey), 'approval')) {
      throw new AuthorityError('approval', 'approval signature invalid', true)
    }
  } else {
    const key = assertUsableDirectoryKey(directory.lookup(approval.approver_id), now)
    if (!verifyObject(unsignedApproval(approval), approval.signature, importPublicKey(key.publicKey))) {
      throw new AuthorityError('approval', 'approval signature invalid', true)
    }
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
