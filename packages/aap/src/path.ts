import type { KeyObject } from 'node:crypto'
import {
  emitAuthorizationReceipt,
  verifyAuthorizationReceipt,
  type AuthorizationReceiptV1,
  type HumanAttestation,
} from 'adap-receipt'
import { evaluateToolCall, type Policy, type PolicyDecision } from 'adap-policy'
import { publicKeyFingerprint, signHex, verifyHex, sha256 } from './crypto.js'
import { AuthorityError } from './errors.js'
import type { NonceStore } from './nonce.js'
import { PendingAuthorizationStore, type PendingStore } from './pending.js'
import {
  ImmutablePolicyResolver,
  assertPolicyContentHash,
  type PolicyResolver,
} from './policy-resolver.js'
import { resolveTrustedNow, type Clock } from './clock.js'
import type { Decision, HumanApproval, Identity, SignedDelegation, SignedIntent } from './protocol.js'
import { unsignedDelegation, unsignedIntent } from './protocol.js'
import { deepDataClone } from './snapshot.js'
import { authorizePresented, presentAuthority, verifyHumanApproval } from './validate.js'

export interface ExecutionContext {
  readonly action: string
  readonly target: string
  readonly actor: string
  readonly principalId: string
  readonly parameters: Readonly<Record<string, unknown>>
  readonly intentHash: string
}

export interface ProtocolResult {
  readonly decision: Decision
  readonly ruleId: string
  readonly reason: string
  readonly intentHash: string
  readonly delegationHash: string
  readonly policyHash: string
  readonly executionHash: string
  readonly executed: boolean
  /** False when the signature was not verified. Those results have no receipt. */
  readonly authenticated: boolean
  readonly result?: unknown
  readonly receipt?: AuthorizationReceiptV1
}

export function authenticatedReceipt(result: ProtocolResult): AuthorizationReceiptV1 {
  if (!result.authenticated || result.receipt == null) {
    throw new Error('authenticated authority result is missing its receipt')
  }
  return result.receipt
}

export interface RunAuthorityPathInput {
  readonly chain: readonly SignedDelegation[]
  readonly intent: SignedIntent
  readonly directory: ReadonlyMap<string, string>
  /**
   * Operator-configured identities allowed to issue a root delegation.
   * Required. A public key in `directory` with a valid signature is not enough.
   */
  readonly trustedRootIssuers: ReadonlySet<string> | readonly string[]
  /** Must be the document pinned under `policyUri` in `policyResolver`. */
  readonly policy: Policy
  readonly policyUri: string
  readonly ledger: NonceStore
  readonly signer: Identity
  readonly approval?: HumanApproval
  readonly execute?: (ctx: ExecutionContext) => unknown
  /**
   * Trusted runtime clock. When omitted, the process clock is used.
   * A caller-supplied `now` is rejected and cannot move expiry.
   */
  readonly clock?: Clock
  /**
   * Not a clock. If this field is present, the path rejects the request.
   * Authorization time comes only from `clock` or the process clock.
   */
  readonly now?: unknown
  /** Pending REQUIRE_HUMAN store. Required for safe continuation. */
  readonly pendingStore?: PendingStore
  /**
   * Operator-owned registry. The URI must already be registered. The path never
   * registers a caller document, and the caller `policy` must hash to the pin.
   */
  readonly policyResolver: PolicyResolver
  /** Dedup set for approval replay within a process. */
  readonly seenApprovals?: Set<string>
  readonly receiptSequence?: number
  readonly prevReceiptHash?: string | null
}

const NONE_EXEC = 'none'
const UNHASHABLE_EXEC = 'unhashable'

function hasResolver(value: unknown): value is PolicyResolver {
  if (value == null || typeof value !== 'object') return false
  const candidate = value as Partial<Record<keyof PolicyResolver, unknown>>
  return (
    typeof candidate.resolveByUri === 'function' &&
    typeof candidate.resolveByContentHash === 'function'
  )
}

function unauthenticatedRejection(error: unknown): ProtocolResult {
  const code = error instanceof AuthorityError ? error.code : 'canonicalization'
  const reason =
    error instanceof AuthorityError ? error.message : 'authority input could not be canonicalized'
  return {
    decision: 'BLOCK',
    ruleId: code,
    reason,
    intentHash: '',
    delegationHash: '',
    policyHash: '',
    executionHash: NONE_EXEC,
    executed: false,
    authenticated: false,
  }
}

export async function runAuthorityPath(input: RunAuthorityPathInput): Promise<ProtocolResult> {
  let signatureVerified = false
  let intentHash = ''
  let delegationHash = ''
  let policyHash = ''
  let principalId: string | undefined
  let now = new Date()
  let presented: { chain: SignedDelegation[]; intent: SignedIntent } | undefined

  try {
    now = resolveTrustedNow(input)
    if (!hasResolver(input.policyResolver)) {
      throw new AuthorityError('policy', 'a trusted policy resolver is required', false)
    }
    if (input.trustedRootIssuers == null) {
      throw new AuthorityError('trust', 'trusted root issuers are required', false)
    }
    presented = presentAuthority({
      chain: input.chain,
      intent: input.intent,
      directory: input.directory,
      trustedRootIssuers: input.trustedRootIssuers,
    })
    signatureVerified = true
    intentHash = sha256(unsignedIntent(presented.intent))
    delegationHash = sha256(presented.chain.map(unsignedDelegation))
    policyHash =
      input.policyResolver.resolveByUri(input.policyUri)?.contentHash ?? sha256(input.policy)
    principalId = presented.chain[0]?.issuer

    // An approval presented with a different intent fails for the binding reason
    // before nonce or pending state can mask it.
    if (input.approval != null && input.approval.intent_hash !== intentHash) {
      throw new AuthorityError('approval', 'approval is not bound to this intent', true)
    }

    const usability = await input.ledger.assertUsable(presented.intent.nonce, intentHash)
    const verified = authorizePresented({
      chain: presented.chain,
      intent: presented.intent,
      now,
    })
    const pendingStore = input.pendingStore
    const seenApprovals = input.seenApprovals
    const view: RunAuthorityPathInput & { now: Date } = {
      ...input,
      intent: verified.intent,
      chain: verified.chain,
      now,
    }

    // A human-wait pending nonce cannot be re-evaluated into ALLOW by supplying a new policy.
    if (usability === 'pending' && !input.approval) {
      throw new AuthorityError(
        'approval',
        'pending REQUIRE_HUMAN cannot continue without a bound human approval',
        true
      )
    }

    let policy = input.policy

    if (input.approval) {
      if (!pendingStore) {
        throw new AuthorityError(
          'approval',
          'pending authorization store is required to continue REQUIRE_HUMAN',
          true
        )
      }
      if (!principalId) throw new AuthorityError('approval', 'missing principal', true)

      const pending = await pendingStore.get(verified.intent.nonce)
      if (!pending) {
        throw new AuthorityError('approval', 'no pending authorization for this nonce', true)
      }

      if (input.policyUri !== pending.policyUri) {
        throw new AuthorityError('approval', 'policy URI does not match pending context', true)
      }
      const resolved = input.policyResolver.resolveByContentHash(pending.policyContentHash)
      if (resolved.uri !== pending.policyUri) {
        throw new AuthorityError('approval', 'policy URI does not match pending context', true)
      }
      if (sha256(input.policy) !== resolved.contentHash) {
        throw new AuthorityError(
          'approval',
          'continuation policy content hash does not match pending context',
          true
        )
      }
      const boundPolicy = resolved.policy
      const boundHash = resolved.contentHash

      await pendingStore.requireContinuation({
        nonce: verified.intent.nonce,
        intentHash,
        principalId,
        agentId: verified.intent.actor,
        delegationChainHash: delegationHash,
        policyUri: pending.policyUri,
        policyContentHash: boundHash,
        policyVersion: pending.policyVersion,
        policyName: pending.policyName,
        approverId: principalId,
        now,
      })

      policy = boundPolicy
      policyHash = boundHash

      const policyDecision = evaluateToolCall({
        policy,
        toolName: verified.intent.action,
        toolArgs: deepDataClone(verified.intent.parameters) as Record<string, unknown>,
        agentRole: verified.intent.actor,
      })

      if (policyDecision.action !== 'REQUIRE_HUMAN') {
        throw new AuthorityError(
          'approval',
          'pinned policy no longer yields REQUIRE_HUMAN for this intent',
          true
        )
      }
      if (policyDecision.ruleId !== pending.matchedRuleId) {
        throw new AuthorityError('approval', 'pinned policy rule does not match pending context', true)
      }

      verifyHumanApproval({
        approval: input.approval,
        intentHash,
        principalId,
        agentId: verified.intent.actor,
        delegationChainHash: delegationHash,
        policyContentHash: policyHash,
        matchedRuleId: pending.matchedRuleId,
        intent: verified.intentPayload,
        directory: input.directory,
        now,
        seenApprovalKeys: seenApprovals,
      })

      await pendingStore.markApproved(verified.intent.nonce, intentHash)

      return await executeBound(
        { ...view, policy },
        {
          decision: policyDecision,
          intentHash,
          delegationHash,
          policyHash,
          principalId,
          approved: true,
        }
      )
    }

    // Unknown URIs are not registered from the caller object, and a different
    // document for a known URI does not replace the pin.
    const existing = input.policyResolver.resolveByUri(input.policyUri)
    if (!existing) {
      throw new AuthorityError('policy', 'unknown policy URI', true)
    }
    assertPolicyContentHash(policy, existing.contentHash)
    policy = existing.policy
    policyHash = existing.contentHash

    const policyDecision = evaluateToolCall({
      policy,
      toolName: verified.intent.action,
      toolArgs: deepDataClone(verified.intent.parameters) as Record<string, unknown>,
      agentRole: verified.intent.actor,
    })

    if (
      policyDecision.action === 'BLOCK' ||
      (policyDecision.action !== 'ALLOW' && policyDecision.action !== 'REQUIRE_HUMAN')
    ) {
      await input.ledger.consume(verified.intent.nonce, intentHash)
      return seal(
        { ...view, policy },
        {
          decision: 'BLOCK',
          ruleId: policyDecision.ruleId,
          reason: policyDecision.reason,
          alertSeverity: policyDecision.alertSeverity,
          matched: policyDecision.matched,
          intentHash,
          delegationHash,
          policyHash,
          executed: false,
          failureMode: 'RULE_VIOLATION',
          principalId,
        }
      )
    }

    if (policyDecision.action === 'REQUIRE_HUMAN') {
      if (!principalId) throw new AuthorityError('approval', 'missing principal', true)
      if (!pendingStore) {
        throw new AuthorityError(
          'approval',
          'pending authorization store is required for REQUIRE_HUMAN',
          true
        )
      }
      await pendingStore.put({
        intentHash,
        principalId,
        agentId: verified.intent.actor,
        delegationChainHash: delegationHash,
        policyUri: input.policyUri,
        policyContentHash: policyHash,
        policyVersion: policy.version,
        policyName: policy.policyName,
        matchedRuleId: policyDecision.ruleId,
        originalDecision: 'REQUIRE_HUMAN',
        approvalState: 'pending',
        expiry: verified.intent.expires_at,
        nonce: verified.intent.nonce,
        approverId: principalId,
      })
      await input.ledger.reserve(verified.intent.nonce, intentHash)
      return seal(
        { ...view, policy },
        {
          decision: 'REQUIRE_HUMAN',
          ruleId: policyDecision.ruleId,
          reason: policyDecision.reason,
          alertSeverity: policyDecision.alertSeverity,
          matched: policyDecision.matched,
          intentHash,
          delegationHash,
          policyHash,
          executed: false,
          failureMode: 'NONE',
          principalId,
          human: { required: true, status: 'pending' },
        }
      )
    }

    // ALLOW
    return await executeBound(
      { ...view, policy },
      {
        decision: policyDecision,
        intentHash,
        delegationHash,
        policyHash,
        principalId: principalId ?? verified.intent.actor,
        approved: false,
      }
    )
  } catch (error) {
    if (!signatureVerified || !presented) {
      return unauthenticatedRejection(error)
    }
    if (!intentHash) {
      try {
        intentHash = sha256(unsignedIntent(presented.intent))
        delegationHash = sha256(presented.chain.map(unsignedDelegation))
        if (!policyHash) {
          policyHash =
            input.policyResolver.resolveByUri(input.policyUri)?.contentHash ?? sha256(input.policy)
        }
        principalId = presented.chain[0]?.issuer
      } catch {
        return unauthenticatedRejection(error)
      }
    }
    const view: RunAuthorityPathInput & { now: Date } = {
      ...input,
      intent: presented.intent,
      chain: presented.chain,
      now,
    }
    if (error instanceof AuthorityError) {
      if (error.authenticated && error.code !== 'replay' && error.code !== 'approval') {
        await retireNonce(input.ledger, presented.intent.nonce, intentHash)
      }
      return sealOrClosed(view, {
        decision: 'BLOCK',
        ruleId: error.code,
        reason: error.message,
        alertSeverity: 'CRITICAL',
        matched: false,
        intentHash,
        delegationHash,
        policyHash,
        executed: false,
        failureMode: 'RULE_VIOLATION',
        principalId,
      })
    }
    await retireNonce(input.ledger, presented.intent.nonce, intentHash)
    return sealOrClosed(view, {
      decision: 'BLOCK',
      ruleId: 'system',
      reason: 'authority path failed closed',
      alertSeverity: 'CRITICAL',
      matched: false,
      intentHash,
      delegationHash,
      policyHash,
      executed: false,
      failureMode: 'SYSTEM_ERROR',
      principalId,
    })
  }
}

function sealOrClosed(
  input: RunAuthorityPathInput & { readonly now?: Date; readonly policy?: Policy },
  fields: Parameters<typeof seal>[1]
): ProtocolResult {
  try {
    return seal(input, fields)
  } catch {
    return {
      decision: 'BLOCK',
      ruleId: 'system',
      reason: 'authority path failed closed',
      intentHash: fields.intentHash,
      delegationHash: fields.delegationHash,
      policyHash: fields.policyHash,
      executionHash: NONE_EXEC,
      executed: false,
      authenticated: true,
    }
  }
}

async function retireNonce(ledger: NonceStore, nonce: string, intentHash: string): Promise<void> {
  try {
    await ledger.consume(nonce, intentHash)
  } catch {
    // A store rejection must not escape the authority boundary.
  }
}

async function executeBound(
  input: RunAuthorityPathInput & { readonly now: Date; readonly policy: Policy },
  bound: {
    readonly decision: PolicyDecision
    readonly intentHash: string
    readonly delegationHash: string
    readonly policyHash: string
    readonly principalId: string
    readonly approved: boolean
  }
): Promise<ProtocolResult> {
  if (!input.execute) {
    await input.ledger.consume(input.intent.nonce, bound.intentHash)
    return seal(input, {
      ...bound,
      decision: 'BLOCK',
      ruleId: 'execution',
      reason: 'execution boundary has no executor',
      alertSeverity: 'CRITICAL',
      matched: false,
      executed: false,
      failureMode: 'SYSTEM_ERROR',
    })
  }

  // Only ALLOW reaches the executor. Approved REQUIRE_HUMAN is represented as ALLOW.
  if (bound.decision.action !== 'ALLOW' && !bound.approved) {
    await input.ledger.consume(input.intent.nonce, bound.intentHash)
    return seal(input, {
      ...bound,
      decision: 'BLOCK',
      ruleId: 'execution',
      reason: 'executor requires ALLOW',
      alertSeverity: 'CRITICAL',
      matched: false,
      executed: false,
      failureMode: 'RULE_VIOLATION',
    })
  }

  const presentedHash = sha256(unsignedIntent(input.intent))
  if (
    presentedHash !== bound.intentHash ||
    (input.approval != null && input.approval.intent_hash !== bound.intentHash)
  ) {
    await input.ledger.consume(input.intent.nonce, bound.intentHash)
    return seal(input, {
      ...bound,
      decision: 'BLOCK',
      ruleId: 'intent',
      reason: 'intent at the execution boundary does not match the authorized intent',
      alertSeverity: 'CRITICAL',
      matched: false,
      executed: false,
      failureMode: 'RULE_VIOLATION',
    })
  }

  try {
    await input.ledger.claimForExecution(input.intent.nonce, bound.intentHash)
  } catch (error) {
    if (error instanceof AuthorityError && error.code === 'replay') {
      return seal(input, {
        ...bound,
        decision: 'BLOCK',
        ruleId: 'replay',
        reason: error.message,
        alertSeverity: 'CRITICAL',
        matched: false,
        executed: false,
        failureMode: 'RULE_VIOLATION',
      })
    }
    throw error
  }

  const ctx: ExecutionContext = {
    action: input.intent.action,
    target: input.intent.target,
    actor: input.intent.actor,
    principalId: bound.principalId,
    parameters: deepDataClone(input.intent.parameters) as Record<string, unknown>,
    intentHash: bound.intentHash,
  }

  let result: unknown
  try {
    result = await input.execute(ctx)
  } catch {
    await input.ledger.fail(input.intent.nonce, bound.intentHash)
    return seal(input, {
      decision: 'BLOCK',
      ruleId: 'execution',
      reason: 'executor failed; nothing is recorded as executed',
      alertSeverity: 'CRITICAL',
      matched: false,
      intentHash: bound.intentHash,
      delegationHash: bound.delegationHash,
      policyHash: bound.policyHash,
      executed: false,
      failureMode: 'SYSTEM_ERROR',
      principalId: bound.principalId,
    })
  }

  // The callback returned. A later store or seal failure does not rewrite an
  // observed result as "nothing executed". The nonce is still spent so the same
  // intent cannot retry. An explicit unknown downstream state is not a confirmed
  // side effect and is not rewritten as BLOCK.
  const outcomeUnknown = isUnknownExecutionReport(result)
  try {
    await input.ledger.consume(input.intent.nonce, bound.intentHash)
  } catch {
    // The claim already spent exclusivity. A consume race must not escape.
  }
  try {
    await input.pendingStore?.consume(input.intent.nonce, bound.intentHash)
  } catch {
    // Pending consume is bookkeeping after the side-effect boundary.
  }

  const reason = outcomeUnknown
    ? 'Downstream outcome is unknown. The nonce is consumed. The side effect was not confirmed and the call was not repeated.'
    : bound.approved
      ? `Human approval bound to intent ${bound.intentHash}`
      : bound.decision.reason

  try {
    return seal(input, {
      decision: 'ALLOW',
      ruleId: bound.decision.ruleId,
      reason,
      alertSeverity: outcomeUnknown ? 'CRITICAL' : bound.decision.alertSeverity,
      matched: bound.decision.matched,
      intentHash: bound.intentHash,
      delegationHash: bound.delegationHash,
      policyHash: bound.policyHash,
      executed: !outcomeUnknown,
      result,
      failureMode: outcomeUnknown ? 'SYSTEM_ERROR' : 'NONE',
      principalId: bound.principalId,
      extensions: outcomeUnknown ? { executionState: 'unknown' } : undefined,
      human: bound.approved
        ? {
            required: true,
            status: 'approved',
            approverId: input.approval?.approver_id,
            decidedAt: input.approval?.approved_at,
          }
        : undefined,
    })
  } catch {
    return {
      decision: 'ALLOW',
      ruleId: bound.decision.ruleId,
      reason,
      intentHash: bound.intentHash,
      delegationHash: bound.delegationHash,
      policyHash: bound.policyHash,
      executionHash: UNHASHABLE_EXEC,
      executed: !outcomeUnknown,
      authenticated: true,
      result,
    }
  }
}

function isUnknownExecutionReport(result: unknown): boolean {
  return (
    result != null &&
    typeof result === 'object' &&
    !Array.isArray(result) &&
    (result as { executionState?: unknown }).executionState === 'unknown'
  )
}

function seal(
  input: RunAuthorityPathInput & { readonly now?: Date; readonly policy?: Policy },
  fields: {
    readonly decision: Decision
    readonly ruleId: string
    readonly reason: string
    readonly alertSeverity: 'LOW' | 'MEDIUM' | 'CRITICAL'
    readonly matched: boolean
    readonly intentHash: string
    readonly delegationHash: string
    readonly policyHash: string
    readonly executed: boolean
    readonly result?: unknown
    readonly failureMode: 'NONE' | 'RULE_VIOLATION' | 'SYSTEM_ERROR'
    readonly principalId?: string
    readonly human?: HumanAttestation
    readonly extensions?: Readonly<Record<string, unknown>>
  }
): ProtocolResult {
  const decidedAt = (input.now ?? resolveTrustedNow(input)).toISOString()
  const policy = input.policy
  const executionHash = fields.executed ? sha256(fields.result ?? null) : NONE_EXEC
  const drafted = emitAuthorizationReceipt({
    agentId: input.intent.actor,
    toolName: input.intent.action,
    toolArgs: deepDataClone(input.intent.parameters) as Record<string, unknown>,
    action: fields.decision,
    ruleId: fields.ruleId,
    reason: fields.reason,
    alertSeverity: fields.alertSeverity,
    matched: fields.matched,
    policyUri: input.policyUri,
    policyName: policy?.policyName ?? 'unknown',
    policyVersion: policy?.version ?? '0',
    policyContentHash: fields.policyHash,
    intentHash: fields.intentHash,
    principalId: fields.principalId,
    delegationChain: input.chain.map((delegation) => delegation.subject),
    authority:
      fields.principalId && input.chain.length > 0
        ? {
            principalId: fields.principalId,
            chain: input.chain.map((delegation) => ({
              delegationId: delegation.delegation_id,
              subject: delegation.subject,
              hash: sha256(unsignedDelegation(delegation)),
            })),
          }
        : undefined,
    issuer: input.signer.id,
    issuerKeyId: publicKeyFingerprint(input.signer.publicKey),
    decidedAt,
    receiptId: `rcpt_${fields.intentHash.slice(0, 20)}_${fields.executed ? 'exec' : fields.decision.toLowerCase()}`,
    execution: {
      targetSystem: input.intent.target,
      executed: fields.executed,
      executedAt: fields.executed ? decidedAt : undefined,
      intentHash: fields.intentHash,
    },
    human: fields.human,
    failureMode: fields.failureMode,
    extensions: fields.extensions,
    sequence: input.receiptSequence,
    prevReceiptHash: input.prevReceiptHash,
    signatureHex: 'ab'.repeat(64),
  })
  const receipt = signReceipt(drafted, input.signer.privateKey)
  return {
    decision: fields.decision,
    ruleId: fields.ruleId,
    reason: fields.reason,
    intentHash: fields.intentHash,
    delegationHash: fields.delegationHash,
    policyHash: fields.policyHash,
    executionHash,
    executed: fields.executed,
    authenticated: true,
    result: fields.result,
    receipt,
  }
}

export function signReceipt(receipt: AuthorizationReceiptV1, privateKey: KeyObject): AuthorizationReceiptV1 {
  const { signature: _signature, ...unsigned } = receipt
  return { ...receipt, signature: signHex(unsigned, privateKey) }
}

export function verifyProtocolReceipt(
  receipt: AuthorizationReceiptV1,
  publicKey: KeyObject
): {
  readonly valid: boolean
  readonly errors: readonly string[]
} {
  const structure = verifyAuthorizationReceipt(receipt)
  const { signature, ...unsigned } = receipt
  const signatureOk = verifyHex(unsigned, signature, publicKey)
  const errors = [...structure.errors]
  if (!signatureOk) errors.push('ed25519 signature invalid')
  return { valid: structure.valid && signatureOk, errors }
}

export { ImmutablePolicyResolver, PendingAuthorizationStore }
