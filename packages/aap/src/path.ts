import { randomBytes, type KeyObject } from 'node:crypto'
import {
  emitAuthorizationReceipt,
  verifyAuthorizationReceipt,
  type AuthorizationReceiptV1,
  type HumanAttestation,
} from 'adap-receipt'
import { evaluateToolCall, type Policy, type PolicyDecision } from 'adap-policy'
import { publicKeyFingerprint, signHex, verifyHex, sha256 } from './crypto.js'
import { AuthorityError } from './errors.js'
import type { DirectoryInput } from './validate.js'
import type { NonceStore } from './nonce.js'
import {
  DEFAULT_MAX_PENDING_APPROVALS,
  PendingAuthorizationStore,
  type PendingStore,
} from './pending.js'
import {
  ImmutablePolicyResolver,
  assertPolicyContentHash,
  type PolicyResolver,
} from './policy-resolver.js'
import { MAX_ISSUED_AT_SKEW_MS, resolveTrustedNow, type Clock } from './clock.js'
import type { Decision, HumanApproval, Identity, SignedDelegation, SignedIntent } from './protocol.js'
import { unsignedDelegation, unsignedIntent } from './protocol.js'
import { deepDataClone } from './snapshot.js'
import { authorityMcpCall, hashMcpToolDefinition, type McpToolDefinition } from './mcp-tool.js'
import { validateParametersAgainstSchema } from './schema-validate.js'
import { chargeCumulativeSpend, type SpendLedger } from './spend.js'
import {
  assertChainProfileConsistency,
  authorizePresented,
  presentAuthority,
  verifyHumanApproval,
} from './validate.js'

export class ExecutionOutcomeUnknownError extends Error {
  constructor(message = 'downstream outcome unknown') {
    super(message)
    this.name = 'ExecutionOutcomeUnknownError'
  }
}

export interface ExecutionContext {
  readonly action: string
  readonly target: string
  readonly actor: string
  readonly principalId: string
  readonly parameters: Readonly<Record<string, unknown>>
  readonly intentHash: string
  /**
   * The runtime's tool-definition hash when one was presented, the same value the
   * receipt binds. The executor can compare it with the live definition before
   * dispatch and refuse one that changed after authorization.
   */
  readonly toolDefinitionHash?: string
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
  readonly directory: DirectoryInput
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
  /**
   * Optional operator root-of-authority check. When set, a root whose issuer
   * is not authorized fails closed (`root_not_authorized`).
   * Self-issued roots (`issuer === subject`) are rejected unless
   * `allowSelfIssuedRoot` is explicitly true.
   */
  readonly rootAuthority?: {
    readonly mayIssueRoot: (input: {
      readonly issuerId: string
      readonly subjectId: string
      readonly capabilities: readonly { readonly action: string; readonly target: string }[]
    }) => boolean
    /** Opt-in for issuer === subject roots. Default false (spec: reject self-issued). */
    readonly allowSelfIssuedRoot?: boolean
  }
  /**
   * Optional per-delegation revocation check. `revoked` and `unavailable` fail closed.
   */
  readonly revocationCheck?: (
    delegationId: string,
  ) => 'active' | 'revoked' | 'unavailable' | Promise<'active' | 'revoked' | 'unavailable'>
  /**
   * Optional human-approval identity policy. When set, self-approval and non-human
   * approvers fail closed.
   */
  readonly approvalPolicy?: {
    readonly isHuman?: (identityId: string) => boolean
    readonly allowSelfApproval?: boolean
  }
  /**
   * Max concurrent open pending approvals per (principal, agent). Default 5.
   * Not controllable via request metadata.
   */
  readonly maxPendingApprovals?: number
  /**
   * Tolerance applied only to `issued_at` (`issued_at <= now + skew`).
   * Default 0. Values above {@link MAX_ISSUED_AT_SKEW_MS} are rejected.
   * `expires_at` is not extended. A non-zero value is recorded on the receipt.
   */
  readonly issuedAtSkewMs?: number
  /**
   * Verifier audience. Required unless `unsafeDevAllowUnconfiguredChecks` is set.
   * Every delegation, intent, and approval `aud` must equal it.
   */
  readonly audience?: string
  /**
   * Dev-only escape hatch. Default false. When true, missing root authority,
   * revocation, approver kind, and audience are not enforced. Recorded on the receipt.
   */
  readonly unsafeDevAllowUnconfiguredChecks?: boolean
  readonly enforcementMode?: 'gateway' | 'in_process'
  readonly credentialBoundary?: 'gateway_isolated' | 'caller_supplied'
  /**
   * Required when any delegation in the chain sets `cumulative_max_amount`.
   * `max_amount` stays a per-intent ceiling. This ledger is the running sum.
   */
  readonly spendLedger?: SpendLedger
  /**
   * Copy tool arguments into the receipt. Default false: the emitter redacts
   * them. Set true only when the caller has decided the arguments are not secret.
   */
  readonly includeArgsUnredacted?: boolean
  readonly argsRedactedAllowlist?: readonly string[]
  /**
   * Runtime hash of the MCP tool definition about to be called (`sha256:` + hex).
   * Required for an authority-enforcing MCP call (`target` under `mcp/`), and
   * required when any delegation sets `tool_definition_hash`. A missing or
   * different hash is `BLOCK` before policy evaluation and before dispatch.
   * On those calls a well-formed value is bound on every receipt as
   * `execution.toolDefinitionHash` and passed to the executor.
   */
  readonly mcpToolDefinitionHash?: string
  /**
   * The full pinned MCP tool definition whose hash is `mcpToolDefinitionHash`.
   * When present on a pin-checked call, `intent.parameters` is validated against
   * its `input_schema` before policy evaluation: an undeclared key, a case/fold
   * variant of a declared key, or a value whose type does not match the schema is
   * `BLOCK` (`parameter_schema`). The presented definition must hash to the pin,
   * so it cannot describe a schema other than the one the grant authorized.
   * Omitting it preserves the prior behaviour (hash pin only, no shape check).
   */
  readonly mcpToolDefinition?: McpToolDefinition
}

const NONE_EXEC = 'none'
const UNHASHABLE_EXEC = 'unhashable'
const TOOL_DEFINITION_PIN = /^sha256:[0-9a-f]{64}$/

/**
 * The runtime tool-definition hash to bind on the receipt and hand to the executor.
 *
 * Bound only on a call the path pin-checks: a target under `mcp/`, or a chain that sets
 * `tool_definition_hash`. On any other call nothing compares the value with a grant, so
 * a receipt must not carry it as if it had been checked. A malformed value is never bound.
 * On a pin-checked call it cannot match the pin, so the path refuses that call.
 */
function boundToolDefinitionHash(input: {
  readonly mcpToolDefinitionHash?: unknown
  readonly chain: readonly { readonly constraints?: { readonly tool_definition_hash?: unknown } }[]
  readonly intent: { readonly target: string }
}): string | undefined {
  const hash = input.mcpToolDefinitionHash
  if (typeof hash !== 'string' || !TOOL_DEFINITION_PIN.test(hash)) return undefined
  const pinned = input.chain.some((delegation) => delegation.constraints?.tool_definition_hash != null)
  return pinned || input.intent.target.startsWith('mcp/') ? hash : undefined
}

function assertToolDefinitionPin(
  chain: readonly { readonly constraints: { readonly tool_definition_hash?: unknown } }[],
  runtimeHash: string | undefined,
  required: boolean
): void {
  const pins: string[] = []
  for (const delegation of chain) {
    const pin = delegation.constraints.tool_definition_hash
    if (pin == null) continue
    if (typeof pin !== 'string' || !TOOL_DEFINITION_PIN.test(pin)) {
      throw new AuthorityError('tool_definition', 'tool definition pin is malformed', true)
    }
    pins.push(pin)
  }
  if (pins.length === 0) {
    if (required) {
      throw new AuthorityError('tool_definition', 'tool definition pin is required', true)
    }
    return
  }
  if (pins.some((pin) => pin !== pins[0])) {
    throw new AuthorityError('tool_definition', 'tool definition pin mismatch', true)
  }
  if (runtimeHash !== pins[0]) {
    throw new AuthorityError('tool_definition', 'tool definition pin mismatch', true)
  }
}

function assertMcpAuthority(
  intent: { readonly action: string; readonly target: string },
  chain: readonly { readonly constraints: { readonly tool_definition_hash?: unknown } }[],
  runtimeHash: string | undefined
): void {
  const call = authorityMcpCall(intent.action, intent.target)
  if (call.kind === 'malformed') {
    throw new AuthorityError('mcp_binding', call.reason, true)
  }
  assertToolDefinitionPin(chain, runtimeHash, call.kind === 'call')
}

/**
 * When the runtime presents the full pinned tool definition, enforce its
 * `input_schema` against `intent.parameters`. Runs only on a pin-checked call
 * (a chain that sets `tool_definition_hash`, or an `mcp/` target), so callers
 * that do not pass a definition are unaffected. The presented definition must
 * hash to the presented pin, so it cannot stand in for a different schema.
 */
function assertParametersConformToPin(
  intent: { readonly target: string; readonly parameters: Readonly<Record<string, unknown>> },
  chain: readonly { readonly constraints?: { readonly tool_definition_hash?: unknown } }[],
  definition: McpToolDefinition | undefined,
  runtimeHash: string | undefined,
): void {
  if (definition === undefined) return
  const pinRelevant =
    intent.target.startsWith('mcp/') ||
    chain.some((delegation) => delegation.constraints?.tool_definition_hash != null)
  if (!pinRelevant) return
  const definitionHash = hashMcpToolDefinition(definition)
  if (runtimeHash !== undefined && runtimeHash !== definitionHash) {
    throw new AuthorityError('tool_definition', 'presented tool definition does not match its hash', true)
  }
  validateParametersAgainstSchema(intent.parameters, definition.input_schema, 'parameters')
}

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
  /** True while verifying a human approval against an already-reserved pending nonce. */
  let pendingApprovalContinuation = false

  const issuedAtSkewMs = input.issuedAtSkewMs ?? 0
  if (
    typeof issuedAtSkewMs !== 'number' ||
    !Number.isSafeInteger(issuedAtSkewMs) ||
    issuedAtSkewMs < 0 ||
    issuedAtSkewMs > MAX_ISSUED_AT_SKEW_MS
  ) {
    return unauthenticatedRejection(
      new AuthorityError(
        'clock',
        `issuedAtSkewMs must be an integer from 0 to ${MAX_ISSUED_AT_SKEW_MS}`,
        false
      )
    )
  }

  try {
    now = resolveTrustedNow(input)
    if (!hasResolver(input.policyResolver)) {
      throw new AuthorityError('policy', 'a trusted policy resolver is required', false)
    }
    presented = presentAuthority({
      chain: input.chain,
      intent: input.intent,
      directory: input.directory,
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

    assertMcpAuthority(presented.intent, presented.chain, input.mcpToolDefinitionHash)
    assertParametersConformToPin(presented.intent, presented.chain, input.mcpToolDefinition, input.mcpToolDefinitionHash)

    const usability = await input.ledger.assertUsable(
      presented.intent.actor,
      presented.intent.nonce,
      intentHash
    )
    const verified = authorizePresented({
      chain: presented.chain,
      intent: presented.intent,
      now,
      issuedAtSkewMs,
    })

    const devBypass = input.unsafeDevAllowUnconfiguredChecks === true
    if (!devBypass && !input.audience) {
      throw new AuthorityError('audience', 'AUDIENCE_MISMATCH', true)
    }
    if (input.audience) {
      const audience = input.audience
      for (const delegation of verified.chain) {
        if (delegation.aud !== audience) {
          throw new AuthorityError('audience', 'AUDIENCE_MISMATCH', true)
        }
      }
      if (verified.intent.aud !== audience) {
        throw new AuthorityError('audience', 'AUDIENCE_MISMATCH', true)
      }
      if (input.approval && input.approval.aud !== audience) {
        throw new AuthorityError('audience', 'AUDIENCE_MISMATCH', true)
      }
    }
    if (!devBypass && !input.rootAuthority) {
      throw new AuthorityError('root_not_authorized', 'root authority is required', true)
    }
    if (!devBypass && !input.revocationCheck) {
      throw new AuthorityError('revoked', 'revocation check is required', true)
    }

    const root = verified.chain[0]
    if (root && !root.parent_delegation_id) {
      if (
        root.issuer === root.subject &&
        input.rootAuthority?.allowSelfIssuedRoot !== true
      ) {
        throw new AuthorityError(
          'root_not_authorized',
          'self-issued root not allowed',
          true
        )
      }
      if (input.rootAuthority) {
        const allowed = input.rootAuthority.mayIssueRoot({
          issuerId: root.issuer,
          subjectId: root.subject,
          capabilities: root.capabilities.map((capability) => ({
            action: capability.action,
            target: capability.target ?? '',
          })),
        })
        if (!allowed) {
          throw new AuthorityError(
            'root_not_authorized',
            'root issuer is not authorized for this grant',
            true
          )
        }
      }
    }
    if (input.revocationCheck) {
      for (const delegation of verified.chain) {
        const status = await input.revocationCheck(delegation.delegation_id)
        if (status === 'revoked') {
          throw new AuthorityError('revoked', `delegation ${delegation.delegation_id} is revoked`, true)
        }
        if (status === 'unavailable') {
          throw new AuthorityError('revoked', 'revocation status unavailable', true)
        }
      }
    }
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

      const pending = await pendingStore.get(verified.intent.actor, verified.intent.nonce)
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
        toolTarget: verified.intent.target,
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

      if (input.approvalPolicy?.isHuman && !input.approvalPolicy.isHuman(input.approval.approver_id)) {
        throw new AuthorityError('approval', 'approver is not a human identity', true)
      }
      if (input.approvalPolicy?.allowSelfApproval !== true) {
        const approverId = input.approval.approver_id
        const subjects = new Set(verified.chain.map((delegation) => delegation.subject))
        if (subjects.has(approverId) || approverId === verified.intent.actor) {
          throw new AuthorityError('approval', 'approver cannot approve their own agent action', true)
        }
      }

      const humanDecision = input.approval.decision
      const authorityProfile = assertChainProfileConsistency(verified.chain)
      // From here through verifyHumanApproval, schema/identity/profile/signature
      // failures must not retire the reserved pending nonce (#25).
      pendingApprovalContinuation = true
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
        expectedDecision: humanDecision === 'DENY' ? 'DENY' : 'APPROVE',
        authorityProfile,
        requireApproverKind: input.unsafeDevAllowUnconfiguredChecks !== true,
      })
      pendingApprovalContinuation = false

      if (humanDecision === 'DENY') {
        await pendingStore.markDeclined(verified.intent.actor, verified.intent.nonce, intentHash)
        await input.ledger.consume(verified.intent.actor, verified.intent.nonce, intentHash)
        return seal(
          { ...view, policy },
          {
            decision: 'BLOCK',
            ruleId: pending.matchedRuleId,
            reason: 'human denied the authorization',
            alertSeverity: policyDecision.alertSeverity,
            matched: true,
            intentHash,
            delegationHash,
            policyHash,
            executed: false,
            failureMode: 'RULE_VIOLATION',
            principalId,
            human: {
              required: true,
              status: 'declined',
              approverId: input.approval.approver_id,
              decidedAt: input.approval.approved_at,
            },
          }
        )
      }

      await pendingStore.markApproved(verified.intent.actor, verified.intent.nonce, intentHash)

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
      toolTarget: verified.intent.target,
    })

    // Only ALLOW reaches executeBound. REQUIRE_HUMAN pauses. Every other
    // action, including one the v0.1 schema cannot produce, is BLOCK.
    if (
      policyDecision.action === 'BLOCK' ||
      (policyDecision.action !== 'ALLOW' && policyDecision.action !== 'REQUIRE_HUMAN')
    ) {
      await input.ledger.consume(verified.intent.actor, verified.intent.nonce, intentHash)
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
      try {
        await pendingStore.put(
          {
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
          },
          {
            maxPendingApprovals: input.maxPendingApprovals ?? DEFAULT_MAX_PENDING_APPROVALS,
            now,
          }
        )
      } catch (error) {
        if (error instanceof AuthorityError && error.code === 'approval_queue_full') {
          return seal(
            { ...view, policy },
            {
              decision: 'BLOCK',
              ruleId: 'approval_queue_full',
              reason: 'pending approval queue is full',
              alertSeverity: 'CRITICAL',
              matched: true,
              intentHash,
              delegationHash,
              policyHash,
              executed: false,
              failureMode: 'RULE_VIOLATION',
              principalId,
            }
          )
        }
        throw error
      }
      await input.ledger.reserve(verified.intent.actor, verified.intent.nonce, intentHash)
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
      // Do not burn a reserved pending nonce for unauthenticated / pre-crypto
      // approval failures (schema, identity, profile, signature). Those codes
      // are otherwise authenticated=true so a malformed approval could DoS the
      // pending queue (#25). Binding failures use code `approval` and are also
      // preserved; replay is preserved so the real consumer stays recorded.
      const preservePendingNonce =
        pendingApprovalContinuation &&
        (error.code === 'schema' ||
          error.code === 'identity' ||
          error.code === 'profile' ||
          error.code === 'signature')
      if (
        error.authenticated &&
        error.code !== 'replay' &&
        error.code !== 'approval' &&
        !preservePendingNonce
      ) {
        await retireNonce(input.ledger, presented.intent.actor, presented.intent.nonce, intentHash)
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
    await retireNonce(input.ledger, presented.intent.actor, presented.intent.nonce, intentHash)
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

async function retireNonce(
  ledger: NonceStore,
  actorId: string,
  nonce: string,
  intentHash: string
): Promise<void> {
  try {
    await ledger.consume(actorId, nonce, intentHash)
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
    await input.ledger.consume(input.intent.actor, input.intent.nonce, bound.intentHash)
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
    await input.ledger.consume(input.intent.actor, input.intent.nonce, bound.intentHash)
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

  await chargeCumulativeSpend({
    chain: input.chain,
    parameters: input.intent.parameters,
    intentHash: bound.intentHash,
    ledger: input.spendLedger,
  })

  const presentedHash = sha256(unsignedIntent(input.intent))
  if (
    presentedHash !== bound.intentHash ||
    (input.approval != null && input.approval.intent_hash !== bound.intentHash)
  ) {
    await input.ledger.consume(input.intent.actor, input.intent.nonce, bound.intentHash)
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
    await input.ledger.claimForExecution(input.intent.actor, input.intent.nonce, bound.intentHash)
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

  const toolDefinitionHash = boundToolDefinitionHash(input)
  const ctx: ExecutionContext = {
    ...(toolDefinitionHash !== undefined ? { toolDefinitionHash } : {}),
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
  } catch (error) {
    // The executor was invoked. Authority already allowed dispatch, and a
    // downstream side effect cannot be ruled out. This matches
    // ExecutionOutcomeUnknownError: ALLOW, outcome unknown, executed false,
    // SYSTEM_ERROR. `not_dispatched` is only for a halt before `execute`.
    await input.ledger.consume(input.intent.actor, input.intent.nonce, bound.intentHash)
    return seal(input, {
      decision: 'ALLOW',
      ruleId: bound.decision.ruleId,
      reason:
        error instanceof ExecutionOutcomeUnknownError
          ? 'downstream outcome unknown'
          : 'executor failed after dispatch; downstream outcome is unknown',
      alertSeverity: 'CRITICAL',
      matched: bound.decision.matched,
      intentHash: bound.intentHash,
      delegationHash: bound.delegationHash,
      policyHash: bound.policyHash,
      executed: false,
      failureMode: 'SYSTEM_ERROR',
      principalId: bound.principalId,
      executionOutcome: 'unknown',
    })
  }

  // The callback returned. A later store or seal failure does not rewrite that as
  // "nothing executed". The nonce is still spent so the same intent cannot retry.
  try {
    await input.ledger.consume(input.intent.actor, input.intent.nonce, bound.intentHash)
  } catch {
    // The claim already spent exclusivity. A consume race must not escape.
  }
  try {
    await input.pendingStore?.consume(input.intent.actor, input.intent.nonce, bound.intentHash)
  } catch {
    // Pending consume is bookkeeping after the side-effect boundary.
  }

  try {
    return seal(input, {
      decision: 'ALLOW',
      ruleId: bound.decision.ruleId,
      reason: bound.approved
        ? `Human approval bound to intent ${bound.intentHash}`
        : bound.decision.reason,
      alertSeverity: bound.decision.alertSeverity,
      matched: bound.decision.matched,
      intentHash: bound.intentHash,
      delegationHash: bound.delegationHash,
      policyHash: bound.policyHash,
      executed: true,
      result,
      failureMode: 'NONE',
      principalId: bound.principalId,
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
      reason: bound.approved
        ? `Human approval bound to intent ${bound.intentHash}`
        : bound.decision.reason,
      intentHash: bound.intentHash,
      delegationHash: bound.delegationHash,
      policyHash: bound.policyHash,
      executionHash: UNHASHABLE_EXEC,
      executed: true,
      authenticated: true,
      result,
    }
  }
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
    readonly executionOutcome?: 'not_dispatched' | 'returned' | 'unknown' | 'failed_after_dispatch'
  }
): ProtocolResult {
  const decidedAt = (input.now ?? resolveTrustedNow(input)).toISOString()
  const toolDefinitionHash = boundToolDefinitionHash(input)
  const policy = input.policy
  const executionHash = fields.executed ? sha256(fields.result ?? null) : NONE_EXEC
  const toolArgs = deepDataClone(input.intent.parameters) as Record<string, unknown>
  const receipt = emitAuthorizationReceipt({
    agentId: input.intent.actor,
    toolName: input.intent.action,
    toolArgs,
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
    // A unique per-emission suffix. The same intent can produce more than one receipt
    // (for example two refusals), and those receipts must not share a receiptId, or a
    // receipt log fails verifyReceiptChain's duplicate-receiptId check (#62). The readable
    // intent/decision prefix is kept; the random tail matches emitAuthorizationReceipt.
    receiptId: `rcpt_${fields.intentHash.slice(0, 20)}_${fields.executed ? 'exec' : fields.decision.toLowerCase()}_${randomBytes(6).toString('hex')}`,
    execution: {
      targetSystem: input.intent.target,
      executed: fields.executionOutcome === 'unknown' ? false : fields.executed,
      executedAt: fields.executed && fields.executionOutcome !== 'unknown' ? decidedAt : undefined,
      intentHash: fields.intentHash,
      outcome: fields.executionOutcome ?? (fields.executed ? 'returned' : 'not_dispatched'),
      ...(toolDefinitionHash !== undefined ? { toolDefinitionHash } : {}),
    },
    human: fields.human,
    failureMode: fields.failureMode,
    sequence: input.receiptSequence,
    prevReceiptHash: input.prevReceiptHash,
    extensions: {
      checks_applied: {
        root_authority: Boolean(input.rootAuthority) && input.unsafeDevAllowUnconfiguredChecks !== true,
        revocation_check: Boolean(input.revocationCheck) && input.unsafeDevAllowUnconfiguredChecks !== true,
        human_approver_kind: input.unsafeDevAllowUnconfiguredChecks !== true,
        no_self_approval: input.approvalPolicy?.allowSelfApproval !== true,
        approval_policy: Boolean(input.approvalPolicy),
        parameter_schema: toolDefinitionHash !== undefined && input.mcpToolDefinition != null,
        unsafe_dev_unconfigured_checks: input.unsafeDevAllowUnconfiguredChecks === true,
      },
      enforcement_mode: input.enforcementMode ?? 'in_process',
      credential_boundary: input.credentialBoundary ?? 'caller_supplied',
      ...(input.issuedAtSkewMs != null && input.issuedAtSkewMs > 0
        ? { issuedAtSkewMs: input.issuedAtSkewMs }
        : {}),
    },
    signer: input.signer.privateKey,
    includeArgsUnredacted: input.includeArgsUnredacted === true,
    argsRedactedAllowlist: input.argsRedactedAllowlist,
  })
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
  const errors = structure.errors.filter((item) => item !== 'MISSING_PUBLIC_KEY')
  if (!signatureOk) errors.push('ed25519 signature invalid')
  return {
    valid: structure.structureOk && structure.contentHashOk && !structure.demoSignature && signatureOk,
    errors,
  }
}

export { ImmutablePolicyResolver, PendingAuthorizationStore }
