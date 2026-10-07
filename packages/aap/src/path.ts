import type { KeyObject } from 'node:crypto'
import {
  emitAuthorizationReceipt,
  verifyAuthorizationReceipt,
  type AuthorizationReceiptV1,
  type HumanAttestation,
} from 'adap-receipt'
import { evaluateToolCall, type Policy, type PolicyDecision } from 'adap-policy'
import { publicKeyFingerprint, signHex, verifyHex } from './crypto.js'
import { sha256 } from './crypto.js'
import { AuthorityError } from './errors.js'
import { NonceLedger } from './nonce.js'
import type { Decision, HumanApproval, Identity, SignedDelegation, SignedIntent } from './protocol.js'
import { unsignedDelegation, unsignedIntent } from './protocol.js'
import { verifyAuthority, verifyHumanApproval } from './validate.js'

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
  readonly result?: unknown
  readonly receipt: AuthorizationReceiptV1
}

export interface RunAuthorityPathInput {
  readonly chain: readonly SignedDelegation[]
  readonly intent: SignedIntent
  readonly directory: ReadonlyMap<string, string>
  readonly policy: Policy
  readonly policyUri: string
  readonly now: Date
  readonly ledger: NonceLedger
  readonly signer: Identity
  readonly approval?: HumanApproval
  readonly execute?: (ctx: ExecutionContext) => unknown
}

const NONE_EXEC = 'none'

export async function runAuthorityPath(input: RunAuthorityPathInput): Promise<ProtocolResult> {
  const intentHash = sha256(unsignedIntent(input.intent))
  const delegationHash = sha256(input.chain.map(unsignedDelegation))
  const policyHash = sha256(input.policy)
  const principalId = input.chain[0]?.issuer

  try {
    const verified = verifyAuthority({
      chain: input.chain,
      intent: input.intent,
      directory: input.directory,
      now: input.now,
    })
    const usability = input.ledger.assertUsable(verified.intent.nonce, intentHash)
    if (usability === 'pending' && !input.approval) {
      input.ledger.reserve(verified.intent.nonce, intentHash)
    }

    const policyDecision = evaluateToolCall({
      policy: input.policy,
      toolName: verified.intent.action,
      toolArgs: { ...verified.intent.parameters },
      agentRole: verified.intent.actor,
    })

    if (policyDecision.action === 'BLOCK' || (policyDecision.action !== 'ALLOW' && policyDecision.action !== 'REQUIRE_HUMAN')) {
      input.ledger.consume(verified.intent.nonce, intentHash)
      return seal(input, {
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
      })
    }

    if (policyDecision.action === 'REQUIRE_HUMAN' && !input.approval) {
      input.ledger.reserve(verified.intent.nonce, intentHash)
      return seal(input, {
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
      })
    }

    if (policyDecision.action === 'REQUIRE_HUMAN' && input.approval) {
      if (!principalId) throw new AuthorityError('approval', 'missing principal', true)
      verifyHumanApproval({
        approval: input.approval,
        intentHash,
        principalId,
        intent: verified.intentPayload,
        directory: input.directory,
        now: input.now,
      })
    }

    return await executeBound(input, {
      decision: policyDecision,
      intentHash,
      delegationHash,
      policyHash,
      principalId: principalId ?? verified.intent.actor,
      approved: policyDecision.action === 'REQUIRE_HUMAN',
    })
  } catch (error) {
    if (error instanceof AuthorityError) {
      if (error.authenticated && error.code !== 'replay' && error.code !== 'approval') {
        input.ledger.consume(input.intent.nonce, intentHash)
      }
      return seal(input, {
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
    input.ledger.consume(input.intent.nonce, intentHash)
    return seal(input, {
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

async function executeBound(
  input: RunAuthorityPathInput,
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
    input.ledger.consume(input.intent.nonce, bound.intentHash)
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

  const presentedHash = sha256(unsignedIntent(input.intent))
  if (presentedHash !== bound.intentHash || (input.approval != null && input.approval.intent_hash !== bound.intentHash)) {
    input.ledger.consume(input.intent.nonce, bound.intentHash)
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

  const ctx: ExecutionContext = {
    action: input.intent.action,
    target: input.intent.target,
    actor: input.intent.actor,
    principalId: bound.principalId,
    parameters: { ...input.intent.parameters },
    intentHash: bound.intentHash,
  }

  try {
    const result = await input.execute(ctx)
    input.ledger.consume(input.intent.nonce, bound.intentHash)
    return seal(input, {
      decision: 'ALLOW',
      ruleId: bound.decision.ruleId,
      reason: bound.approved ? `Human approval bound to intent ${bound.intentHash}` : bound.decision.reason,
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
    input.ledger.consume(input.intent.nonce, bound.intentHash)
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
}

function seal(
  input: RunAuthorityPathInput,
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
  }
): ProtocolResult {
  const executionHash = fields.executed ? sha256(fields.result ?? null) : NONE_EXEC
  const drafted = emitAuthorizationReceipt({
    agentId: input.intent.actor,
    toolName: input.intent.action,
    toolArgs: { ...input.intent.parameters },
    action: fields.decision,
    ruleId: fields.ruleId,
    reason: fields.reason,
    alertSeverity: fields.alertSeverity,
    matched: fields.matched,
    policyUri: input.policyUri,
    policyName: input.policy.policyName,
    policyVersion: input.policy.version,
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
    decidedAt: input.now.toISOString(),
    receiptId: `rcpt_${fields.intentHash.slice(0, 20)}_${fields.executed ? 'exec' : fields.decision.toLowerCase()}`,
    execution: {
      targetSystem: input.intent.target,
      executed: fields.executed,
      executedAt: fields.executed ? input.now.toISOString() : undefined,
      intentHash: fields.intentHash,
    },
    human: fields.human,
    failureMode: fields.failureMode,
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
    result: fields.result,
    receipt,
  }
}

export function signReceipt(receipt: AuthorizationReceiptV1, privateKey: KeyObject): AuthorizationReceiptV1 {
  const { signature: _signature, ...unsigned } = receipt
  return { ...receipt, signature: signHex(unsigned, privateKey) }
}

export function verifyProtocolReceipt(receipt: AuthorizationReceiptV1, publicKey: KeyObject): {
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
