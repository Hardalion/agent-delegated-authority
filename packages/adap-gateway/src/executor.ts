import {
  runAuthorityPath,
  type ExecutionContext,
  type ProtocolResult,
  type RunAuthorityPathInput,
} from 'adap'
import {
  canonicalizeAction,
  canonicalizeTarget,
  freezeAuthorizedParameters,
} from './canonicalize.js'
import type { CredentialBroker, DownstreamOutcome } from './credentials.js'
import { correlationId, type SecurityEventSink, type ExecutionKnowledge } from './events.js'

export interface GatewayExecuteInput extends Omit<RunAuthorityPathInput, 'execute'> {
  readonly broker: CredentialBroker
  readonly events?: SecurityEventSink
  readonly tenantId?: string
  /** Called before the downstream POST and again when the outcome is known. */
  readonly onExecutionState?: (
    state: ExecutionKnowledge,
    info: { readonly intentHash: string; readonly correlationId: string; readonly detail?: string },
  ) => Promise<void>
}

/**
 * Whether the execution-state callback confirmed the write.
 * `not_configured` means `onExecutionState` was omitted.
 * `confirmed` means every callback that ran succeeded.
 * `failed` means a callback threw. A failure before the downstream call
 * prevents that call. A failure after it does not hide the downstream result
 * and does not repeat the call.
 */
export type ExecutionStatePersistence = 'not_configured' | 'confirmed' | 'failed'

export interface GatewayExecuteResult extends ProtocolResult {
  readonly correlationId: string
  readonly downstream?: DownstreamOutcome
  readonly executionState: ExecutionKnowledge | 'not_started'
  readonly executionStatePersistence: ExecutionStatePersistence
}

/**
 * Trusted execution boundary:
 * 1. Run the ADAP authority path.
 * 2. On ALLOW, resolve a credential handle inside the broker.
 * 3. Refuse the call unless the authorized action and target are already canonical.
 * 4. POST only through the broker — agents never see rail credentials.
 */
export async function executeAuthorized(input: GatewayExecuteInput): Promise<GatewayExecuteResult> {
  const corr = correlationId()
  const events = input.events
  let downstream: DownstreamOutcome | undefined
  let executionState: ExecutionKnowledge | 'not_started' = 'not_started'
  let executionStatePersistence: ExecutionStatePersistence = input.onExecutionState
    ? 'confirmed'
    : 'not_configured'
  let authorizedCtx: ExecutionContext | undefined

  const persistExecutionState = async (
    state: ExecutionKnowledge,
    info: { readonly intentHash: string; readonly correlationId: string; readonly detail?: string },
    phase: 'before' | 'after',
  ): Promise<void> => {
    if (!input.onExecutionState) return
    try {
      await input.onExecutionState(state, info)
    } catch {
      executionStatePersistence = 'failed'
      events?.emit({
        type: 'storage.failure',
        timestamp: new Date().toISOString(),
        correlationId: corr,
        tenantId: input.tenantId,
        intentHash: info.intentHash,
        reason:
          phase === 'before'
            ? 'execution log update failed before the downstream call'
            : 'execution log update failed after the downstream call',
      })
      if (phase === 'before') {
        throw new Error('execution state persistence failed before the downstream call')
      }
    }
  }

  const result = await runAuthorityPath({
    ...input,
    execute: async (ctx) => {
      authorizedCtx = ctx
      let action: string
      let target: string
      try {
        action = canonicalizeAction(ctx.action)
        target = canonicalizeTarget(ctx.target)
      } catch {
        throw new Error('canonicalization mismatch')
      }
      // The authorized action is executed as signed. Folding case or trimming
      // would run a different action than the one the authority path allowed.
      if (ctx.action !== action || ctx.target !== target) {
        throw new Error('canonicalization mismatch')
      }
      // Reject confused-deputy: parameters frozen from authorized snapshot only
      const parameters = freezeAuthorizedParameters(ctx.parameters)
      events?.emit({
        type: 'execution.started',
        timestamp: new Date().toISOString(),
        correlationId: corr,
        tenantId: input.tenantId,
        intentHash: ctx.intentHash,
      })
      await persistExecutionState(
        'started',
        {
          intentHash: ctx.intentHash,
          correlationId: corr,
        },
        'before',
      )
      executionState = 'started'
      let handle: string
      try {
        handle = await input.broker.resolveHandle(action, target)
      } catch (error) {
        events?.emit({
          type: 'credential.broker_failure',
          timestamp: new Date().toISOString(),
          correlationId: corr,
          tenantId: input.tenantId,
          intentHash: ctx.intentHash,
          reason: 'credential broker rejected the route',
        })
        throw error
      }
      downstream = await input.broker.execute(handle, {
        action,
        target,
        parameters,
        intentHash: ctx.intentHash,
        correlationId: corr,
      })
      executionState = downstream.status
      await persistExecutionState(
        downstream.status,
        {
          intentHash: ctx.intentHash,
          correlationId: corr,
          detail: 'error' in downstream ? downstream.error : undefined,
        },
        'after',
      )
      if (downstream.status === 'failed') {
        events?.emit({
          type: 'execution.failed',
          timestamp: new Date().toISOString(),
          correlationId: corr,
          intentHash: ctx.intentHash,
          reason: downstream.error,
        })
        throw new Error('downstream_failed')
      }
      if (downstream.status === 'unknown') {
        events?.emit({
          type: 'execution.outcome_unknown',
          timestamp: new Date().toISOString(),
          correlationId: corr,
          intentHash: ctx.intentHash,
          reason: downstream.error,
        })
        // Return, do not throw. The nonce is consumed so the same intent cannot be
        // retried. The result states that the downstream outcome is unknown.
        return {
          executionState: 'unknown',
          correlationId: corr,
          error: downstream.error,
        }
      }
      events?.emit({
        type: downstream.status === 'accepted' ? 'execution.completed' : 'execution.completed',
        timestamp: new Date().toISOString(),
        correlationId: corr,
        intentHash: ctx.intentHash,
      })
      return {
        executionState: downstream.status,
        correlationId: corr,
        authorized: { action, target, intentHash: ctx.intentHash },
      }
    },
  })

  if (downstream?.status === 'unknown') {
    // outcome_unknown already emitted
  } else if (result.decision === 'ALLOW' && result.executed) {
    events?.emit({
      type: 'authorization.allow',
      timestamp: new Date().toISOString(),
      correlationId: corr,
      intentHash: result.intentHash,
      decision: result.decision,
    })
  } else if (result.decision === 'REQUIRE_HUMAN') {
    events?.emit({
      type: 'authorization.require_human',
      timestamp: new Date().toISOString(),
      correlationId: corr,
      intentHash: result.intentHash,
      decision: result.decision,
    })
  } else if (result.decision === 'BLOCK') {
    const type =
      result.reason.includes('nonce') || result.reason.includes('replay')
        ? 'replay.attempt'
        : result.authenticated
          ? 'authorization.block'
          : 'signature.invalid'
    events?.emit({
      type,
      timestamp: new Date().toISOString(),
      correlationId: corr,
      intentHash: result.intentHash || undefined,
      decision: result.decision,
      reason: result.reason,
    })
  }

  // Ensure no caller can mutate the authorized context object afterward
  if (authorizedCtx) {
    Object.freeze(authorizedCtx)
  }

  return { ...result, correlationId: corr, downstream, executionState, executionStatePersistence }
}

/**
 * Bypass attempt helper for tests: trying to call the broker with a forged
 * context that was not produced by runAuthorityPath must still resolve only
 * registered routes — and production networks must not expose writeUrl to agents.
 */
export async function attemptDirectBrokerExecute(
  broker: CredentialBroker,
  action: string,
  target: string,
  parameters: Record<string, unknown>,
): Promise<DownstreamOutcome> {
  const handle = await broker.resolveHandle(action, target)
  return broker.execute(handle, {
    action: canonicalizeAction(action),
    target: canonicalizeTarget(target),
    parameters: freezeAuthorizedParameters(parameters),
    intentHash: 'forged',
    correlationId: correlationId(),
  })
}
