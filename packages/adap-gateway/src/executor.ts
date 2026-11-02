import {
  ExecutionNotDispatchedError,
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

export interface GatewayExecuteResult extends ProtocolResult {
  readonly correlationId: string
  readonly downstream?: DownstreamOutcome
  readonly executionState: ExecutionKnowledge | 'not_started'
}

/**
 * Trusted execution boundary:
 * 1. Run the ADAP authority path.
 * 2. On ALLOW, resolve a credential handle inside the broker.
 * 3. Re-validate canonical action/target against the authorized context.
 * 4. POST only through the broker — agents never see rail credentials.
 */
export async function executeAuthorized(input: GatewayExecuteInput): Promise<GatewayExecuteResult> {
  const corr = correlationId()
  const events = input.events
  let downstream: DownstreamOutcome | undefined
  let executionState: ExecutionKnowledge | 'not_started' = 'not_started'
  let authorizedCtx: ExecutionContext | undefined

  const result = await runAuthorityPath({
    ...input,
    execute: async (ctx) => {
      authorizedCtx = ctx
      const action = canonicalizeAction(ctx.action)
      const target = canonicalizeTarget(ctx.target)
      if (action !== canonicalizeAction(ctx.action) || target !== ctx.target) {
        throw new ExecutionNotDispatchedError('canonicalization mismatch')
      }
      // Reject confused-deputy: parameters frozen from authorized snapshot only
      const parameters = freezeAuthorizedParameters(ctx.parameters)
      let handle: string
      try {
        handle = await input.broker.resolveHandle(action, target)
      } catch {
        events?.emit({
          type: 'credential.broker_failure',
          timestamp: new Date().toISOString(),
          correlationId: corr,
          tenantId: input.tenantId,
          intentHash: ctx.intentHash,
          reason: 'credential broker rejected the route',
        })
        throw new ExecutionNotDispatchedError('credential broker rejected the route')
      }
      // `started` means the broker call is about to leave this process.
      // A failure before this point is not_dispatched, not an in-flight dispatch.
      events?.emit({
        type: 'execution.started',
        timestamp: new Date().toISOString(),
        correlationId: corr,
        tenantId: input.tenantId,
        intentHash: ctx.intentHash,
      })
      await input.onExecutionState?.('started', {
        intentHash: ctx.intentHash,
        correlationId: corr,
      })
      executionState = 'started'
      downstream = await input.broker.execute(handle, {
        action,
        target,
        parameters,
        intentHash: ctx.intentHash,
        correlationId: corr,
      })
      executionState = downstream.status
      try {
        await input.onExecutionState?.(downstream.status, {
          intentHash: ctx.intentHash,
          correlationId: corr,
          detail: 'error' in downstream ? downstream.error : undefined,
        })
      } catch {
        events?.emit({
          type: 'storage.failure',
          timestamp: new Date().toISOString(),
          correlationId: corr,
          tenantId: input.tenantId,
          intentHash: ctx.intentHash,
          reason: 'execution log update failed after the downstream call',
        })
      }
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
        // The broker already left this process. Throwing records outcome unknown
        // and fails the nonce. Returning would seal executed=true.
        throw new Error('downstream_outcome_unknown')
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

  if (result.executionKnowledge === 'not_dispatched' && downstream == null) {
    executionState = 'not_started'
  }

  if (result.executionKnowledge === 'unknown' && downstream?.status !== 'unknown') {
    events?.emit({
      type: 'execution.outcome_unknown',
      timestamp: new Date().toISOString(),
      correlationId: corr,
      intentHash: result.intentHash,
      reason: result.reason,
    })
    executionState = 'unknown'
  }

  if (downstream?.status === 'unknown') {
    executionState = 'unknown'
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

  return { ...result, correlationId: corr, downstream, executionState }
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
