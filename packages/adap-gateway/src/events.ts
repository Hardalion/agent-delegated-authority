export type ExecutionKnowledge =
  | 'started'
  | 'accepted'
  | 'completed'
  | 'failed'
  | 'unknown'
  | 'reconciled'

export type SecurityEventType =
  | 'authorization.allow'
  | 'authorization.require_human'
  | 'authorization.block'
  | 'signature.invalid'
  | 'replay.attempt'
  | 'policy.mismatch'
  | 'approval.accepted'
  | 'approval.rejected'
  | 'approval.expired'
  | 'nonce.conflict'
  | 'execution.started'
  | 'execution.completed'
  | 'execution.failed'
  | 'execution.outcome_unknown'
  | 'receipt.verify_failure'
  | 'admin.policy_change'
  | 'key.rotation'
  | 'storage.failure'
  | 'credential.broker_failure'

export interface SecurityEvent {
  readonly type: SecurityEventType
  readonly timestamp: string
  readonly correlationId: string
  readonly tenantId?: string
  readonly intentHash?: string
  readonly decision?: string
  readonly reason?: string
  readonly details?: Readonly<Record<string, string | number | boolean | null>>
}

export interface SecurityEventSink {
  emit(event: SecurityEvent): void
}

/** Structured JSON logs. Never attach raw parameters or secrets. */
export class JsonSecurityEventSink implements SecurityEventSink {
  emit(event: SecurityEvent): void {
    // eslint-disable-next-line no-console
    console.info(JSON.stringify({ channel: 'adap.security', ...event }))
  }
}

export class MemorySecurityEventSink implements SecurityEventSink {
  readonly events: SecurityEvent[] = []
  emit(event: SecurityEvent): void {
    this.events.push(event)
  }
}

export function correlationId(): string {
  return `corr_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`
}
