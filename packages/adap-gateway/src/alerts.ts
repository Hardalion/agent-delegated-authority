import type { SecurityEvent, SecurityEventSink, SecurityEventType } from './events.js'

const ALERT_TYPES = new Set<SecurityEventType>([
  'replay.attempt',
  'storage.failure',
  'execution.outcome_unknown',
  'credential.broker_failure',
  'signature.invalid',
  'receipt.verify_failure',
])

export class AlertingEventSink implements SecurityEventSink {
  constructor(
    private readonly inner: SecurityEventSink,
    private readonly webhookUrl: string | undefined,
    private readonly replica: string,
  ) {}

  emit(event: SecurityEvent): void {
    this.inner.emit(event)
    if (!this.webhookUrl || !ALERT_TYPES.has(event.type)) return
    const body = JSON.stringify({
      alert: event.type,
      correlationId: event.correlationId,
      replica: this.replica,
      intentHash: event.intentHash ?? null,
      timestamp: event.timestamp,
    })
    void fetch(this.webhookUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
      signal: AbortSignal.timeout(2_000),
    }).catch(() => {
      console.error(JSON.stringify({
        channel: 'adap.security',
        type: 'alert.delivery_failed',
        correlationId: event.correlationId,
        replica: this.replica,
      }))
    })
  }
}
