import type { Pool } from './pool.js'

export type ExecutionKnowledge =
  | 'started'
  | 'accepted'
  | 'completed'
  | 'failed'
  | 'unknown'
  | 'reconciled'

const PREDECESSORS: Record<ExecutionKnowledge, readonly ExecutionKnowledge[]> = {
  started: [],
  accepted: ['started'],
  completed: ['started', 'accepted'],
  failed: ['started', 'accepted'],
  unknown: ['started', 'accepted'],
  reconciled: ['unknown', 'started'],
}

export function predecessorsOf(state: ExecutionKnowledge): readonly ExecutionKnowledge[] {
  return PREDECESSORS[state]
}

export interface ExecutionLogRecord {
  readonly intentHash: string
  readonly nonce: string
  readonly correlationId: string
  readonly state: ExecutionKnowledge
  readonly detail: string | null
}

/**
 * Durable record of what the gateway actually knows about a downstream call.
 * Transitions are one-way. A failed transition does not authorize another POST.
 */
export class PostgresExecutionLog {
  constructor(
    private readonly pool: Pool,
    private readonly tenantId = 'default',
  ) {}

  async get(intentHash: string): Promise<ExecutionLogRecord | undefined> {
    const { rows } = await this.pool.query<{
      intent_hash: string
      nonce: string
      correlation_id: string
      state: ExecutionKnowledge
      detail: string | null
    }>(
      `SELECT intent_hash, nonce, correlation_id, state, detail
       FROM adap_execution_log
       WHERE tenant_id = $1 AND intent_hash = $2`,
      [this.tenantId, intentHash],
    )
    const row = rows[0]
    if (!row) return undefined
    return {
      intentHash: row.intent_hash,
      nonce: row.nonce,
      correlationId: row.correlation_id,
      state: row.state,
      detail: row.detail,
    }
  }

  async record(input: {
    readonly intentHash: string
    readonly nonce: string
    readonly correlationId: string
    readonly state: ExecutionKnowledge
    readonly detail?: string
  }): Promise<void> {
    if (input.state === 'started') {
      const inserted = await this.pool.query(
        `INSERT INTO adap_execution_log
           (tenant_id, intent_hash, nonce, correlation_id, state, detail)
         VALUES ($1, $2, $3, $4, 'started', $5)
         ON CONFLICT (tenant_id, intent_hash) DO NOTHING
         RETURNING intent_hash`,
        [this.tenantId, input.intentHash, input.nonce, input.correlationId, input.detail ?? null],
      )
      if ((inserted.rowCount ?? 0) === 1) return
      const current = await this.get(input.intentHash)
      if (current?.state === 'started') return
      throw new Error('execution log refused to restart an existing attempt')
    }

    const allowed = PREDECESSORS[input.state]
    const updated = await this.pool.query(
      `UPDATE adap_execution_log
       SET state = $3, detail = $4, updated_at = now()
       WHERE tenant_id = $1
         AND intent_hash = $2
         AND state = ANY($5::text[])
       RETURNING intent_hash`,
      [this.tenantId, input.intentHash, input.state, input.detail ?? null, allowed],
    )
    if ((updated.rowCount ?? 0) !== 1) {
      throw new Error(`execution log refused transition to ${input.state}`)
    }
  }
}
