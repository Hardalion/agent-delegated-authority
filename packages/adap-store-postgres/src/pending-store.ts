import {
  AuthorityError,
  DEFAULT_MAX_PENDING_APPROVALS,
  assertValidIdentity,
  assertValidNonce,
  type PendingAuthorization,
  type PendingContinuation,
  type PendingPutOptions,
  type PendingStore,
} from 'adap'
import type { Pool } from './pool.js'

export interface PostgresPendingStoreOptions {
  readonly pool: Pool
  readonly tenantId?: string
  readonly maxPendingApprovals?: number
}

type PendingRow = {
  nonce: string
  intent_hash: string
  principal_id: string
  agent_id: string
  actor_id: string
  delegation_chain_hash: string
  policy_uri: string
  policy_content_hash: string
  policy_version: string
  policy_name: string
  matched_rule_id: string
  original_decision: 'REQUIRE_HUMAN'
  approval_state: 'pending' | 'approved' | 'declined' | 'consumed' | 'expired'
  expiry: Date
  approver_id: string
}

function fromRow(row: PendingRow): PendingAuthorization {
  return {
    nonce: row.nonce,
    intentHash: row.intent_hash,
    principalId: row.principal_id,
    agentId: row.agent_id,
    delegationChainHash: row.delegation_chain_hash,
    policyUri: row.policy_uri,
    policyContentHash: row.policy_content_hash,
    policyVersion: row.policy_version,
    policyName: row.policy_name,
    matchedRuleId: row.matched_rule_id,
    originalDecision: row.original_decision,
    approvalState: row.approval_state,
    expiry: row.expiry.toISOString(),
    approverId: row.approver_id,
  }
}

/**
 * Durable pending REQUIRE_HUMAN store with actor-scoped keys and an atomic
 * per-(principal, agent) queue cap.
 *
 * Queue enforcement: a single transaction locks the principal/agent queue via
 * `SELECT … FOR UPDATE` on active pending rows, expires stale ones, counts,
 * then inserts. Concurrent gateway instances sharing this database cannot
 * exceed the cap.
 */
export class PostgresPendingStore implements PendingStore {
  private readonly pool: Pool
  private readonly tenantId: string
  private readonly maxPendingApprovals: number

  constructor(options: PostgresPendingStoreOptions) {
    this.pool = options.pool
    this.tenantId = options.tenantId ?? 'default'
    this.maxPendingApprovals = options.maxPendingApprovals ?? DEFAULT_MAX_PENDING_APPROVALS
  }

  async put(record: PendingAuthorization, options?: PendingPutOptions): Promise<void> {
    const actorId = assertValidIdentity(record.agentId, 'pending.agentId')
    const nonce = assertValidNonce(record.nonce)
    const approverId = assertValidIdentity(record.approverId, 'pending.approverId')
    const max = options?.maxPendingApprovals ?? this.maxPendingApprovals
    const now = options?.now ?? new Date()

    const existing = await this.get(actorId, nonce)
    if (existing) {
      if (
        existing.intentHash !== record.intentHash ||
        existing.approvalState !== 'pending' ||
        existing.policyContentHash !== record.policyContentHash
      ) {
        throw new AuthorityError('approval', 'pending authorization conflict for nonce', true)
      }
      return
    }

    const client = await this.pool.connect()
    try {
      await client.query('BEGIN')
      // Advisory lock covers the empty-queue case where FOR UPDATE would lock no rows.
      // Use a printable separator; Postgres rejects NUL in text parameters.
      await client.query(
        `SELECT pg_advisory_xact_lock(
           hashtextextended($1 || E'\\x1f' || $2 || E'\\x1f' || $3, 0)
         )`,
        [this.tenantId, record.principalId, record.agentId],
      )
      // Expire stale pending rows for this principal/agent so they do not consume capacity.
      await client.query(
        `UPDATE adap_pending
         SET approval_state = 'expired', updated_at = now()
         WHERE tenant_id = $1
           AND principal_id = $2
           AND agent_id = $3
           AND approval_state = 'pending'
           AND expiry <= $4`,
        [this.tenantId, record.principalId, record.agentId, now],
      )
      // Serialize concurrent queue checks for this principal/agent pair.
      await client.query(
        `SELECT nonce FROM adap_pending
         WHERE tenant_id = $1
           AND principal_id = $2
           AND agent_id = $3
           AND approval_state = 'pending'
           AND expiry > $4
         FOR UPDATE`,
        [this.tenantId, record.principalId, record.agentId, now],
      )
      const countResult = await client.query<{ count: string }>(
        `SELECT COUNT(*)::text AS count FROM adap_pending
         WHERE tenant_id = $1
           AND principal_id = $2
           AND agent_id = $3
           AND approval_state = 'pending'
           AND expiry > $4`,
        [this.tenantId, record.principalId, record.agentId, now],
      )
      const active = Number(countResult.rows[0]?.count ?? '0')
      if (active >= max) {
        await client.query('ROLLBACK')
        throw new AuthorityError('approval_queue_full', 'pending approval queue is full', true)
      }
      await client.query(
        `INSERT INTO adap_pending (
           nonce, actor_id, intent_hash, principal_id, agent_id, delegation_chain_hash,
           policy_uri, policy_content_hash, policy_version, policy_name,
           matched_rule_id, original_decision, approval_state, expiry, approver_id, tenant_id
         ) VALUES (
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'REQUIRE_HUMAN','pending',$12,$13,$14
         )`,
        [
          nonce,
          actorId,
          record.intentHash,
          record.principalId,
          record.agentId,
          record.delegationChainHash,
          record.policyUri,
          record.policyContentHash,
          record.policyVersion,
          record.policyName,
          record.matchedRuleId,
          new Date(record.expiry),
          approverId,
          this.tenantId,
        ],
      )
      await client.query('COMMIT')
    } catch (err) {
      try {
        await client.query('ROLLBACK')
      } catch {
        // ignore
      }
      if (err instanceof AuthorityError) throw err
      const code = typeof err === 'object' && err && 'code' in err ? String((err as { code: unknown }).code) : ''
      if (code === '23505') {
        throw new AuthorityError('approval', 'pending authorization conflict for nonce', true)
      }
      throw err
    } finally {
      client.release()
    }
  }

  async get(actorId: string, nonce: string): Promise<PendingAuthorization | undefined> {
    const key = assertValidNonce(nonce)
    const actor = assertValidIdentity(actorId, 'pending.agentId')
    const { rows } = await this.pool.query<PendingRow>(
      `SELECT nonce, intent_hash, principal_id, agent_id, actor_id, delegation_chain_hash,
              policy_uri, policy_content_hash, policy_version, policy_name,
              matched_rule_id, original_decision, approval_state, expiry, approver_id
       FROM adap_pending
       WHERE nonce = $1 AND tenant_id = $2 AND actor_id = $3`,
      [key, this.tenantId, actor],
    )
    return rows[0] ? fromRow(rows[0]) : undefined
  }

  async requireContinuation(input: PendingContinuation): Promise<PendingAuthorization> {
    const record = await this.get(input.agentId, input.nonce)
    if (!record) {
      throw new AuthorityError('approval', 'no pending authorization for this nonce', true)
    }
    if (record.approvalState === 'pending' && Date.parse(record.expiry) <= input.now.getTime()) {
      await this.pool.query(
        `UPDATE adap_pending SET approval_state = 'expired', updated_at = now()
         WHERE nonce = $1 AND tenant_id = $2 AND actor_id = $3 AND approval_state = 'pending'`,
        [record.nonce, this.tenantId, input.agentId],
      )
      throw new AuthorityError('approval', 'pending authorization expired', true)
    }
    if (record.approvalState !== 'pending') {
      throw new AuthorityError('approval', 'pending authorization is not open', true)
    }
    const checks: Array<[unknown, unknown, string]> = [
      [record.intentHash, input.intentHash, 'intent hash'],
      [record.principalId, input.principalId, 'principal'],
      [record.agentId, input.agentId, 'agent'],
      [record.delegationChainHash, input.delegationChainHash, 'delegation chain'],
      [record.policyUri, input.policyUri, 'policy URI'],
      [record.policyContentHash, input.policyContentHash, 'policy content hash'],
      [record.policyVersion, input.policyVersion, 'policy version'],
      [record.policyName, input.policyName, 'policy name'],
      [record.approverId, input.approverId, 'approver'],
      [record.originalDecision, 'REQUIRE_HUMAN', 'original decision'],
    ]
    for (const [left, right, label] of checks) {
      if (left !== right) {
        throw new AuthorityError('approval', `continuation ${label} does not match pending context`, true)
      }
    }
    return record
  }

  async markApproved(actorId: string, nonce: string, intentHash: string): Promise<void> {
    const result = await this.pool.query(
      `UPDATE adap_pending
       SET approval_state = 'approved', updated_at = now()
       WHERE nonce = $1
         AND tenant_id = $2
         AND actor_id = $3
         AND intent_hash = $4
         AND approval_state = 'pending'
       RETURNING nonce`,
      [assertValidNonce(nonce), this.tenantId, assertValidIdentity(actorId, 'pending.agentId'), intentHash],
    )
    if ((result.rowCount ?? 0) !== 1) {
      throw new AuthorityError('approval', 'cannot mark approval on this pending context', true)
    }
  }

  async markDeclined(actorId: string, nonce: string, intentHash: string): Promise<void> {
    const result = await this.pool.query(
      `UPDATE adap_pending
       SET approval_state = 'declined', updated_at = now()
       WHERE nonce = $1
         AND tenant_id = $2
         AND actor_id = $3
         AND intent_hash = $4
         AND approval_state = 'pending'
       RETURNING nonce`,
      [assertValidNonce(nonce), this.tenantId, assertValidIdentity(actorId, 'pending.agentId'), intentHash],
    )
    if ((result.rowCount ?? 0) !== 1) {
      throw new AuthorityError('approval', 'cannot mark decline on this pending context', true)
    }
  }

  async consume(actorId: string, nonce: string, intentHash: string): Promise<void> {
    await this.pool.query(
      `UPDATE adap_pending
       SET approval_state = 'consumed', updated_at = now()
       WHERE nonce = $1
         AND tenant_id = $2
         AND actor_id = $3
         AND intent_hash = $4`,
      [assertValidNonce(nonce), this.tenantId, assertValidIdentity(actorId, 'pending.agentId'), intentHash],
    )
  }

  async countActivePending(principalId: string, agentId: string, now = new Date()): Promise<number> {
    const { rows } = await this.pool.query<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM adap_pending
       WHERE tenant_id = $1
         AND principal_id = $2
         AND agent_id = $3
         AND approval_state = 'pending'
         AND expiry > $4`,
      [this.tenantId, principalId, agentId, now],
    )
    return Number(rows[0]?.count ?? '0')
  }
}
