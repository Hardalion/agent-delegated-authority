import {
  AuthorityError,
  assertValidIdentity,
  assertValidNonce,
  type PendingAuthorization,
  type PendingContinuation,
  type PendingStore,
} from 'adap'
import type { Pool } from './pool.js'

export interface PostgresPendingStoreOptions {
  readonly pool: Pool
  readonly tenantId?: string
}

type PendingRow = {
  nonce: string
  intent_hash: string
  principal_id: string
  agent_id: string
  delegation_chain_hash: string
  policy_uri: string
  policy_content_hash: string
  policy_version: string
  policy_name: string
  matched_rule_id: string
  original_decision: 'REQUIRE_HUMAN'
  approval_state: 'pending' | 'approved' | 'consumed'
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
 * Durable pending REQUIRE_HUMAN store.
 * `markApproved` is a conditional UPDATE from `pending` → `approved`.
 * Execution gating still relies on the nonce claim, not this store alone.
 */
export class PostgresPendingStore implements PendingStore {
  private readonly pool: Pool
  private readonly tenantId: string

  constructor(options: PostgresPendingStoreOptions) {
    this.pool = options.pool
    this.tenantId = options.tenantId ?? 'default'
  }

  async put(record: PendingAuthorization): Promise<void> {
    const nonce = assertValidNonce(record.nonce)
    const approverId = assertValidIdentity(record.approverId, 'pending.approverId')
    const existing = await this.get(nonce)
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
    try {
      await this.pool.query(
        `INSERT INTO adap_pending (
           nonce, intent_hash, principal_id, agent_id, delegation_chain_hash,
           policy_uri, policy_content_hash, policy_version, policy_name,
           matched_rule_id, original_decision, approval_state, expiry, approver_id, tenant_id
         ) VALUES (
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'REQUIRE_HUMAN','pending',$11,$12,$13
         )`,
        [
          nonce,
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
    } catch (err) {
      const code = typeof err === 'object' && err && 'code' in err ? String((err as { code: unknown }).code) : ''
      if (code === '23505') {
        throw new AuthorityError('approval', 'pending authorization conflict for nonce', true)
      }
      throw err
    }
  }

  async get(nonce: string): Promise<PendingAuthorization | undefined> {
    const key = assertValidNonce(nonce)
    const { rows } = await this.pool.query<PendingRow>(
      `SELECT nonce, intent_hash, principal_id, agent_id, delegation_chain_hash,
              policy_uri, policy_content_hash, policy_version, policy_name,
              matched_rule_id, original_decision, approval_state, expiry, approver_id
       FROM adap_pending
       WHERE nonce = $1 AND tenant_id = $2`,
      [key, this.tenantId],
    )
    return rows[0] ? fromRow(rows[0]) : undefined
  }

  async requireContinuation(input: PendingContinuation): Promise<PendingAuthorization> {
    const nonce = assertValidNonce(input.nonce)
    const record = await this.get(nonce)
    if (!record) {
      throw new AuthorityError('approval', 'no pending authorization for this nonce', true)
    }
    if (record.approvalState !== 'pending') {
      throw new AuthorityError('approval', 'pending authorization is not open', true)
    }
    if (Date.parse(record.expiry) <= input.now.getTime()) {
      throw new AuthorityError('approval', 'pending authorization expired', true)
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

  async markApproved(nonce: string, intentHash: string): Promise<void> {
    const key = assertValidNonce(nonce)
    const result = await this.pool.query(
      `UPDATE adap_pending
       SET approval_state = 'approved', updated_at = now()
       WHERE nonce = $1
         AND tenant_id = $2
         AND intent_hash = $3
         AND approval_state = 'pending'
       RETURNING nonce`,
      [key, this.tenantId, intentHash],
    )
    if ((result.rowCount ?? 0) !== 1) {
      throw new AuthorityError('approval', 'cannot mark approval on this pending context', true)
    }
  }

  async consume(nonce: string, intentHash: string): Promise<void> {
    const key = assertValidNonce(nonce)
    await this.pool.query(
      `UPDATE adap_pending
       SET approval_state = 'consumed', updated_at = now()
       WHERE nonce = $1
         AND tenant_id = $2
         AND intent_hash = $3`,
      [key, this.tenantId, intentHash],
    )
  }
}
