import {
  AuthorityError,
  ImmutablePolicyResolver,
  sha256,
  type ImmutablePolicyBinding,
  type PolicyResolver,
} from 'adap'
import { PolicySchema, type Policy } from 'adap-policy'
import type { Pool } from './pool.js'

export interface PostgresPolicyRegistryOptions {
  readonly pool: Pool
  readonly tenantId?: string
}

/**
 * Durable immutable policy registry.
 *
 * Operators call `registerAsync` (or `hydrate` after external insert).
 * The sync `PolicyResolver.register` only returns an existing pin or rejects —
 * the authority path never registers caller documents.
 *
 * First content hash wins for a URI within a tenant. Revocation blocks new
 * resolutions after the next hydrate; in-flight pending rows keep their bound hash.
 */
export class PostgresPolicyRegistry implements PolicyResolver {
  private readonly pool: Pool
  private readonly tenantId: string
  private readonly memory = new ImmutablePolicyResolver()

  constructor(options: PostgresPolicyRegistryOptions) {
    this.pool = options.pool
    this.tenantId = options.tenantId ?? 'default'
  }

  async hydrate(): Promise<number> {
    const { rows } = await this.pool.query<{
      uri: string
      body: Policy
      content_hash: string
      revoked: boolean
    }>(
      `SELECT uri, body, content_hash, revoked
       FROM adap_policies
       WHERE tenant_id = $1 AND revoked = false`,
      [this.tenantId],
    )
    let count = 0
    for (const row of rows) {
      const parsed = PolicySchema.parse(row.body)
      const hash = sha256(parsed)
      if (hash !== row.content_hash) {
        throw new AuthorityError('policy', 'stored policy content hash mismatch', true)
      }
      this.memory.register(parsed, row.uri)
      count += 1
    }
    return count
  }

  /**
   * Sync PolicyResolver surface: idempotent return of an existing pin only.
   * New publications must use `registerAsync`.
   */
  register(policy: Policy, uri: string): ImmutablePolicyBinding {
    const parsed = PolicySchema.parse(policy)
    const contentHash = sha256(parsed)
    const byUri = this.memory.resolveByUri(uri)
    if (byUri) {
      if (byUri.contentHash !== contentHash) {
        throw new AuthorityError('policy', 'policy URI already bound to a different immutable content hash')
      }
      return byUri
    }
    throw new AuthorityError(
      'policy',
      'policy not published; call registerAsync then hydrate, or registerAsync alone',
      true,
    )
  }

  async registerAsync(policy: Policy, uri: string): Promise<ImmutablePolicyBinding> {
    if (typeof uri !== 'string' || uri.length === 0) {
      throw new AuthorityError('policy', 'policy URI is required')
    }
    const parsed = PolicySchema.parse(policy)
    const contentHash = sha256(parsed)

    const existing = await this.pool.query<{ content_hash: string; revoked: boolean }>(
      `SELECT content_hash, revoked FROM adap_policies WHERE tenant_id = $1 AND uri = $2`,
      [this.tenantId, uri],
    )
    const row = existing.rows[0]
    if (row) {
      if (row.content_hash !== contentHash) {
        throw new AuthorityError('policy', 'policy URI already bound to a different immutable content hash')
      }
      if (row.revoked) {
        throw new AuthorityError('policy', 'policy URI is revoked', true)
      }
      return this.memory.register(parsed, uri)
    }

    try {
      await this.pool.query(
        `INSERT INTO adap_policies (content_hash, uri, body, tenant_id)
         VALUES ($1, $2, $3::jsonb, $4)`,
        [contentHash, uri, JSON.stringify(parsed), this.tenantId],
      )
    } catch (err) {
      const code = typeof err === 'object' && err && 'code' in err ? String((err as { code: unknown }).code) : ''
      if (code === '23505') {
        const again = await this.pool.query<{ content_hash: string; revoked: boolean }>(
          `SELECT content_hash, revoked FROM adap_policies WHERE tenant_id = $1 AND uri = $2`,
          [this.tenantId, uri],
        )
        const raced = again.rows[0]
        if (raced && raced.content_hash === contentHash && !raced.revoked) {
          return this.memory.register(parsed, uri)
        }
        throw new AuthorityError('policy', 'policy URI already bound to a different immutable content hash')
      }
      throw err
    }
    return this.memory.register(parsed, uri)
  }

  async revokeByUri(uri: string): Promise<void> {
    const result = await this.pool.query(
      `UPDATE adap_policies
       SET revoked = true, revoked_at = now()
       WHERE tenant_id = $1 AND uri = $2 AND revoked = false
       RETURNING content_hash`,
      [this.tenantId, uri],
    )
    if ((result.rowCount ?? 0) !== 1) {
      throw new AuthorityError('policy', 'policy URI not found or already revoked', true)
    }
  }

  resolveByContentHash(contentHash: string): ImmutablePolicyBinding {
    return this.memory.resolveByContentHash(contentHash)
  }

  resolveByUri(uri: string): ImmutablePolicyBinding | undefined {
    return this.memory.resolveByUri(uri)
  }
}
