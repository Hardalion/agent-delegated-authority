import { createCipheriv, createDecipheriv, randomBytes, type KeyObject } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import {
  AuthorityError,
  assertValidIdentity,
  assertValidNonce,
  createIdentity,
  exportPrivateKeyPkcs8,
  identityFromKeys,
  importPrivateKeyPkcs8,
  type AtomicNonceBackend,
  type Identity,
  type NonceRecord,
  type PendingAuthorization,
  type PendingContinuation,
  type PendingStore,
  type VersionedNonceRecord,
} from 'adap'

const SCHEMA_VERSION = 1
const KEY_BYTES = 32
const IV_BYTES = 12
const AUTH_TAG_BYTES = 16

type JsonRecord = Record<string, unknown>

export interface DurableIdentities {
  readonly principal: Identity
  readonly agent: Identity
  readonly outsider: Identity
  readonly signer: Identity
}

export interface IdentityIds {
  readonly principalId: string
  readonly agentId: string
  readonly outsiderId: string
  readonly signerId: string
}

export interface ReceiptMeta {
  readonly sequence: number
  readonly prevHash: string | null
}

export type ExecutionState = 'started' | 'unresolved' | 'completed'

export interface ExecutionOperation {
  readonly intentHash: string
  readonly nonce: string
  readonly state: ExecutionState
  readonly correlationId: string
  readonly classification: string | null
  readonly resourceId: string | null
  readonly updatedAt: string
}

export interface ExecutionStart {
  readonly intentHash: string
  readonly nonce: string
  readonly correlationId: string
  readonly classification?: string | null
  readonly updatedAt?: string
}

export interface OpenTeamDurableStoreOptions {
  readonly teamId: string
  readonly databasePath?: string
  readonly stateDirectory?: string
  readonly encryptionKey?: Buffer
  readonly encryptionKeyBase64url?: string
  readonly env?: NodeJS.ProcessEnv
  readonly hosted?: boolean
  readonly deployment?: 'local' | 'hosted'
}

export interface TeamDurableStore {
  readonly databasePath: string
  readonly nonceBackend: AtomicNonceBackend
  readonly pendingStore: PendingStore
  loadOrCreateIdentities(ids: IdentityIds): DurableIdentities
  saveCases(cases: readonly object[]): void
  loadCases<T = JsonRecord>(): T[]
  saveOpen(open: ReadonlyMap<string, unknown> | readonly object[]): void
  loadOpen<T = unknown>(): Map<string, T>
  saveTimeline(timeline: readonly object[]): void
  loadTimeline<T = JsonRecord>(): T[]
  saveGatewayEvents(events: readonly object[]): void
  loadGatewayEvents<T = JsonRecord>(): T[]
  saveSeenApprovals(approvals: ReadonlySet<string> | readonly string[]): void
  loadSeenApprovals(): Set<string>
  saveReceiptMeta(meta: ReceiptMeta): void
  loadReceiptMeta(): ReceiptMeta
  recordExecutionStart(input: ExecutionStart): void
  recordExecutionStart(
    intentHash: string,
    nonce: string,
    correlationId: string,
    classification?: string | null,
  ): void
  markExecutionUnresolved(intentHash: string, classification?: string | null, updatedAt?: string): void
  markExecutionCompleted(intentHash: string, resourceId?: string | null, updatedAt?: string): void
  getExecution(intentHash: string): ExecutionOperation | undefined
  clearOperationalState(): void
  close(): void
}

interface StoredIdentity {
  readonly id: string
  readonly publicKey: string
  readonly privateKeyPkcs8: string
}

interface StoredIdentities {
  readonly principal: StoredIdentity
  readonly agent: StoredIdentity
  readonly outsider: StoredIdentity
  readonly signer: StoredIdentity
}

interface EncryptedBlob {
  readonly version: 1
  readonly iv: string
  readonly tag: string
  readonly ciphertext: string
}

function assertTeamId(teamId: string): string {
  if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(teamId)) {
    throw new Error('teamId must be a lowercase slug')
  }
  return teamId
}

function decodeEncryptionKey(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new Error('ADAP_STATE_ENCRYPTION_KEY must be base64url-encoded 32 bytes')
  }
  const key = Buffer.from(value, 'base64url')
  if (key.length !== KEY_BYTES || key.toString('base64url') !== value) {
    throw new Error('ADAP_STATE_ENCRYPTION_KEY must be base64url-encoded 32 bytes')
  }
  return key
}

function loadOrCreateLocalKey(keyPath: string): Buffer {
  if (existsSync(keyPath)) return decodeEncryptionKey(readFileSync(keyPath, 'utf8').trim())
  const key = randomBytes(KEY_BYTES)
  mkdirSync(dirname(keyPath), { recursive: true, mode: 0o700 })
  try {
    // POSIX honors 0600. On Windows, keep the state directory ACL restricted to the current user.
    writeFileSync(keyPath, `${key.toString('base64url')}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 })
    return key
  } catch (error) {
    if (existsSync(keyPath)) return decodeEncryptionKey(readFileSync(keyPath, 'utf8').trim())
    throw error
  }
}

export function resolveStateEncryptionKey(
  options: Pick<
    OpenTeamDurableStoreOptions,
    | 'teamId'
    | 'stateDirectory'
    | 'encryptionKey'
    | 'encryptionKeyBase64url'
    | 'env'
    | 'hosted'
    | 'deployment'
  >,
): Buffer {
  if (options.encryptionKey) {
    if (options.encryptionKey.length !== KEY_BYTES) throw new Error('state encryption key must be 32 bytes')
    return Buffer.from(options.encryptionKey)
  }
  if (options.encryptionKeyBase64url) return decodeEncryptionKey(options.encryptionKeyBase64url)
  const envKey = (options.env ?? process.env).ADAP_STATE_ENCRYPTION_KEY
  if (envKey) return decodeEncryptionKey(envKey)
  const hosted =
    options.hosted ??
    (options.deployment === 'hosted' || (options.env ?? process.env).ADAP_DEPLOYMENT === 'hosted')
  if (hosted) throw new Error('Hosted mode requires ADAP_STATE_ENCRYPTION_KEY')
  const stateDirectory = options.stateDirectory ?? join(process.cwd(), '.demo', 'state')
  return loadOrCreateLocalKey(join(stateDirectory, `${assertTeamId(options.teamId)}.key`))
}

function migrate(database: DatabaseSync): void {
  database.exec('PRAGMA journal_mode = WAL')
  database.exec('PRAGMA foreign_keys = ON')
  database.exec(`
    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    ) STRICT
  `)
  const row = database.prepare("SELECT value FROM meta WHERE key = 'schema_version'").get() as
    | { value: string }
    | undefined
  let version = row ? Number.parseInt(row.value, 10) : 0
  if (!Number.isInteger(version) || version < 0 || version > SCHEMA_VERSION) {
    throw new Error(`Unsupported durable-store schema version: ${row?.value ?? 'unknown'}`)
  }
  if (version < 1) {
    database.exec('BEGIN IMMEDIATE')
    try {
      database.exec(`
        CREATE TABLE nonces (
          nonce TEXT PRIMARY KEY,
          version INTEGER NOT NULL,
          status TEXT NOT NULL CHECK (status IN ('pending', 'consumed', 'failed')),
          intent_hash TEXT NOT NULL,
          in_flight INTEGER NOT NULL CHECK (in_flight IN (0, 1))
        ) STRICT;
        CREATE TABLE pending_auth (
          nonce TEXT PRIMARY KEY,
          json TEXT NOT NULL
        ) STRICT;
        CREATE TABLE seen_approvals (
          approval_key TEXT PRIMARY KEY
        ) STRICT;
        CREATE TABLE cases (
          id TEXT PRIMARY KEY,
          json TEXT NOT NULL,
          created_at TEXT NOT NULL
        ) STRICT;
        CREATE TABLE open_intents (
          nonce TEXT PRIMARY KEY,
          json TEXT NOT NULL
        ) STRICT;
        CREATE TABLE timeline (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          json TEXT NOT NULL
        ) STRICT;
        CREATE TABLE gateway_events (
          id INTEGER PRIMARY KEY,
          json TEXT NOT NULL
        ) STRICT;
        CREATE TABLE execution_ops (
          intent_hash TEXT PRIMARY KEY,
          nonce TEXT NOT NULL,
          state TEXT NOT NULL CHECK (state IN ('started', 'unresolved', 'completed')),
          correlation_id TEXT NOT NULL,
          classification TEXT,
          resource_id TEXT,
          updated_at TEXT NOT NULL
        ) STRICT;
        CREATE TABLE receipt_meta (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          sequence INTEGER NOT NULL,
          prev_hash TEXT
        ) STRICT;
        CREATE TABLE identities_blob (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          encrypted TEXT NOT NULL
        ) STRICT
      `)
      database
        .prepare("INSERT INTO meta (key, value) VALUES ('schema_version', ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value")
        .run(String(SCHEMA_VERSION))
      database.exec('COMMIT')
      version = 1
    } catch (error) {
      database.exec('ROLLBACK')
      throw error
    }
  }
  if (version !== SCHEMA_VERSION) throw new Error(`Durable-store migration stopped at version ${version}`)
}

function transaction(database: DatabaseSync, operation: () => void): void {
  database.exec('BEGIN IMMEDIATE')
  try {
    operation()
    database.exec('COMMIT')
  } catch (error) {
    database.exec('ROLLBACK')
    throw error
  }
}

function parseJson<T>(json: string): T {
  return JSON.parse(json) as T
}

function pendingConflict(): AuthorityError {
  return new AuthorityError('approval', 'pending authorization conflict for nonce', true)
}

class SqliteNonceBackend implements AtomicNonceBackend {
  constructor(private readonly database: DatabaseSync) {}

  read(nonce: string): VersionedNonceRecord | undefined {
    const row = this.database
      .prepare('SELECT version, status, intent_hash, in_flight FROM nonces WHERE nonce = ?')
      .get(nonce) as
      | { version: number; status: NonceRecord['status']; intent_hash: string; in_flight: number }
      | undefined
    if (!row) return undefined
    return {
      version: Number(row.version),
      record: { status: row.status, intentHash: row.intent_hash, inFlight: row.in_flight === 1 },
    }
  }

  compareAndSwap(nonce: string, expectedVersion: number, record: NonceRecord): boolean {
    if (expectedVersion === 0) {
      return (
        Number(
          this.database
            .prepare(
              'INSERT INTO nonces (nonce, version, status, intent_hash, in_flight) VALUES (?, 1, ?, ?, ?) ON CONFLICT (nonce) DO NOTHING',
            )
            .run(nonce, record.status, record.intentHash, record.inFlight ? 1 : 0).changes,
        ) === 1
      )
    }
    return (
      Number(
        this.database
          .prepare(
            'UPDATE nonces SET version = version + 1, status = ?, intent_hash = ?, in_flight = ? WHERE nonce = ? AND version = ?',
          )
          .run(record.status, record.intentHash, record.inFlight ? 1 : 0, nonce, expectedVersion).changes,
      ) === 1
    )
  }
}

class SqlitePendingStore implements PendingStore {
  constructor(private readonly database: DatabaseSync) {}

  put(record: PendingAuthorization): void {
    const nonce = assertValidNonce(record.nonce)
    const normalized: PendingAuthorization = {
      ...record,
      nonce,
      approverId: assertValidIdentity(record.approverId, 'pending.approverId'),
      approvalState: 'pending',
    }
    const existing = this.get(nonce)
    if (existing) {
      if (
        existing.intentHash !== normalized.intentHash ||
        existing.approvalState !== 'pending' ||
        existing.policyContentHash !== normalized.policyContentHash
      ) {
        throw pendingConflict()
      }
      return
    }
    try {
      this.database
        .prepare('INSERT INTO pending_auth (nonce, json) VALUES (?, ?)')
        .run(nonce, JSON.stringify(normalized))
    } catch {
      const raced = this.get(nonce)
      if (
        !raced ||
        raced.intentHash !== normalized.intentHash ||
        raced.approvalState !== 'pending' ||
        raced.policyContentHash !== normalized.policyContentHash
      ) {
        throw pendingConflict()
      }
    }
  }

  get(nonce: string): PendingAuthorization | undefined {
    const key = assertValidNonce(nonce)
    const row = this.database.prepare('SELECT json FROM pending_auth WHERE nonce = ?').get(key) as
      | { json: string }
      | undefined
    return row ? parseJson<PendingAuthorization>(row.json) : undefined
  }

  requireContinuation(input: PendingContinuation): PendingAuthorization {
    const record = this.get(input.nonce)
    if (!record) throw new AuthorityError('approval', 'no pending authorization for this nonce', true)
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
    for (const [actual, expected, label] of checks) {
      if (actual !== expected) {
        throw new AuthorityError('approval', `continuation ${label} does not match pending context`, true)
      }
    }
    return record
  }

  markApproved(nonce: string, intentHash: string): void {
    const key = assertValidNonce(nonce)
    const record = this.get(key)
    if (!record || record.intentHash !== intentHash || record.approvalState !== 'pending') {
      throw new AuthorityError('approval', 'cannot mark approval on this pending context', true)
    }
    const next = { ...record, approvalState: 'approved' as const }
    const result = this.database
      .prepare(
        "UPDATE pending_auth SET json = ? WHERE nonce = ? AND json_extract(json, '$.intentHash') = ? AND json_extract(json, '$.approvalState') = 'pending'",
      )
      .run(JSON.stringify(next), key, intentHash)
    if (Number(result.changes) !== 1) {
      throw new AuthorityError('approval', 'cannot mark approval on this pending context', true)
    }
  }

  consume(nonce: string, intentHash: string): void {
    const key = assertValidNonce(nonce)
    const record = this.get(key)
    if (!record || record.intentHash !== intentHash) return
    this.database
      .prepare("UPDATE pending_auth SET json = ? WHERE nonce = ? AND json_extract(json, '$.intentHash') = ?")
      .run(JSON.stringify({ ...record, approvalState: 'consumed' }), key, intentHash)
  }
}

class SqliteTeamDurableStore implements TeamDurableStore {
  readonly nonceBackend: AtomicNonceBackend
  readonly pendingStore: PendingStore

  constructor(
    readonly databasePath: string,
    private readonly teamId: string,
    private readonly database: DatabaseSync,
    private readonly encryptionKey: Buffer,
  ) {
    this.nonceBackend = new SqliteNonceBackend(database)
    this.pendingStore = new SqlitePendingStore(database)
  }

  loadOrCreateIdentities(ids: IdentityIds): DurableIdentities {
    const row = this.database.prepare('SELECT encrypted FROM identities_blob WHERE id = 1').get() as
      | { encrypted: string }
      | undefined
    if (row) {
      const stored = this.decryptIdentities(row.encrypted)
      const expected = [ids.principalId, ids.agentId, ids.outsiderId, ids.signerId]
      const actual = [stored.principal.id, stored.agent.id, stored.outsider.id, stored.signer.id]
      if (expected.some((id, index) => id !== actual[index])) {
        throw new Error('stored identity ids do not match requested identity ids')
      }
      return {
        principal: this.restoreIdentity(stored.principal),
        agent: this.restoreIdentity(stored.agent),
        outsider: this.restoreIdentity(stored.outsider),
        signer: this.restoreIdentity(stored.signer),
      }
    }
    const identities: DurableIdentities = {
      principal: createIdentity(ids.principalId),
      agent: createIdentity(ids.agentId),
      outsider: createIdentity(ids.outsiderId),
      signer: createIdentity(ids.signerId),
    }
    const encrypted = this.encryptIdentities({
      principal: this.storeIdentity(identities.principal),
      agent: this.storeIdentity(identities.agent),
      outsider: this.storeIdentity(identities.outsider),
      signer: this.storeIdentity(identities.signer),
    })
    this.database.prepare('INSERT INTO identities_blob (id, encrypted) VALUES (1, ?)').run(encrypted)
    return identities
  }

  saveCases(cases: readonly object[]): void {
    transaction(this.database, () => {
      this.database.exec('DELETE FROM cases')
      const insert = this.database.prepare('INSERT INTO cases (id, json, created_at) VALUES (?, ?, ?)')
      const base = Date.now()
      cases.forEach((item, index) => {
        const record = item as JsonRecord
        const id = typeof record.id === 'string' ? record.id : ''
        if (!id) throw new Error('case.id must be a non-empty string')
        const createdAt =
          typeof record.createdAt === 'string' ? record.createdAt : new Date(base - index).toISOString()
        insert.run(id, JSON.stringify(item), createdAt)
      })
    })
  }

  loadCases<T = JsonRecord>(): T[] {
    const rows = this.database.prepare('SELECT json FROM cases ORDER BY created_at DESC, id ASC').all() as {
      json: string
    }[]
    return rows.map((row) => parseJson<T>(row.json))
  }

  saveOpen(open: ReadonlyMap<string, unknown> | readonly object[]): void {
    transaction(this.database, () => {
      this.database.exec('DELETE FROM open_intents')
      const insert = this.database.prepare('INSERT INTO open_intents (nonce, json) VALUES (?, ?)')
      if (!Array.isArray(open)) {
        for (const [nonce, value] of open as ReadonlyMap<string, unknown>) {
          insert.run(nonce, JSON.stringify(value))
        }
        return
      }
      for (const value of open as readonly object[]) {
        const record = value as JsonRecord
        const intent = record.intent as JsonRecord | undefined
        const nonce =
          typeof record.nonce === 'string'
            ? record.nonce
            : intent && typeof intent.nonce === 'string'
              ? intent.nonce
              : ''
        if (!nonce) throw new Error('open intent nonce must be a non-empty string')
        insert.run(nonce, JSON.stringify(value))
      }
    })
  }

  loadOpen<T = unknown>(): Map<string, T> {
    const rows = this.database.prepare('SELECT nonce, json FROM open_intents ORDER BY nonce').all() as {
      nonce: string
      json: string
    }[]
    return new Map(rows.map((row) => [row.nonce, parseJson<T>(row.json)]))
  }

  saveTimeline(timeline: readonly object[]): void {
    this.replaceOrderedJson('timeline', timeline)
  }

  loadTimeline<T = JsonRecord>(): T[] {
    return this.loadOrderedJson<T>('timeline')
  }

  saveGatewayEvents(events: readonly object[]): void {
    this.replaceOrderedJson('gateway_events', events)
  }

  loadGatewayEvents<T = JsonRecord>(): T[] {
    return this.loadOrderedJson<T>('gateway_events')
  }

  saveSeenApprovals(approvals: ReadonlySet<string> | readonly string[]): void {
    transaction(this.database, () => {
      this.database.exec('DELETE FROM seen_approvals')
      const insert = this.database.prepare('INSERT INTO seen_approvals (approval_key) VALUES (?)')
      for (const key of approvals) insert.run(key)
    })
  }

  loadSeenApprovals(): Set<string> {
    const rows = this.database.prepare('SELECT approval_key FROM seen_approvals ORDER BY approval_key').all() as {
      approval_key: string
    }[]
    return new Set(rows.map((row) => row.approval_key))
  }

  saveReceiptMeta(meta: ReceiptMeta): void {
    if (!Number.isSafeInteger(meta.sequence) || meta.sequence < 0) {
      throw new Error('receipt sequence must be a non-negative safe integer')
    }
    this.database
      .prepare(
        'INSERT INTO receipt_meta (id, sequence, prev_hash) VALUES (1, ?, ?) ON CONFLICT (id) DO UPDATE SET sequence = excluded.sequence, prev_hash = excluded.prev_hash',
      )
      .run(meta.sequence, meta.prevHash)
  }

  loadReceiptMeta(): ReceiptMeta {
    const row = this.database.prepare('SELECT sequence, prev_hash FROM receipt_meta WHERE id = 1').get() as
      | { sequence: number; prev_hash: string | null }
      | undefined
    return row ? { sequence: Number(row.sequence), prevHash: row.prev_hash } : { sequence: 0, prevHash: null }
  }

  recordExecutionStart(input: ExecutionStart): void
  recordExecutionStart(
    intentHash: string,
    nonce: string,
    correlationId: string,
    classification?: string | null,
  ): void
  recordExecutionStart(
    inputOrHash: ExecutionStart | string,
    nonce?: string,
    correlationId?: string,
    classification?: string | null,
  ): void {
    const input: ExecutionStart =
      typeof inputOrHash === 'string'
        ? {
            intentHash: inputOrHash,
            nonce: nonce ?? '',
            correlationId: correlationId ?? '',
            classification,
          }
        : inputOrHash
    if (!input.intentHash || !input.nonce || !input.correlationId) {
      throw new Error('execution start requires intentHash, nonce, and correlationId')
    }
    this.database
      .prepare(
        `INSERT INTO execution_ops
          (intent_hash, nonce, state, correlation_id, classification, resource_id, updated_at)
         VALUES (?, ?, 'started', ?, ?, NULL, ?)
         ON CONFLICT (intent_hash) DO UPDATE SET
          nonce = excluded.nonce,
          state = excluded.state,
          correlation_id = excluded.correlation_id,
          classification = excluded.classification,
          resource_id = NULL,
          updated_at = excluded.updated_at`,
      )
      .run(
        input.intentHash,
        input.nonce,
        input.correlationId,
        input.classification ?? null,
        input.updatedAt ?? new Date().toISOString(),
      )
  }

  markExecutionUnresolved(intentHash: string, classification?: string | null, updatedAt?: string): void {
    const result = this.database
      .prepare(
        `UPDATE execution_ops
         SET state = 'unresolved', classification = COALESCE(?, classification), updated_at = ?
         WHERE intent_hash = ? AND state != 'completed'`,
      )
      .run(classification ?? null, updatedAt ?? new Date().toISOString(), intentHash)
    if (Number(result.changes) !== 1) throw new Error('execution operation is missing or already completed')
  }

  markExecutionCompleted(intentHash: string, resourceId?: string | null, updatedAt?: string): void {
    const result = this.database
      .prepare(
        `UPDATE execution_ops
         SET state = 'completed', resource_id = ?, updated_at = ?
         WHERE intent_hash = ?`,
      )
      .run(resourceId ?? null, updatedAt ?? new Date().toISOString(), intentHash)
    if (Number(result.changes) !== 1) throw new Error('execution operation is missing')
  }

  getExecution(intentHash: string): ExecutionOperation | undefined {
    const row = this.database
      .prepare(
        'SELECT intent_hash, nonce, state, correlation_id, classification, resource_id, updated_at FROM execution_ops WHERE intent_hash = ?',
      )
      .get(intentHash) as
      | {
          intent_hash: string
          nonce: string
          state: ExecutionState
          correlation_id: string
          classification: string | null
          resource_id: string | null
          updated_at: string
        }
      | undefined
    return row
      ? {
          intentHash: row.intent_hash,
          nonce: row.nonce,
          state: row.state,
          correlationId: row.correlation_id,
          classification: row.classification,
          resourceId: row.resource_id,
          updatedAt: row.updated_at,
        }
      : undefined
  }

  clearOperationalState(): void {
    transaction(this.database, () => {
      this.database.exec(`
        DELETE FROM nonces;
        DELETE FROM pending_auth;
        DELETE FROM seen_approvals;
        DELETE FROM cases;
        DELETE FROM open_intents;
        DELETE FROM timeline;
        DELETE FROM gateway_events;
        DELETE FROM execution_ops;
        DELETE FROM receipt_meta
      `)
    })
  }

  close(): void {
    this.database.close()
  }

  private replaceOrderedJson(table: 'timeline' | 'gateway_events', values: readonly object[]): void {
    transaction(this.database, () => {
      this.database.exec(`DELETE FROM ${table}`)
      const insert = this.database.prepare(`INSERT INTO ${table} (json) VALUES (?)`)
      for (const value of values) insert.run(JSON.stringify(value))
    })
  }

  private loadOrderedJson<T>(table: 'timeline' | 'gateway_events'): T[] {
    const rows = this.database.prepare(`SELECT json FROM ${table} ORDER BY id`).all() as { json: string }[]
    return rows.map((row) => parseJson<T>(row.json))
  }

  private storeIdentity(identity: Identity): StoredIdentity {
    return {
      id: identity.id,
      publicKey: identity.publicKey,
      privateKeyPkcs8: exportPrivateKeyPkcs8(identity.privateKey).toString('base64url'),
    }
  }

  private restoreIdentity(identity: StoredIdentity): Identity {
    return identityFromKeys(
      identity.id,
      identity.publicKey,
      importPrivateKeyPkcs8(Buffer.from(identity.privateKeyPkcs8, 'base64url')),
    )
  }

  private encryptIdentities(identities: StoredIdentities): string {
    const iv = randomBytes(IV_BYTES)
    const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, iv, { authTagLength: AUTH_TAG_BYTES })
    cipher.setAAD(Buffer.from(`adap-state:${this.teamId}:identities:v1`))
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(identities), 'utf8'), cipher.final()])
    const blob: EncryptedBlob = {
      version: 1,
      iv: iv.toString('base64url'),
      tag: cipher.getAuthTag().toString('base64url'),
      ciphertext: ciphertext.toString('base64url'),
    }
    return JSON.stringify(blob)
  }

  private decryptIdentities(encrypted: string): StoredIdentities {
    const blob = parseJson<EncryptedBlob>(encrypted)
    if (blob.version !== 1) throw new Error('unsupported encrypted identity blob version')
    const decipher = createDecipheriv(
      'aes-256-gcm',
      this.encryptionKey,
      Buffer.from(blob.iv, 'base64url'),
      { authTagLength: AUTH_TAG_BYTES },
    )
    decipher.setAAD(Buffer.from(`adap-state:${this.teamId}:identities:v1`))
    decipher.setAuthTag(Buffer.from(blob.tag, 'base64url'))
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(blob.ciphertext, 'base64url')),
      decipher.final(),
    ])
    return parseJson<StoredIdentities>(plaintext.toString('utf8'))
  }
}

export function openTeamDurableStore(options: OpenTeamDurableStoreOptions): TeamDurableStore {
  const teamId = assertTeamId(options.teamId)
  const stateDirectory = options.stateDirectory ?? join(process.cwd(), '.demo', 'state')
  const databasePath = options.databasePath ?? join(stateDirectory, `${teamId}.sqlite`)
  mkdirSync(dirname(databasePath), { recursive: true, mode: 0o700 })
  const encryptionKey = resolveStateEncryptionKey({ ...options, teamId, stateDirectory })
  const database = new DatabaseSync(databasePath)
  try {
    migrate(database)
    return new SqliteTeamDurableStore(databasePath, teamId, database, encryptionKey)
  } catch (error) {
    database.close()
    throw error
  }
}
