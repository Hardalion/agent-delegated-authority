import { readFileSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { DatabaseSync } from 'node:sqlite'
import { afterEach, describe, expect, it } from 'vitest'
import {
  AuthorityError,
  DEFAULT_MAX_PENDING_APPROVALS,
  exportPrivateKeyPkcs8,
  type PendingAuthorization,
} from 'adap'
import { openTeamDurableStore, type TeamDurableStore } from './durable-store.js'

const temporaryDirectories: string[] = []
const openStores: TeamDurableStore[] = []

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'adap-durable-store-'))
  temporaryDirectories.push(directory)
  return directory
}

function open(directory: string, encryptionKey = Buffer.alloc(32, 7)): TeamDurableStore {
  const store = openTeamDurableStore({
    teamId: 'team-test',
    stateDirectory: directory,
    encryptionKey,
  })
  openStores.push(store)
  return store
}

afterEach(async () => {
  while (openStores.length > 0) openStores.pop()?.close()
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })))
})

describe('team durable store', () => {
  it('performs nonce compare-and-swap atomically', async () => {
    const store = open(await temporaryDirectory())
    const actor = 'agt_treasury'
    const first = { status: 'pending', intentHash: 'intent-a', inFlight: false, actorId: actor } as const
    const second = { status: 'pending', intentHash: 'intent-a', inFlight: true, actorId: actor } as const

    expect(store.nonceBackend.compareAndSwap(actor, 'nonce-a', 0, first)).toBe(true)
    expect(store.nonceBackend.compareAndSwap(actor, 'nonce-a', 0, second)).toBe(false)
    expect(store.nonceBackend.compareAndSwap(actor, 'nonce-a', 1, second)).toBe(true)
    expect(store.nonceBackend.read(actor, 'nonce-a')).toEqual({ version: 2, record: second })
  })

  it('roundtrips pending authorization state', async () => {
    const store = open(await temporaryDirectory())
    const pending: PendingAuthorization = {
      intentHash: 'intent-hash',
      principalId: 'prn_treasury',
      agentId: 'agt_treasury',
      delegationChainHash: 'delegation-hash',
      policyUri: 'urn:adap:test',
      policyContentHash: 'policy-hash',
      policyVersion: '1',
      policyName: 'Test policy',
      matchedRuleId: 'human-review',
      originalDecision: 'REQUIRE_HUMAN',
      approvalState: 'pending',
      expiry: '2030-01-01T00:00:00.000Z',
      nonce: 'nonce-pending',
      approverId: 'prn_treasury',
    }

    store.pendingStore.put(pending)
    expect(store.pendingStore.get(pending.agentId, pending.nonce)).toEqual(pending)
    store.pendingStore.markApproved(pending.agentId, pending.nonce, pending.intentHash)
    expect(store.pendingStore.get(pending.agentId, pending.nonce)?.approvalState).toBe('approved')
    store.pendingStore.consume(pending.agentId, pending.nonce, pending.intentHash)
    expect(store.pendingStore.get(pending.agentId, pending.nonce)?.approvalState).toBe('consumed')
  })

  it('roundtrips encrypted identities across reopen', async () => {
    const directory = await temporaryDirectory()
    const ids = {
      principalId: 'prn_treasury',
      agentId: 'agt_treasury',
      outsiderId: 'agt_outsider',
      signerId: 'iss_hackathon',
    }
    const firstStore = open(directory)
    const first = firstStore.loadOrCreateIdentities(ids)
    const privateKey = exportPrivateKeyPkcs8(first.principal.privateKey)
    const publicKey = first.principal.publicKey
    const databasePath = firstStore.databasePath
    firstStore.close()
    openStores.splice(openStores.indexOf(firstStore), 1)

    const databaseBytes = readFileSync(databasePath)
    expect(databaseBytes.includes(privateKey)).toBe(false)

    const secondStore = open(directory)
    const second = secondStore.loadOrCreateIdentities(ids)
    expect(second.principal.publicKey).toBe(publicKey)
    expect(exportPrivateKeyPkcs8(second.principal.privateKey)).toEqual(privateKey)
  })

  it('records an unresolved execution lifecycle', async () => {
    const store = open(await temporaryDirectory())
    store.recordExecutionStart({
      intentHash: 'intent-execution',
      nonce: 'nonce-execution',
      correlationId: 'corr-execution',
      classification: 'payment',
      updatedAt: '2026-11-11T12:00:00.000Z',
    })
    store.markExecutionUnresolved('intent-execution', 'outcome_unknown', '2026-11-11T12:00:01.000Z')

    expect(store.getExecution('intent-execution')).toEqual({
      intentHash: 'intent-execution',
      nonce: 'nonce-execution',
      state: 'unresolved',
      correlationId: 'corr-execution',
      classification: 'outcome_unknown',
      resourceId: null,
      updatedAt: '2026-11-11T12:00:01.000Z',
    })
  })
})

describe('sqlite pending approval quotas', () => {
  const NOW = new Date('2026-11-11T12:00:00.000Z')

  function pending(
    over: Partial<PendingAuthorization> & Pick<PendingAuthorization, 'nonce' | 'intentHash'>,
  ): PendingAuthorization {
    return {
      principalId: 'prn_treasury',
      agentId: 'agt_treasury',
      delegationChainHash: 'delegation-hash',
      policyUri: 'urn:adap:test',
      policyContentHash: 'policy-hash',
      policyVersion: '1',
      policyName: 'Test policy',
      matchedRuleId: 'human-review',
      originalDecision: 'REQUIRE_HUMAN',
      approvalState: 'pending',
      expiry: '2030-01-01T00:00:00.000Z',
      approverId: 'prn_treasury',
      ...over,
    }
  }

  it('enforces the default limit and honors caller-supplied limits', async () => {
    const store = open(await temporaryDirectory())
    expect(DEFAULT_MAX_PENDING_APPROVALS).toBe(5)
    for (let i = 0; i < DEFAULT_MAX_PENDING_APPROVALS; i += 1) {
      store.pendingStore.put(pending({ nonce: `n-default-${i}`, intentHash: `ih-default-${i}` }), {
        now: NOW,
      })
    }
    expect(() =>
      store.pendingStore.put(pending({ nonce: 'n-default-overflow', intentHash: 'ih-overflow' }), {
        now: NOW,
      }),
    ).toThrow(/queue is full/i)
    expect(store.pendingStore.get('agt_treasury', 'n-default-overflow')).toBeUndefined()
    expect(store.pendingStore.countActivePending?.('prn_treasury', 'agt_treasury', NOW)).toBe(5)

    const tight = open(await temporaryDirectory())
    tight.pendingStore.put(pending({ nonce: 'n-low-1', intentHash: 'ih-low-1' }), {
      maxPendingApprovals: 1,
      now: NOW,
    })
    expect(() =>
      tight.pendingStore.put(pending({ nonce: 'n-low-2', intentHash: 'ih-low-2' }), {
        maxPendingApprovals: 1,
        now: NOW,
      }),
    ).toThrow(AuthorityError)

    const wide = open(await temporaryDirectory())
    for (let i = 0; i < 3; i += 1) {
      wide.pendingStore.put(pending({ nonce: `n-high-${i}`, intentHash: `ih-high-${i}` }), {
        maxPendingApprovals: 3,
        now: NOW,
      })
    }
    expect(wide.pendingStore.countActivePending?.('prn_treasury', 'agt_treasury', NOW)).toBe(3)
  })

  it('ignores expired, approved, declined and consumed rows in the active count', async () => {
    const store = open(await temporaryDirectory())
    store.pendingStore.put(
      pending({
        nonce: 'n-expired',
        intentHash: 'ih-expired',
        expiry: '2026-11-11T11:00:00.000Z',
      }),
      { maxPendingApprovals: 1, now: NOW },
    )
    store.pendingStore.put(pending({ nonce: 'n-live', intentHash: 'ih-live' }), {
      maxPendingApprovals: 1,
      now: NOW,
    })
    expect(store.pendingStore.countActivePending?.('prn_treasury', 'agt_treasury', NOW)).toBe(1)
    expect(store.pendingStore.get('agt_treasury', 'n-expired')?.approvalState).toBe('expired')

    store.pendingStore.markApproved('agt_treasury', 'n-live', 'ih-live')
    store.pendingStore.put(pending({ nonce: 'n-after-approved', intentHash: 'ih-after-approved' }), {
      maxPendingApprovals: 1,
      now: NOW,
    })
    store.pendingStore.markDeclined('agt_treasury', 'n-after-approved', 'ih-after-approved')
    store.pendingStore.put(pending({ nonce: 'n-after-declined', intentHash: 'ih-after-declined' }), {
      maxPendingApprovals: 1,
      now: NOW,
    })
    store.pendingStore.consume('agt_treasury', 'n-after-declined', 'ih-after-declined')
    store.pendingStore.put(pending({ nonce: 'n-after-consumed', intentHash: 'ih-after-consumed' }), {
      maxPendingApprovals: 1,
      now: NOW,
    })
    expect(store.pendingStore.countActivePending?.('prn_treasury', 'agt_treasury', NOW)).toBe(1)
  })

  it('keeps independent quotas per principal and agent', async () => {
    const store = open(await temporaryDirectory())
    store.pendingStore.put(pending({ nonce: 'n-a', intentHash: 'ih-a', agentId: 'agt_a' }), {
      maxPendingApprovals: 1,
      now: NOW,
    })
    store.pendingStore.put(pending({ nonce: 'n-b', intentHash: 'ih-b', agentId: 'agt_b' }), {
      maxPendingApprovals: 1,
      now: NOW,
    })
    store.pendingStore.put(
      pending({
        nonce: 'n-p2',
        intentHash: 'ih-p2',
        principalId: 'prn_other',
        agentId: 'agt_a',
        approverId: 'prn_other',
      }),
      { maxPendingApprovals: 1, now: NOW },
    )
    expect(store.pendingStore.countActivePending?.('prn_treasury', 'agt_a', NOW)).toBe(1)
    expect(store.pendingStore.countActivePending?.('prn_treasury', 'agt_b', NOW)).toBe(1)
    expect(store.pendingStore.countActivePending?.('prn_other', 'agt_a', NOW)).toBe(1)
  })

  it('serializes concurrent inserts so the configured limit cannot be exceeded', async () => {
    const directory = await temporaryDirectory()
    const left = open(directory)
    const right = open(directory)
    const successes: string[] = []
    const failures: string[] = []
    const workers = [left, right, left, right].map((store, index) => () => {
      try {
        store.pendingStore.put(
          pending({ nonce: `n-race-${index}`, intentHash: `ih-race-${index}` }),
          { maxPendingApprovals: 2, now: NOW },
        )
        successes.push(`n-race-${index}`)
      } catch (error) {
        failures.push(error instanceof Error ? error.message : String(error))
      }
    })
    // Overlapping BEGIN IMMEDIATE writers on the shared SQLite file.
    await Promise.all(workers.map((run) => Promise.resolve().then(run)))
    expect(successes).toHaveLength(2)
    expect(failures).toHaveLength(2)
    expect(left.pendingStore.countActivePending?.('prn_treasury', 'agt_treasury', NOW)).toBe(2)
    for (const nonce of ['n-race-0', 'n-race-1', 'n-race-2', 'n-race-3']) {
      if (!successes.includes(nonce)) {
        expect(left.pendingStore.get('agt_treasury', nonce)).toBeUndefined()
      }
    }
  })

  it('migrates schema v1 nonce and pending rows to actor-scoped v2 keys', async () => {
    const directory = await temporaryDirectory()
    const databasePath = join(directory, 'team-migrate.sqlite')
    const legacy = new DatabaseSync(databasePath)
    legacy.exec(`
      CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
      INSERT INTO meta (key, value) VALUES ('schema_version', '1');
      CREATE TABLE nonces (
        nonce TEXT PRIMARY KEY,
        version INTEGER NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('pending', 'consumed', 'failed')),
        intent_hash TEXT NOT NULL,
        in_flight INTEGER NOT NULL CHECK (in_flight IN (0, 1))
      ) STRICT;
      INSERT INTO nonces (nonce, version, status, intent_hash, in_flight)
        VALUES ('legacy-nonce', 1, 'consumed', 'ih-legacy', 0);
      CREATE TABLE pending_auth (
        nonce TEXT PRIMARY KEY,
        json TEXT NOT NULL
      ) STRICT;
      INSERT INTO pending_auth (nonce, json) VALUES (
        'legacy-pending',
        '{"intentHash":"ih-pending","principalId":"prn_treasury","agentId":"agt_treasury","delegationChainHash":"d","policyUri":"u","policyContentHash":"p","policyVersion":"1","policyName":"n","matchedRuleId":"r","originalDecision":"REQUIRE_HUMAN","approvalState":"pending","expiry":"2030-01-01T00:00:00.000Z","nonce":"legacy-pending","approverId":"prn_treasury"}'
      );
      CREATE TABLE seen_approvals (approval_key TEXT PRIMARY KEY) STRICT;
      CREATE TABLE cases (id TEXT PRIMARY KEY, json TEXT NOT NULL, created_at TEXT NOT NULL) STRICT;
      CREATE TABLE open_intents (nonce TEXT PRIMARY KEY, json TEXT NOT NULL) STRICT;
      CREATE TABLE timeline (id INTEGER PRIMARY KEY AUTOINCREMENT, json TEXT NOT NULL) STRICT;
      CREATE TABLE gateway_events (id INTEGER PRIMARY KEY, json TEXT NOT NULL) STRICT;
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
      ) STRICT;
    `)
    legacy.close()

    const store = openTeamDurableStore({
      teamId: 'team-migrate',
      stateDirectory: directory,
      encryptionKey: Buffer.alloc(32, 9),
      databasePath,
    })
    openStores.push(store)

    const tombstone = store.nonceBackend.read('agt_treasury', 'legacy-nonce')
    expect(tombstone?.record.actorId).toBe('')
    expect(tombstone?.record.status).toBe('consumed')
    expect(
      store.nonceBackend.compareAndSwap('agt_treasury', 'legacy-nonce', 0, {
        status: 'pending',
        intentHash: 'ih-new',
        inFlight: false,
        actorId: 'agt_treasury',
      }),
    ).toBe(false)

    const migrated = store.pendingStore.get('agt_treasury', 'legacy-pending')
    expect(migrated?.intentHash).toBe('ih-pending')
    store.pendingStore.put(pending({ nonce: 'post-migrate', intentHash: 'ih-post' }), {
      maxPendingApprovals: 2,
      now: NOW,
    })
    expect(store.pendingStore.get('agt_treasury', 'post-migrate')?.intentHash).toBe('ih-post')
  })
})

