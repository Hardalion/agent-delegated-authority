import { readFileSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, describe, expect, it } from 'vitest'
import { exportPrivateKeyPkcs8, type PendingAuthorization } from 'adap'
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
    const first = { status: 'pending', intentHash: 'intent-a', inFlight: false } as const
    const second = { status: 'pending', intentHash: 'intent-a', inFlight: true } as const

    expect(store.nonceBackend.compareAndSwap('nonce-a', 0, first)).toBe(true)
    expect(store.nonceBackend.compareAndSwap('nonce-a', 0, second)).toBe(false)
    expect(store.nonceBackend.compareAndSwap('nonce-a', 1, second)).toBe(true)
    expect(store.nonceBackend.read('nonce-a')).toEqual({ version: 2, record: second })
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
    expect(store.pendingStore.get(pending.nonce)).toEqual(pending)
    store.pendingStore.markApproved(pending.nonce, pending.intentHash)
    expect(store.pendingStore.get(pending.nonce)?.approvalState).toBe('approved')
    store.pendingStore.consume(pending.nonce, pending.intentHash)
    expect(store.pendingStore.get(pending.nonce)?.approvalState).toBe('consumed')
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
