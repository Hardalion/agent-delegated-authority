import { spawnSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { evaluate, AGENT_ID } from '../../../hackathon-starter.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

describe('participant starter identity', () => {
  it('allows a read, waits for apply, and blocks an over-cap or prohibited tool', () => {
    expect(evaluate(AGENT_ID, 'read', {}).action).toBe('ALLOW')
    expect(evaluate(AGENT_ID, 'read', {}).ruleId).toBe('read_allow')
    expect(evaluate(AGENT_ID, 'apply', { amount: 300 }).action).toBe('REQUIRE_HUMAN')
    expect(evaluate(AGENT_ID, 'apply', { amount: 800 }).action).toBe('BLOCK')
    expect(evaluate(AGENT_ID, 'apply', { amount: 800 }).ruleId).toBe('block_over_cap')
    expect(evaluate(AGENT_ID, 'delete_records', {}).action).toBe('BLOCK')
  })

  it('denies an unknown, missing, or malformed agent without a hidden default', () => {
    expect(evaluate('agt_unknown', 'read', {}).ruleId).toBe('agent_not_in_scope')
    expect(evaluate(undefined, 'read', {}).action).toBe('BLOCK')
    expect(evaluate('bad role', 'read', {}).action).toBe('BLOCK')
    expect(evaluate('', 'read', {}).action).toBe('BLOCK')
  })

  it('runs both starter entrypoints', () => {
    const mjs = spawnSync(process.execPath, ['hackathon-starter.mjs'], { cwd: root, encoding: 'utf8' })
    expect(mjs.status).toBe(0)
    expect(mjs.stdout).toContain('ALLOW')
    expect(mjs.stdout).toContain('REQUIRE_HUMAN')
    expect(mjs.stdout + mjs.stderr).toContain('BLOCK')
    const ts = spawnSync(process.execPath, ['--experimental-strip-types', 'hackathon-starter.ts'], {
      cwd: root,
      encoding: 'utf8',
    })
    expect(ts.status, ts.stderr).toBe(0)
    expect(ts.stdout).toContain('ALLOW')
    expect(ts.stdout).toContain('REQUIRE_HUMAN')
  })
})
