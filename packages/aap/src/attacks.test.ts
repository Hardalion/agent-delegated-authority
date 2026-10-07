import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { formatAttack, runAttacks } from './attacks.js'

describe('attack suite', () => {
  it('rejects each attack before execution and verifies the receipt', async () => {
    const attacks = await runAttacks()
    expect(attacks.map((attack) => attack.id)).toEqual([
      '01-over-delegation',
      '02-privilege-escalation',
      '03-prompt-injection',
      '04-replay',
      '05-expired-delegation',
      '06-post-approval-mutation',
    ])

    for (const attack of attacks) {
      expect(attack.decision).toBe('BLOCK')
      expect(attack.executed).toBe(false)
      expect(attack.receiptVerified).toBe(true)
      expect(attack.policyHashMatches).toBe(true)
      expect(attack.intentHashMatches).toBe(true)
      const file = readFileSync(new URL(`../../../examples/attacks/${attack.id}.txt`, import.meta.url), 'utf8').replace(
        /\r\n/g,
        '\n'
      )
      expect(file).toBe(`${formatAttack(attack)}\n`)
    }

    const byId = new Map(attacks.map((attack) => [attack.id, attack]))
    expect(byId.get('01-over-delegation')?.reason).toBe('child raises max_amount')
    expect(byId.get('01-over-delegation')?.executorCalls).toBe(0)
    expect(byId.get('02-privilege-escalation')?.reason).toBe('capability cannot be re-delegated: purchase')
    expect(byId.get('03-prompt-injection')?.reason).toBe('amount exceeds delegated max_amount')
    expect(byId.get('03-prompt-injection')?.closing).toBe('The model is not the authority boundary.')
    expect(byId.get('04-replay')?.reason).toBe('nonce already used')
    expect(byId.get('04-replay')?.executorCalls).toBe(1)
    expect(byId.get('05-expired-delegation')?.reason).toBe('expired or not-yet-valid authority')
    expect(byId.get('06-post-approval-mutation')?.reason).toBe('approval is not bound to this intent')
    expect(byId.get('06-post-approval-mutation')?.executorCalls).toBe(0)
  })
})
