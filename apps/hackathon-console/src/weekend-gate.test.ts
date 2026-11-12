import { afterEach, describe, expect, it } from 'vitest'
import type { Server } from 'node:http'
import { DemoRuntime } from './runtime.js'
import { createDemoServer, listen } from './server.js'
import { ConsoleSecurity, type DeploymentConfig } from './security.js'
import { createIdentity, signDelegation, signIntent } from 'adap'
import { WEEKEND_AGENT, adapNode, gateTool, normalizeToolCall, verifyHandoff, wrapLangChainTool } from './weekend-gate.js'

const servers: Server[] = []
const TOKEN = 'team-test-token-0123456789abcdef'

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))))
})

describe('weekend gate', () => {
  it('runs an allowed research tool once and does not run a blocked or held tool', async () => {
    let calls = 0
    const allowed = await gateTool({
      agentRole: WEEKEND_AGENT,
      toolName: 'search_web',
      toolArgs: { q: 'athens' },
      execute: () => {
        calls += 1
        return 'found'
      },
    })
    expect(allowed.decision.action).toBe('ALLOW')
    expect(allowed.executed).toBe(true)
    expect(allowed.output).toBe('found')

    const review = await gateTool({
      agentRole: WEEKEND_AGENT,
      toolName: 'send_email',
      toolArgs: { to: 'team@example.com' },
      execute: () => {
        calls += 1
        return 'sent'
      },
    })
    expect(review.decision.action).toBe('REQUIRE_HUMAN')
    expect(review.executed).toBe(false)

    const blocked = await gateTool({
      agentRole: WEEKEND_AGENT,
      toolName: 'delete_record',
      toolArgs: { id: 'row-1' },
      execute: () => {
        calls += 1
      },
    })
    expect(blocked.decision.action).toBe('BLOCK')
    expect(blocked.decision.ruleId).toBe('block_dangerous')
    expect(blocked.executed).toBe(false)

    const over = await gateTool({
      agentRole: WEEKEND_AGENT,
      toolName: 'send_payment',
      toolArgs: { amount: 800 },
      execute: () => {
        calls += 1
      },
    })
    expect(over.decision.action).toBe('BLOCK')
    expect(['block_dangerous', 'block_payment_over_cap']).toContain(over.decision.ruleId)
    expect(over.executed).toBe(false)

    const invented = await gateTool({
      agentRole: WEEKEND_AGENT,
      toolName: 'fold_laundry',
      toolArgs: {},
      execute: () => {
        calls += 1
      },
    })
    expect(invented.decision.action).toBe('REQUIRE_HUMAN')
    expect(invented.executed).toBe(false)
    expect(calls).toBe(1)
  })

  it('fails closed for a missing, unknown, or malformed agent', async () => {
    for (const agentRole of [undefined, 'agt_unknown', 'bad role']) {
      let called = false
      const result = await gateTool({
        agentRole,
        toolName: 'search_web',
        toolArgs: {},
        execute: () => {
          called = true
        },
      })
      expect(result.decision.action).toBe('BLOCK')
      expect(result.decision.ruleId).toBe('agent_not_in_scope')
      expect(result.executed).toBe(false)
      expect(called).toBe(false)
    }
  })

  it('wraps a LangChain tool so a blocked call never reaches the original', async () => {
    let calls = 0
    const tool = {
      name: 'delete_record',
      description: 'delete a row',
      func: async () => {
        calls += 1
        return 'gone'
      },
    }
    const wrapped = await wrapLangChainTool(tool, WEEKEND_AGENT)
    const refused = await wrapped.invoke({ id: 'row-1' })
    expect(refused).toMatchObject({ executed: false, decision: { action: 'BLOCK' } })
    expect(calls).toBe(0)

    const search = await wrapLangChainTool(
      {
        name: 'search_web',
        invoke: async () => {
          calls += 1
          return 'found'
        },
      },
      WEEKEND_AGENT,
    )
    expect(await search.invoke({ q: 'athens' })).toBe('found')
    expect(calls).toBe(1)
  })

  it('stops a LangGraph node on a blocked tool and on a handoff without a chain', async () => {
    let ran = 0
    const node = adapNode(
      async (state: { toolName: string }) => {
        ran += 1
        return { ...state, didRun: true }
      },
      { agentRole: WEEKEND_AGENT },
    )
    const blocked = await node({ toolName: 'delete_record', args: { id: '1' } })
    expect(blocked.adap?.proceed).toBe(false)
    expect(ran).toBe(0)

    const handoff = await node({ toolName: 'search_web', fromAgent: 'agt_a', toAgent: 'agt_b', args: { q: 'athens' } })
    expect(handoff.adap?.proceed).toBe(false)
    expect(handoff.adap?.reason).toMatch(/delegation chain/i)
    expect(ran).toBe(0)
  })

  it('lets a LangGraph handoff proceed only when verifyAuthority accepts the chain', () => {
    const now = new Date('2026-11-14T12:00:00.000Z')
    const principal = createIdentity('prn_team')
    const agent = createIdentity('agt_a')
    const directory = new Map([
      [principal.id, principal.publicKey],
      [agent.id, agent.publicKey],
    ])
    const chain = [
      signDelegation(
        {
          delegation_id: 'del_root',
          issuer: principal.id,
          subject: agent.id,
          capabilities: [{ action: 'delegate_task', target: 'agents/*', delegable: false }],
          constraints: {},
          issued_at: '2026-11-14T11:00:00.000Z',
          expires_at: '2026-11-14T18:00:00.000Z',
        },
        principal,
      ),
    ]
    const intent = signIntent(
      {
        intent_id: 'int_handoff',
        actor: agent.id,
        delegation_chain: ['del_root'],
        action: 'delegate_task',
        target: 'agents/agt_b',
        parameters: {},
        nonce: 'n-handoff',
        issued_at: '2026-11-14T11:30:00.000Z',
        expires_at: '2026-11-14T18:00:00.000Z',
      },
      agent,
    )
    expect(verifyHandoff({ chain, intent, directory }, now).ok).toBe(true)
    const missing = verifyHandoff({ fromAgent: 'agt_a', toAgent: 'agt_b' }, now)
    expect(missing.ok).toBe(false)
    const tampered = verifyHandoff({ chain, intent: { ...intent, signature: 'aa'.repeat(64) }, directory }, now)
    expect(tampered.ok).toBe(false)
  })

  it('reads OpenAI, LangChain, Claude, and HTTP tool calls', () => {
    expect(normalizeToolCall({ function: { name: 'search_web', arguments: '{"q":"athens"}' } })).toMatchObject({
      toolName: 'search_web',
      toolArgs: { q: 'athens' },
      framework: 'openai-chat',
    })
    expect(normalizeToolCall({ name: 'firecrawl_scrape', args: { url: 'https://example.com' } })).toMatchObject({
      toolName: 'firecrawl_scrape',
      framework: 'langchain',
    })
    expect(normalizeToolCall({ name: 'send_email', input: { to: 'a@b.c' } })).toMatchObject({
      toolName: 'send_email',
      framework: 'anthropic',
    })
    expect(normalizeToolCall({ tool: 'generate_image', args: { prompt: 'stage' } })).toMatchObject({
      toolName: 'generate_image',
      framework: 'http',
    })
    expect('error' in normalizeToolCall({ name: 'search_web', arguments: '{oops' })).toBe(true)
  })

  it('serves the guide without a session and gates a bearer call without running a tool', async () => {
    const runtime = new DemoRuntime({
      passphrase: 'approver-test-passphrase',
      teamId: 'local',
      env: { ADAP_DEMO_ENV: 'hackathon', NODE_ENV: 'demo' },
    })
    const security: DeploymentConfig = {
      deployment: 'local',
      teamId: 'local',
      teamToken: TOKEN,
      approverPassphrase: 'approver-test-passphrase',
      sessionSecret: 'session-secret-local-0123456789abcdef',
      bindHost: '127.0.0.1',
      port: 0,
      sandboxUrl: null,
      sandboxToken: null,
      generatedSecrets: false,
      cookieSecure: false,
      sessionTtlMs: 60_000,
      rateLimitPerMinute: 1_000,
    }
    const server = createDemoServer(runtime, new ConsoleSecurity(security))
    servers.push(server)
    const url = await listen(server)
    const guide = await fetch(`${url}/guide`)
    expect(guide.status).toBe(200)
    const html = await guide.text()
    expect(html).toContain('Ελληνικά')
    expect(html).toContain('Français')
    expect(html).toContain('Deutsch')
    expect(html).toContain('Hardalion')
    expect(html).toContain('https://hardalion.com')
    expect(html).toContain('search_web')
    expect(html).toContain('CrewAI')
    expect(html).toContain('REQUIRE_HUMAN')

    const denied = await fetch(`${url}/api/gate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer wrong-token' },
      body: JSON.stringify({ agentId: WEEKEND_AGENT, tool: 'delete_record', args: {} }),
    })
    expect(denied.status).toBe(401)

    const gated = await fetch(`${url}/api/gate`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${TOKEN}`,
        'x-adap-request': '1',
      },
      body: JSON.stringify({ agentId: WEEKEND_AGENT, tool: 'delete_record', args: { id: '1' } }),
    })
    expect(gated.status).toBe(200)
    const body = await gated.json()
    expect(body.action).toBe('BLOCK')
    expect(body.runTool).toBe(false)
    expect(body.executed).toBe(false)
  })
})
