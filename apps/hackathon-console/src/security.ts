import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { DemoError } from './errors.js'

const DENIED = new Set(['treasury-demo', 'password', 'changeme', 'secret', 'admin'])

export interface DeploymentConfig {
  readonly deployment: 'local' | 'hosted'
  readonly teamId: string
  readonly teamToken: string
  readonly approverPassphrase: string
  readonly sessionSecret: string
  readonly bindHost: '127.0.0.1' | '0.0.0.0'
  readonly port: number
  readonly sandboxUrl: string | null
  readonly sandboxToken: string | null
  readonly generatedSecrets: boolean
  readonly cookieSecure: boolean
  readonly sessionTtlMs: number
  readonly rateLimitPerMinute: number
}

export function loadDeploymentConfig(env: NodeJS.ProcessEnv, options?: { readonly generate?: boolean }): DeploymentConfig {
  const deployment = env.ADAP_DEPLOYMENT === 'hosted' ? 'hosted' : 'local'
  const bind = env.ADAP_BIND_HOST ?? '127.0.0.1'
  if (bind !== '127.0.0.1' && !(env.ADAP_CONTAINER === '1' && bind === '0.0.0.0')) {
    throw new DemoError(
      403,
      'bind_refused',
      'The hackathon console binds to 127.0.0.1. Inside a container, set ADAP_CONTAINER=1 and publish the host port on 127.0.0.1 only.',
    )
  }
  const port = Number(env.ADAP_DEMO_PORT ?? 4317)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new DemoError(403, 'bind_refused', 'ADAP_DEMO_PORT is not a valid port.')
  }
  const generate = options?.generate !== false && deployment === 'local'
  const generated = {
    token: !env.ADAP_TEAM_TOKEN,
    passphrase: !env.ADAP_APPROVER_PASSPHRASE && !env.ADAP_DEMO_PASSPHRASE,
    session: !env.ADAP_SESSION_SECRET,
  }
  const teamToken = env.ADAP_TEAM_TOKEN || (generate ? randomBytes(24).toString('base64url') : '')
  const approverPassphrase = env.ADAP_APPROVER_PASSPHRASE || env.ADAP_DEMO_PASSPHRASE || (generate ? randomBytes(18).toString('base64url') : '')
  const sessionSecret = env.ADAP_SESSION_SECRET || (generate ? randomBytes(32).toString('base64url') : '')
  const teamId = env.ADAP_TEAM_ID || (deployment === 'local' ? 'local' : '')
  assertSecret('team token', teamToken, deployment === 'hosted' ? 24 : 16)
  assertSecret('approver passphrase', approverPassphrase, 12)
  assertSecret('session secret', sessionSecret, 32)
  if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(teamId)) {
    throw new DemoError(403, 'config_refused', 'ADAP_TEAM_ID must be a short lowercase identifier.')
  }
  if (deployment === 'hosted') {
    if (!env.ADAP_SANDBOX_URL || !env.ADAP_SANDBOX_TOKEN) {
      throw new DemoError(403, 'config_refused', 'Hosted mode requires ADAP_SANDBOX_URL and ADAP_SANDBOX_TOKEN.')
    }
    assertSecret('sandbox token', env.ADAP_SANDBOX_TOKEN, 16)
  }
  if (env.ADAP_SANDBOX_TOKEN) assertSecret('sandbox token', env.ADAP_SANDBOX_TOKEN, 16)
  const cookieSecure = deployment === 'hosted' ? env.ADAP_COOKIE_SECURE !== '0' : false
  return {
    deployment,
    teamId,
    teamToken,
    approverPassphrase,
    sessionSecret,
    bindHost: bind,
    port,
    sandboxUrl: env.ADAP_SANDBOX_URL ?? null,
    sandboxToken: env.ADAP_SANDBOX_TOKEN ?? null,
    generatedSecrets: generated.token || generated.passphrase || generated.session,
    cookieSecure,
    sessionTtlMs: 8 * 60 * 60 * 1000,
    rateLimitPerMinute: Number(env.ADAP_RATE_LIMIT_PER_MINUTE ?? 120),
  }
}

function assertSecret(label: string, value: string, min: number): void {
  if (value.length < min || DENIED.has(value.toLowerCase())) {
    throw new DemoError(403, 'config_refused', `${label} is missing or is not an acceptable secret.`)
  }
}

interface Session {
  readonly id: string
  readonly teamId: string
  readonly expiresAt: number
}

export class ConsoleSecurity {
  readonly #config: DeploymentConfig
  readonly #sessions = new Map<string, Session>()
  readonly #hits = new Map<string, number[]>()

  constructor(config: DeploymentConfig) {
    this.#config = config
  }

  get config(): DeploymentConfig {
    return this.#config
  }

  login(token: string): { readonly cookie: string; readonly expiresAt: string } {
    if (!secretEqual(token, this.#config.teamToken)) {
      securityLog('auth.denied', { teamId: this.#config.teamId })
      throw new DemoError(401, 'auth_required', 'Team credential was not accepted.')
    }
    const id = randomBytes(32).toString('base64url')
    const expiresAt = Date.now() + this.#config.sessionTtlMs
    this.#sessions.set(id, { id, teamId: this.#config.teamId, expiresAt })
    this.#trim()
    return { cookie: this.#cookie(id, expiresAt), expiresAt: new Date(expiresAt).toISOString() }
  }

  logout(req: IncomingMessage): void {
    const id = this.#sessionId(req)
    if (id) this.#sessions.delete(id)
  }

  revokeAll(): void {
    this.#sessions.clear()
  }

  authorize(req: IncomingMessage, method: string): void {
    this.#limitHeaders(req)
    const path = new URL(req.url ?? '/', 'http://127.0.0.1').pathname
    if (
      method === 'GET' &&
      (path === '/' ||
        path === '/index.html' ||
        path === '/styles.css' ||
        path === '/app.js' ||
        path === '/i18n.js' ||
        path === '/guide-lang.js' ||
        path === '/guide' ||
        path === '/guide.html' ||
        path === '/api/health' ||
        path === '/api/ready')
    ) {
      this.#rateLimit(`public:${this.#clientAddress(req)}`)
      return
    }
    if (method === 'POST' && path === '/api/session') {
      this.#rateLimit(`login:${this.#clientAddress(req)}`)
      return
    }
    const bearer = bearerToken(req)
    if (bearer != null) {
      if (!secretEqual(bearer, this.#config.teamToken)) {
        this.#rateLimit(`auth:${this.#clientAddress(req)}`)
        securityLog('auth.denied', { teamId: this.#config.teamId, path })
        throw new DemoError(401, 'auth_required', 'Team credential was not accepted.')
      }
      const fingerprint = createHmac('sha256', this.#config.sessionSecret).update(bearer).digest('base64url')
      this.#rateLimit(`bearer:${fingerprint}`)
      return
    }
    const session = this.#validSession(req)
    if (!session || session.teamId !== this.#config.teamId) {
      this.#rateLimit(`auth:${this.#clientAddress(req)}`)
      securityLog('auth.denied', { teamId: this.#config.teamId, path })
      throw new DemoError(401, 'auth_required', 'A team session is required.')
    }
    this.#rateLimit(`session:${session.id}`)
    if (method !== 'GET' && method !== 'HEAD') this.#assertMutation(req)
  }

  applyHeaders(res: ServerResponse): void {
    res.setHeader('x-content-type-options', 'nosniff')
    res.setHeader('x-frame-options', 'DENY')
    res.setHeader('referrer-policy', 'no-referrer')
    res.setHeader('content-security-policy', "default-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    res.setHeader('cache-control', 'no-store')
    res.setHeader('x-permitted-cross-domain-policies', 'none')
    if (this.#config.cookieSecure) res.setHeader('strict-transport-security', 'max-age=31536000')
  }

  #cookie(id: string, expiresAt: number): string {
    const mac = createHmac('sha256', this.#config.sessionSecret).update(id).digest('base64url')
    const maxAge = Math.max(1, Math.floor((expiresAt - Date.now()) / 1000))
    const secure = this.#config.cookieSecure ? '; Secure' : ''
    return `adap_session=${id}.${mac}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secure}`
  }

  #sessionId(req: IncomingMessage): string | null {
    const header = req.headers.cookie ?? ''
    const match = header.match(/(?:^|;\s*)adap_session=([^;]+)/)
    if (!match?.[1]) return null
    const [id, mac] = match[1].split('.')
    if (!id || !mac) return null
    const expected = createHmac('sha256', this.#config.sessionSecret).update(id).digest('base64url')
    if (!secretEqual(mac, expected)) return null
    return id
  }

  #validSession(req: IncomingMessage): Session | null {
    const id = this.#sessionId(req)
    if (!id) return null
    const session = this.#sessions.get(id)
    if (!session) return null
    if (session.expiresAt <= Date.now()) {
      this.#sessions.delete(id)
      return null
    }
    return session
  }

  #assertMutation(req: IncomingMessage): void {
    if (req.headers['x-adap-request'] !== '1') {
      throw new DemoError(403, 'csrf_rejected', 'The request is missing the console request header.')
    }
    const origin = req.headers.origin
    const host = req.headers.host
    if (typeof origin === 'string' && origin.length > 0) {
      let parsed: URL
      try {
        parsed = new URL(origin)
      } catch {
        throw new DemoError(403, 'origin_rejected', 'Origin was not accepted.')
      }
      if (parsed.host !== host) throw new DemoError(403, 'origin_rejected', 'Origin was not accepted.')
    }
  }

  #clientAddress(req: IncomingMessage): string {
    return req.socket.remoteAddress ?? 'local'
  }

  #rateLimit(key: string): void {
    const now = Date.now()
    const recent = (this.#hits.get(key) ?? []).filter((stamp) => now - stamp < 60_000)
    if (recent.length >= this.#config.rateLimitPerMinute) {
      securityLog('rate.limited', { teamId: this.#config.teamId })
      throw new DemoError(429, 'rate_limited', 'Too many requests. Wait and retry.')
    }
    recent.push(now)
    this.#hits.set(key, recent)
  }

  #limitHeaders(req: IncomingMessage): void {
    const size = JSON.stringify(req.headers).length
    if (size > 16_384) throw new DemoError(431, 'headers_too_large', 'Request headers are too large.')
  }

  #trim(): void {
    const sessions = [...this.#sessions.values()].sort((a, b) => a.expiresAt - b.expiresAt)
    while (sessions.length > 20) {
      const oldest = sessions.shift()
      if (oldest) this.#sessions.delete(oldest.id)
    }
  }
}

export function bearerToken(req: IncomingMessage): string | null {
  const header = req.headers.authorization
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return null
  const token = header.slice('Bearer '.length).trim()
  return token.length > 0 ? token : null
}

function secretEqual(input: string, expected: string): boolean {
  const left = Buffer.from(input)
  const right = Buffer.from(expected)
  if (left.length !== right.length) return false
  return timingSafeEqual(left, right)
}

export function securityLog(event: string, fields: Record<string, string | number>): void {
  process.stderr.write(`${JSON.stringify({ ts: new Date().toISOString(), event, ...fields })}\n`)
}
