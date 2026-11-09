import { DemoError } from './errors.js'

export interface DemoEnv {
  NODE_ENV?: string
  ADAP_DEMO_ENV?: string
  ADAP_PG_URL?: string
  ADAP_DEMO_PG_URL?: string
}

export const RESET_CONFIRM = 'RESET HACKATHON DEMO'

/**
 * A demo database URL must be local and must name a hackathon or demo database.
 * The integration database name `adap` is refused.
 */
export function isSafeDemoDatabaseUrl(value: string): boolean {
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    return false
  }
  if (parsed.protocol !== 'postgresql:' && parsed.protocol !== 'postgres:') return false
  const host = parsed.hostname
  if (host !== '127.0.0.1' && host !== 'localhost') return false
  const database = decodeURIComponent(parsed.pathname.replace(/^\//, ''))
  if (!database) return false
  if (!/(hackathon|demo)/i.test(database)) return false
  if (/prod|customer|live/i.test(database)) return false
  return true
}

/**
 * Environment for the hackathon process.
 * ADAP_PG_URL is dropped so a reset in this process cannot see the integration or production URL.
 */
export function demoEnvFromProcess(env: NodeJS.ProcessEnv): DemoEnv {
  if (env.NODE_ENV === 'production' && env.ADAP_DEPLOYMENT !== 'hosted') {
    throw new DemoError(
      403,
      'demo_start_refused',
      'Local mode refuses to start when NODE_ENV is production. Hosted mode stays a sandbox and still requires its own secrets.',
    )
  }
  const next: DemoEnv = {
    NODE_ENV: 'demo',
    ADAP_DEMO_ENV: 'hackathon',
  }
  if (env.ADAP_DEMO_PG_URL) {
    if (!isSafeDemoDatabaseUrl(env.ADAP_DEMO_PG_URL)) {
      throw new DemoError(
        403,
        'demo_database_refused',
        'ADAP_DEMO_PG_URL must be a localhost URL whose database name contains hackathon or demo.',
      )
    }
    next.ADAP_DEMO_PG_URL = env.ADAP_DEMO_PG_URL
  }
  return next
}

export function assertDemoResetAllowed(env: DemoEnv): void {
  if (env.NODE_ENV === 'production') {
    throw new DemoError(
      403,
      'demo_reset_refused',
      'Demo reset is refused when NODE_ENV is production.',
    )
  }
  if (env.ADAP_DEMO_ENV !== 'hackathon') {
    throw new DemoError(
      403,
      'demo_reset_refused',
      'Demo reset requires ADAP_DEMO_ENV=hackathon.',
    )
  }
  if (env.ADAP_PG_URL) {
    throw new DemoError(
      403,
      'demo_reset_refused',
      'Demo reset is refused in a process configured with ADAP_PG_URL.',
    )
  }
  if (env.ADAP_DEMO_PG_URL && !isSafeDemoDatabaseUrl(env.ADAP_DEMO_PG_URL)) {
    throw new DemoError(
      403,
      'demo_reset_refused',
      'Demo reset is refused because ADAP_DEMO_PG_URL is not a local demo database.',
    )
  }
}
