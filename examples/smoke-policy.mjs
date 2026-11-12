#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const cli = join(root, 'packages', 'policy-engine', 'dist', 'cli.js')

function run(argv) {
  const result = spawnSync(process.execPath, [cli, ...argv], { encoding: 'utf8' })
  if (result.stdout) process.stdout.write(result.stdout)
  if (result.stderr) process.stderr.write(result.stderr)
  return result.status ?? 1
}

const mode = process.argv[2]
if (mode === 'block') {
  process.exit(run(['--tool', 'apply', '--agent', 'agt_reader', '--args', JSON.stringify({ amount: 800 }), '--json']))
}
if (mode === 'allow') {
  process.exit(run(['--tool', 'read', '--agent', 'agt_reader', '--json']))
}
process.stderr.write('usage: smoke-policy.mjs block|allow\n')
process.exit(2)
