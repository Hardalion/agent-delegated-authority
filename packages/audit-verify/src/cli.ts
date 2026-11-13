#!/usr/bin/env node
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { verifyAuthorizationReceipt, type AuthorizationReceiptV1 } from './authorization-receipt.js'

function usage(): never {
  console.error(`Usage: adap-receipt <receipt.json> [--public-key <spki.txt>] [--verbose]

Verifies an Authorization Receipt offline.
No network access.

Without --public-key, verification checks structure and the content hash.
Demo placeholder signatures are never accepted as valid evidence.
The Ed25519 signature is checked only when the issuer public key is supplied.
The key file is the SPKI public key, base64url, one line.`)
  process.exit(2)
}

function flagValue(args: string[], name: string): string | undefined {
  const index = args.indexOf(name)
  if (index === -1) return undefined
  return args[index + 1]
}

async function main() {
  const args = process.argv.slice(2).filter((a) => a !== '--')
  if (args.length === 0 || args.includes('-h') || args.includes('--help')) usage()

  const verbose = args.includes('--verbose') || args.includes('-v')
  const publicKeyPath = flagValue(args, '--public-key')
  if (args.includes('--public-key') && !publicKeyPath) usage()
  const fileArg = args.find((arg, index) => !arg.startsWith('-') && args[index - 1] !== '--public-key')
  if (!fileArg) usage()

  const path = resolve(fileArg)
  const receipt = JSON.parse(readFileSync(path, 'utf8')) as AuthorizationReceiptV1
  let result
  try {
    result = verifyAuthorizationReceipt(
      receipt,
      publicKeyPath
        ? { publicKeySpki: readFileSync(resolve(publicKeyPath), 'utf8') }
        : undefined
    )
  } catch {
    console.error('INVALID: issuer public key rejected')
    process.exit(1)
  }

  if (verbose) {
    console.log(`valid: ${result.valid}`)
    console.log(`structure_ok: ${result.structureOk}`)
    console.log(`content_hash_ok: ${result.contentHashOk}`)
    console.log(`demo_signature: ${result.demoSignature}`)
    console.log(`signature_checked: ${result.signatureChecked}`)
    if (result.signatureChecked) console.log(`signature_ok: ${result.signatureOk}`)
    if (result.errors.length > 0) {
      console.log(`errors: ${result.errors.join('; ')}`)
    }
  } else if (result.valid && result.signatureChecked) {
    console.log('OK signature verified with the issuer public key')
  } else if (result.valid) {
    console.log('OK structure and content hash. Signature not checked.')
  } else {
    console.error(`INVALID: ${result.errors.join('; ') || 'receipt failed verification'}`)
  }

  process.exit(result.valid ? 0 : 1)
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error))
  process.exit(2)
})
