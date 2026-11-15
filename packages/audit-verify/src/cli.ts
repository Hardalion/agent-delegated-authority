#!/usr/bin/env node
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { verifyAuthorizationReceipt, verifyReceiptSignature, type AuthorizationReceiptV1 } from './authorization-receipt.js'

function usage(): never {
  console.error(`Usage: adap-receipt <receipt.json> [--public-key <spki.txt>] [--verbose]

Verifies an Authorization Receipt offline.
No network access.

Without --public-key, verification checks structure and the content hash.
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
  const result = verifyAuthorizationReceipt(receipt)
  const errors = [...result.errors]
  let signatureChecked = false
  let signatureOk = false
  if (result.valid && publicKeyPath) {
    signatureChecked = true
    try {
      signatureOk = verifyReceiptSignature(receipt, readFileSync(resolve(publicKeyPath), 'utf8'))
      if (!signatureOk) errors.push('ed25519 signature invalid')
    } catch {
      errors.push('issuer public key rejected')
    }
  }
  const valid = result.valid && (!signatureChecked || signatureOk)

  if (verbose) {
    console.log(`valid: ${valid}`)
    console.log(`structure_ok: ${result.structureOk}`)
    console.log(`content_hash_ok: ${result.contentHashOk}`)
    console.log(`signature_checked: ${signatureChecked}`)
    if (signatureChecked) console.log(`signature_ok: ${signatureOk}`)
    if (errors.length > 0) {
      console.log(`errors: ${errors.join('; ')}`)
    }
  } else if (valid && signatureChecked) {
    console.log('OK signature verified with the issuer public key')
  } else if (valid) {
    console.log('OK structure and content hash. Signature not checked.')
  } else {
    console.error(`INVALID: ${errors.join('; ') || 'receipt failed verification'}`)
  }

  process.exit(valid ? 0 : 1)
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error))
  process.exit(2)
})
