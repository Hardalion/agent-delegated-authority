/**
 * Enforce the pinned MCP `input_schema` against `intent.parameters`.
 *
 * The authority path already pins a tool definition (`tool_definition_hash`) and
 * binds its hash onto the receipt, but that only proves *which* schema is in
 * force — it does not constrain the parameter bag. Without this check the ADAP
 * canonical view of `parameters` and the downstream executor's view can diverge:
 * an array where a scalar is declared, an undeclared key, or a case/fold-variant
 * key that collides with a declared one all flow to the executor untouched.
 *
 * This module closes that gap for the subset of JSON Schema that MCP tool
 * `inputSchema` documents use. It is intentionally dependency-free and strict:
 *
 *  - Unknown keys are rejected unless the object schema sets
 *    `additionalProperties: true`. An authority boundary should not forward a
 *    parameter the tool never declared.
 *  - A presented key that is a Unicode (NFKC) + case fold variant of a declared
 *    property, but not its exact spelling, is rejected, as are two presented keys
 *    that fold to the same form. A case-insensitive downstream parser must not be
 *    handed two spellings of the same field.
 *  - A declared property's value must match its declared `type` (and `enum`),
 *    recursively for nested objects and array items. This rejects a value whose
 *    JSON shape differs from the one policy rules were written against.
 *
 * Schemas are operator-controlled and pinned (the hash must match the grant), so
 * their shape is trusted here. The check runs only when the runtime presents the
 * tool definition, so callers that do not opt in keep their current behaviour.
 */

import { AuthorityError } from './errors.js'

export interface ObjectSchema {
  readonly type?: string | readonly string[]
  readonly properties?: Readonly<Record<string, PropertySchema>>
  readonly required?: readonly string[]
  readonly additionalProperties?: boolean | Readonly<Record<string, unknown>>
}

export interface PropertySchema {
  readonly type?: string | readonly string[]
  readonly enum?: readonly unknown[]
  readonly properties?: Readonly<Record<string, PropertySchema>>
  readonly required?: readonly string[]
  readonly additionalProperties?: boolean | Readonly<Record<string, unknown>>
  readonly items?: PropertySchema
}

/** NFKC + case fold. Two keys that map to the same value collide for a case/fold-insensitive parser. */
function foldKey(key: string): string {
  return key.normalize('NFKC').toLowerCase()
}

function jsonType(value: unknown): string {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  if (Number.isInteger(value)) return 'integer'
  return typeof value // 'string' | 'number' | 'boolean' | 'object' | 'undefined' | ...
}

/** Does `value` satisfy a JSON Schema `type` (string or union)? `integer` ⊂ `number`. */
function typeMatches(declared: string | readonly string[], value: unknown): boolean {
  const declaredList = Array.isArray(declared) ? declared : [declared as string]
  const actual = jsonType(value)
  return declaredList.some((t) => {
    if (t === 'number') return actual === 'number' || actual === 'integer'
    if (t === 'integer') return actual === 'integer'
    return actual === t
  })
}

/** Only an explicit `type: 'object'` schema with a `properties` map is enforceable here. */
function isObjectSchema(schema: unknown): schema is ObjectSchema {
  if (schema == null || typeof schema !== 'object' || Array.isArray(schema)) return false
  const s = schema as ObjectSchema
  const typeOk = s.type === 'object' || (Array.isArray(s.type) && s.type.includes('object'))
  return typeOk && s.properties != null && typeof s.properties === 'object'
}

function reject(message: string): never {
  throw new AuthorityError('parameter_schema', message, true)
}

function assertValueConforms(value: unknown, schema: PropertySchema, path: string): void {
  if (schema.type != null && !typeMatches(schema.type, value)) {
    const want = Array.isArray(schema.type) ? schema.type.join('|') : schema.type
    reject(`${path} must be ${want}, got ${jsonType(value)}`)
  }
  if (schema.enum != null && !schema.enum.some((allowed) => allowed === value)) {
    reject(`${path} is not one of the allowed values`)
  }
  if (isObjectSchema(schema)) {
    validateParametersAgainstSchema(value as Record<string, unknown>, schema, path)
  }
  if ((schema.type === 'array' || (Array.isArray(schema.type) && schema.type.includes('array'))) && schema.items) {
    if (Array.isArray(value)) {
      value.forEach((item, index) => assertValueConforms(item, schema.items as PropertySchema, `${path}[${index}]`))
    }
  }
}

/**
 * Throw `AuthorityError('parameter_schema', …)` when `params` does not conform to
 * the object `schema`. The caller turns that into a fail-closed BLOCK. A schema
 * that is not an enforceable object schema is a no-op (nothing to enforce).
 */
export function validateParametersAgainstSchema(
  params: Readonly<Record<string, unknown>>,
  schema: unknown,
  path = 'parameters',
): void {
  if (!isObjectSchema(schema)) return
  const properties = schema.properties ?? {}
  const open = schema.additionalProperties === true

  // Declared property names by fold form. An ambiguous schema (two declared
  // props that fold together) cannot be enforced unambiguously; fail closed.
  const declaredByFold = new Map<string, string>()
  for (const prop of Object.keys(properties)) {
    const f = foldKey(prop)
    if (declaredByFold.has(f) && declaredByFold.get(f) !== prop) {
      reject(`schema declares case/fold-colliding properties at ${path}`)
    }
    declaredByFold.set(f, prop)
  }

  const seenFold = new Map<string, string>()
  for (const key of Object.keys(params)) {
    const f = foldKey(key)
    const clash = seenFold.get(f)
    if (clash !== undefined && clash !== key) {
      reject(`${path} has case/fold-colliding keys ${JSON.stringify(clash)} and ${JSON.stringify(key)}`)
    }
    seenFold.set(f, key)

    const declared = declaredByFold.get(f)
    if (declared !== undefined) {
      if (declared !== key) {
        reject(`${path}.${key} is a case/fold variant of declared parameter ${JSON.stringify(declared)}`)
      }
      assertValueConforms(params[key], properties[key]!, `${path}.${key}`)
      continue
    }
    if (!open) {
      reject(`undeclared parameter ${JSON.stringify(key)} at ${path}`)
    }
  }

  for (const requiredKey of schema.required ?? []) {
    if (!Object.prototype.hasOwnProperty.call(params, requiredKey)) {
      reject(`missing required parameter ${JSON.stringify(requiredKey)} at ${path}`)
    }
  }
}
