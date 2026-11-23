/**
 * Safe condition evaluator, no eval(); supports the specification expression grammar.
 */

export interface EvaluationContext {
  readonly tool?: {
    readonly name?: string
    readonly target?: string
    readonly args?: Record<string, unknown>
  }
  readonly args?: Record<string, unknown>
  readonly payload?: string
  readonly agentRole?: string
  /** Non-secret decision context (from authz context providers). Paths: `context.*`. */
  readonly context?: Record<string, unknown>
}

type Token =
  | { type: 'ident'; value: string }
  | { type: 'string'; value: string }
  | { type: 'number'; value: number }
  | { type: 'boolean'; value: boolean }
  | { type: 'null' }
  | { type: 'op'; value: string }
  | { type: 'lparen' }
  | { type: 'rparen' }
  | { type: 'lbracket' }
  | { type: 'rbracket' }
  | { type: 'comma' }
  | { type: 'dot' }
  | { type: 'eof' }

function scanNumber(input: string, start: number): { readonly value: number; readonly next: number } {
  let i = start
  let num = ''
  let dots = 0
  while (i < input.length && /[0-9.]/.test(input[i]!)) {
    if (input[i] === '.') {
      dots += 1
      if (dots > 1) throw new Error(`Invalid numeric literal at position ${start}`)
    }
    num += input[i]
    i += 1
  }
  if (num === '' || num === '.') throw new Error(`Invalid numeric literal at position ${start}`)
  const value = Number(num)
  if (!Number.isFinite(value)) throw new Error(`Invalid numeric literal at position ${start}`)
  return { value, next: i }
}

function tokenize(input: string): Token[] {
  const tokens: Token[] = []
  let i = 0

  while (i < input.length) {
    const ch = input[i]
    if (ch === ' ' || ch === '\t' || ch === '\n') {
      i += 1
      continue
    }

    if (ch === '(') {
      tokens.push({ type: 'lparen' })
      i += 1
      continue
    }
    if (ch === ')') {
      tokens.push({ type: 'rparen' })
      i += 1
      continue
    }
    if (ch === '[') {
      tokens.push({ type: 'lbracket' })
      i += 1
      continue
    }
    if (ch === ']') {
      tokens.push({ type: 'rbracket' })
      i += 1
      continue
    }
    if (ch === ',') {
      tokens.push({ type: 'comma' })
      i += 1
      continue
    }
    if (ch === '.') {
      tokens.push({ type: 'dot' })
      i += 1
      continue
    }

    if (ch === "'" || ch === '"') {
      const quote = ch
      const start = i
      i += 1
      let value = ''
      while (i < input.length && input[i] !== quote) {
        const current = input[i]!
        if (current === '\n' || current === '\r') {
          throw new Error(`Unterminated string literal at position ${start}`)
        }
        if (current === '\\') {
          const escaped = input[i + 1]
          if (escaped == null) throw new Error(`Unterminated string literal at position ${start}`)
          if (escaped === 'n') value += '\n'
          else if (escaped === 't') value += '\t'
          else if (escaped === '\\' || escaped === "'" || escaped === '"') value += escaped
          else throw new Error(`Invalid string escape at position ${i}`)
          i += 2
          continue
        }
        value += current
        i += 1
      }
      if (i >= input.length) {
        throw new Error(`Unterminated string literal at position ${start}`)
      }
      i += 1
      tokens.push({ type: 'string', value })
      continue
    }

    if (ch === '-' && i + 1 < input.length && /[0-9]/.test(input[i + 1]!)) {
      const start = i
      i += 1
      const parsed = scanNumber(input, i)
      i = parsed.next
      tokens.push({ type: 'number', value: -parsed.value })
      continue
    }

    if (/[0-9]/.test(ch)) {
      const parsed = scanNumber(input, i)
      i = parsed.next
      tokens.push({ type: 'number', value: parsed.value })
      continue
    }

    if (/[a-zA-Z_]/.test(ch)) {
      let ident = ''
      while (i < input.length && /[a-zA-Z0-9_]/.test(input[i])) {
        ident += input[i]
        i += 1
      }
      if (ident === 'in') {
        tokens.push({ type: 'op', value: ident })
      } else if (ident === 'true') {
        tokens.push({ type: 'boolean', value: true })
      } else if (ident === 'false') {
        tokens.push({ type: 'boolean', value: false })
      } else if (ident === 'null') {
        tokens.push({ type: 'null' })
      } else {
        tokens.push({ type: 'ident', value: ident })
      }
      continue
    }

    const two = input.slice(i, i + 2)
    if (['==', '!=', '>=', '<=', '&&', '||'].includes(two)) {
      tokens.push({ type: 'op', value: two })
      i += 2
      continue
    }
    if (['>', '<'].includes(ch)) {
      tokens.push({ type: 'op', value: ch })
      i += 1
      continue
    }

    throw new Error(`Unsupported token at position ${i}: ${input.slice(i, i + 8)}`)
  }

  tokens.push({ type: 'eof' })
  return tokens
}

const DANGEROUS_PROPERTY = new Set(['__proto__', 'constructor', 'prototype'])

function hasOwn(value: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key)
}

function isDangerousPath(path: string): boolean {
  return path.split('.').some((part) => DANGEROUS_PROPERTY.has(part))
}

function resolvePath(ctx: EvaluationContext, path: string): unknown {
  if (isDangerousPath(path)) return undefined
  const parts = path.split('.')
  let current: unknown = ctx
  for (const part of parts) {
    if (DANGEROUS_PROPERTY.has(part)) return undefined
    if (current == null || typeof current !== 'object') return undefined
    if (!hasOwn(current, part)) return undefined
    current = (current as Record<string, unknown>)[part]
  }
  if (current !== undefined) return current
  // A single argument key that itself contains dots, only when the walk did not resolve.
  if (path.startsWith('args.') && ctx.args && !isDangerousPath(path)) {
    const key = path.slice('args.'.length)
    if (!isDangerousPath(key) && hasOwn(ctx.args, key)) return ctx.args[key]
  }
  if (path === 'tool.name' && ctx.tool?.name) return ctx.tool.name
  if (path.startsWith('tool.args.') && ctx.tool?.args && !isDangerousPath(path)) {
    const key = path.slice('tool.args.'.length)
    if (!isDangerousPath(key) && hasOwn(ctx.tool.args, key)) return ctx.tool.args[key]
  }
  return current
}

function containsValue(current: unknown, arg: unknown, ignoreCase: boolean): boolean {
  if (typeof current === 'string') {
    const haystack = ignoreCase ? current.toLowerCase() : current
    const needle = ignoreCase ? String(arg).toLowerCase() : String(arg)
    return haystack.includes(needle)
  }
  if (Array.isArray(current)) {
    return current.some((item) => {
      if (ignoreCase && typeof item === 'string' && typeof arg === 'string') {
        return item.toLowerCase() === arg.toLowerCase()
      }
      return item === arg
    })
  }
  return false
}

class Parser {
  private pos = 0

  constructor(
    private readonly tokens: Token[],
    private readonly ctx: EvaluationContext
  ) {}

  private peek(): Token {
    return this.tokens[this.pos] ?? { type: 'eof' }
  }

  private consume(): Token {
    const token = this.peek()
    this.pos += 1
    return token
  }

  parse(): boolean {
    const result = this.parseOr()
    if (this.peek().type !== 'eof') {
      throw new Error('Unexpected tokens after expression')
    }
    return result
  }

  private parseOr(): boolean {
    let left = this.parseAnd()
    let next = this.peek()
    while (next.type === 'op' && next.value === '||') {
      this.consume()
      if (left) {
        try {
          this.parseAnd()
        } catch (error) {
          if (!(error instanceof NumericComparisonError) && !(error instanceof NonFiniteComparisonError)) {
            throw error
          }
        }
      } else {
        left = this.parseAnd()
      }
      next = this.peek()
    }
    return left
  }

  private parseAnd(): boolean {
    let left = this.parseComparison()
    let next = this.peek()
    while (next.type === 'op' && next.value === '&&') {
      this.consume()
      if (!left) {
        // The conjunction is already false. Still parse the right side so the
        // token stream stays aligned, but a numeric failure there cannot make
        // this clause true and must not block an unrelated tool.
        try {
          this.parseComparison()
        } catch (error) {
          if (!(error instanceof NumericComparisonError) && !(error instanceof NonFiniteComparisonError)) {
            throw error
          }
        }
      } else {
        left = this.parseComparison()
      }
      next = this.peek()
    }
    return left
  }

  private parseComparison(): boolean {
    const left = this.parsePrimary()
    const op = this.peek()

    if (op.type === 'op' && op.value === 'in') {
      this.consume()
      const values = this.parseArray()
      if (Array.isArray(left)) {
        return values.some((v) => left.includes(v))
      }
      return values.includes(left)
    }

    if (op.type === 'op' && ['==', '!=', '>', '<', '>=', '<='].includes(op.value)) {
      const operator = op.value
      this.consume()
      const right = this.parsePrimary()
      return compare(operator, left, right)
    }

    if (typeof left !== 'boolean') {
      throw new Error('condition must be boolean')
    }
    return left
  }

  private parseArray(): unknown[] {
    if (this.peek().type !== 'lbracket') throw new Error('Expected array literal')
    this.consume()
    const values: unknown[] = []
    if (this.peek().type === 'rbracket') {
      this.consume()
      return values
    }
    while (true) {
      values.push(this.parsePrimary())
      if (this.peek().type === 'comma') {
        this.consume()
        if (this.peek().type === 'rbracket') throw new Error('Trailing comma in array literal')
        continue
      }
      if (this.peek().type === 'rbracket') {
        this.consume()
        return values
      }
      throw new Error('Expected comma between array elements')
    }
  }

  private parsePrimary(): unknown {
    const token = this.peek()

    if (token.type === 'string' || token.type === 'number') {
      this.consume()
      return token.value
    }

    if (token.type === 'boolean' || token.type === 'null') {
      this.consume()
      return token.type === 'boolean' ? token.value : null
    }

    if (token.type === 'ident') {
      this.consume()
      let path = token.value
      let current: unknown = resolvePath(this.ctx, path)

      while (this.peek().type === 'dot') {
        this.consume()
        const member = this.consume()
        const memberName =
          member.type === 'ident' || member.type === 'op' ? member.value : undefined
        if (!memberName) throw new Error('Expected member name after dot')

        if ((memberName === 'contains' || memberName === 'icontains') && this.peek().type === 'lparen') {
          this.consume()
          const arg = this.parsePrimary()
          if (this.peek().type !== 'rparen') throw new Error('Expected closing parenthesis')
          this.consume()
          return containsValue(current, arg, memberName === 'icontains')
        }

        if (DANGEROUS_PROPERTY.has(memberName)) {
          current = undefined
          path = `${path}.${memberName}`
          continue
        }

        path = `${path}.${memberName}`
        current = resolvePath(this.ctx, path)
      }

      return current
    }

    if (token.type === 'lbracket') {
      return this.parseArray()
    }

    if (token.type === 'lparen') {
      this.consume()
      try {
        const inner = this.parseOr()
        if (this.peek().type !== 'rparen') {
          throw new Error('Expected closing parenthesis')
        }
        this.consume()
        return inner
      } catch (error) {
        // Short-circuit `&&` ignores NumericComparisonError on the RHS. When the
        // RHS is parenthesized, consume the closing `)` before rethrowing so the
        // token stream stays aligned (#25).
        if (
          error instanceof NumericComparisonError ||
          error instanceof NonFiniteComparisonError
        ) {
          if (this.peek().type === 'rparen') this.consume()
          throw error
        }
        throw error
      }
    }

    throw new Error(`Unexpected token: ${token.type}`)
  }
}

/** Ordered comparison saw NaN or an infinity. Callers must fail closed. */
export class NonFiniteComparisonError extends Error {
  constructor() {
    super('non-finite values cannot satisfy a numeric comparison')
    this.name = 'NonFiniteComparisonError'
  }
}

/** Ordered comparison saw a value that is not a finite number. Callers must fail closed. */
export class NumericComparisonError extends Error {
  constructor() {
    super('ordered comparison requires finite numbers')
    this.name = 'NumericComparisonError'
  }
}

function compare(operator: string, left: unknown, right: unknown): boolean {
  if (operator === '==' || operator === '!=') {
    if (left === undefined || right === undefined) return false
    return operator === '==' ? left === right : left !== right
  }

  if (typeof left !== 'number' || typeof right !== 'number') {
    throw new NumericComparisonError()
  }
  if (!Number.isFinite(left) || !Number.isFinite(right)) {
    throw new NonFiniteComparisonError()
  }

  if (operator === '>') return left > right
  if (operator === '<') return left < right
  if (operator === '>=') return left >= right
  if (operator === '<=') return left <= right
  return false
}

/** Evaluate a single condition string against context. */
export function evaluateCondition(condition: string, ctx: EvaluationContext): boolean {
  const trimmed = condition.trim()
  if (!trimmed) return false
  const parser = new Parser(tokenize(trimmed), ctx)
  return parser.parse()
}

/** Match a payload that is exactly an example action name. */
export function inferToolFromPayload(payload: string): string | undefined {
  const token = payload.trim().toLowerCase()
  if (token === 'read' || token === 'apply') return token
  return undefined
}

/** Chat / jailbreak fields are not inputs to the evaluator. Typed tool args stay. */
const FREEFORM_ARG_KEYS = new Set([
  'prompt',
  'sourceText',
  'jailbreak',
  'instruction',
  'system',
  'systemPrompt',
  'messages',
  'chat',
  'userMessage',
  'inputText',
])

export function omitFreeformArgs(
  args?: Record<string, unknown>,
): Record<string, unknown> | undefined {
  if (!args) return args
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(args)) {
    if (FREEFORM_ARG_KEYS.has(key)) continue
    out[key] = value
  }
  return out
}

export function buildEvaluationContext(input: {
  toolName?: string
  toolArgs?: Record<string, unknown>
  args?: Record<string, unknown>
  payload?: string
  agentRole?: string
  toolTarget?: string
  context?: Record<string, unknown>
}): EvaluationContext {
  const mergedArgs = omitFreeformArgs(input.toolArgs ?? input.args)
  const inferred =
    input.toolName ?? (input.payload ? inferToolFromPayload(input.payload) : undefined)
  const tool =
    inferred != null
      ? {
          name: inferred,
          args: mergedArgs,
          ...(input.toolTarget != null ? { target: input.toolTarget } : {}),
        }
      : undefined

  return {
    tool,
    args: mergedArgs,
    payload: input.payload,
    agentRole: input.agentRole,
    ...(input.context ? { context: input.context } : {}),
  }
}
