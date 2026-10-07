/**
 * Safe condition evaluator, no eval(); supports the specification expression grammar.
 */

export interface EvaluationContext {
  readonly tool?: {
    readonly name?: string
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
  | { type: 'op'; value: string }
  | { type: 'lparen' }
  | { type: 'rparen' }
  | { type: 'lbracket' }
  | { type: 'rbracket' }
  | { type: 'comma' }
  | { type: 'dot' }
  | { type: 'eof' }

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
      i += 1
      let value = ''
      while (i < input.length && input[i] !== quote) {
        value += input[i]
        i += 1
      }
      i += 1
      tokens.push({ type: 'string', value })
      continue
    }

    if (/[0-9]/.test(ch)) {
      let num = ''
      while (i < input.length && /[0-9.]/.test(input[i])) {
        num += input[i]
        i += 1
      }
      tokens.push({ type: 'number', value: Number(num) })
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
      } else {
        tokens.push({ type: 'ident', value: ident })
      }
      continue
    }

    const two = input.slice(i, i + 2)
    if (['==', '!=', '>=', '<=', '&&'].includes(two)) {
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

function resolvePath(ctx: EvaluationContext, path: string): unknown {
  const parts = path.split('.')
  let current: unknown = ctx
  for (const part of parts) {
    if (current == null || typeof current !== 'object') return undefined
    current = (current as Record<string, unknown>)[part]
  }
  if (path.startsWith('args.') && current === undefined && ctx.args) {
    return ctx.args[path.slice('args.'.length)]
  }
  if (path === 'tool.name' && ctx.tool?.name) return ctx.tool.name
  if (path.startsWith('tool.args.') && ctx.tool?.args) {
    return ctx.tool.args[path.slice('tool.args.'.length)]
  }
  return current
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
    return this.parseAnd()
  }

  private parseAnd(): boolean {
    let left = this.parseComparison()
    let next = this.peek()
    while (next.type === 'op' && next.value === '&&') {
      this.consume()
      const right = this.parseComparison()
      left = left && right
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

    return Boolean(left)
  }

  private parseArray(): unknown[] {
    this.consume() // [
    const values: unknown[] = []
    while (this.peek().type !== 'rbracket') {
      values.push(this.parsePrimary())
      if (this.peek().type === 'comma') this.consume()
    }
    this.consume() // ]
    return values
  }

  private parsePrimary(): unknown {
    const token = this.peek()

    if (token.type === 'string' || token.type === 'number') {
      this.consume()
      return token.value
    }

    if (token.type === 'ident') {
      this.consume()
      const base = token.value

      if (this.peek().type === 'dot') {
        this.consume()
        const method = this.consume()
        const methodName =
          method.type === 'ident' || method.type === 'op' ? method.value : undefined
        if (!methodName) throw new Error('Expected method name after dot')

        if (methodName === 'contains' && this.peek().type === 'lparen') {
          this.consume()
          const arg = this.parsePrimary()
          if (this.peek().type === 'rparen') this.consume()
          const haystack = String(resolvePath(this.ctx, base) ?? '')
          return haystack.toLowerCase().includes(String(arg).toLowerCase())
        }

        const path = `${base}.${methodName}`
        if (this.peek().type === 'dot') {
          this.consume()
          const tail = this.consume()
          if (tail.type !== 'ident') throw new Error('Expected identifier')
          return resolvePath(this.ctx, `${path}.${tail.value}`)
        }
        return resolvePath(this.ctx, path)
      }

      return resolvePath(this.ctx, base)
    }

    if (token.type === 'lbracket') {
      return this.parseArray()
    }

    if (token.type === 'lparen') {
      this.consume()
      const inner = this.parseOr()
      if (this.peek().type === 'rparen') this.consume()
      return inner
    }

    throw new Error(`Unexpected token: ${token.type}`)
  }
}

function compare(operator: string, left: unknown, right: unknown): boolean {
  if (operator === '==') return left === right
  if (operator === '!=') return left !== right

  const ln = typeof left === 'number' ? left : Number(left)
  const rn = typeof right === 'number' ? right : Number(right)
  if (Number.isNaN(ln) || Number.isNaN(rn)) return false

  if (operator === '>') return ln > rn
  if (operator === '<') return ln < rn
  if (operator === '>=') return ln >= rn
  if (operator === '<=') return ln <= rn
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
  context?: Record<string, unknown>
}): EvaluationContext {
  const mergedArgs = omitFreeformArgs(input.toolArgs ?? input.args)
  const inferred =
    input.toolName ?? (input.payload ? inferToolFromPayload(input.payload) : undefined)

  return {
    tool: inferred
      ? { name: inferred, args: mergedArgs }
      : input.toolName
        ? { name: input.toolName, args: mergedArgs }
        : undefined,
    args: mergedArgs,
    payload: input.payload,
    agentRole: input.agentRole,
    ...(input.context ? { context: input.context } : {}),
  }
}
