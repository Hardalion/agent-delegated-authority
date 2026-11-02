export class DemoError extends Error {
  readonly status: number
  readonly code: string

  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'DemoError'
    this.status = status
    this.code = code
  }
}
