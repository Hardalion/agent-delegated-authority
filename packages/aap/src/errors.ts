export class AuthorityError extends Error {
  readonly code: string
  readonly authenticated: boolean

  constructor(code: string, message: string, authenticated = false) {
    super(message)
    this.name = 'AuthorityError'
    this.code = code
    this.authenticated = authenticated
  }
}
