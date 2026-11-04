export const ERROR_CLASS_WIRE_SET = [
  'transient',
  'permanent',
  'auth_required',
  'context_overflow',
] as const

export type ClaustrumCredentialErrorClass = (typeof ERROR_CLASS_WIRE_SET)[number] | 'unknown'
export type ClaustrumCredentialErrorAction =
  | 'gone'
  | 'reauth'
  | 'retry'
  | 'reduce_and_retry'
  | 'degraded'

export class ClaustrumCredentialError extends Error {
  readonly ['class']: ClaustrumCredentialErrorClass

  constructor(
    public readonly code: string,
    errorClass: ClaustrumCredentialErrorClass,
    public readonly action: ClaustrumCredentialErrorAction,
    public readonly rawClass?: string,
  ) {
    super(`Claustrum credential request failed: ${code}`)
    this.name = 'ClaustrumCredentialError'
    this['class'] = errorClass
  }
}

type UnknownClassLogger = (errorClass: string) => void

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function credentialErrorAction(
  errorClass: ClaustrumCredentialErrorClass,
): ClaustrumCredentialErrorAction {
  switch (errorClass) {
    case 'permanent':
      return 'gone'
    case 'auth_required':
      return 'reauth'
    case 'context_overflow':
      return 'reduce_and_retry'
    case 'transient':
      return 'retry'
    case 'unknown':
      return 'degraded'
  }
}

export function asCredentialError(
  response: unknown,
  fallbackCode = 'invalid_response',
  logUnknownClass: UnknownClassLogger = (errorClass) => console.warn(errorClass),
): ClaustrumCredentialError {
  const result = isRecord(response) && isRecord(response.result) ? response.result : undefined
  const error = result && isRecord(result.error) ? result.error : undefined
  const rawClass = error?.class
  const rawCode = error?.code
  // An unfamiliar class specifies no known remedy. Preserve it for diagnostics,
  // but expose a degraded state rather than guessing that retrying will help.
  // A known class without a code is still malformed and must not drive a
  // definitive action such as `gone`; keep its existing invalid-response fallback.
  const hasValidClass = typeof rawClass === 'string' && (ERROR_CLASS_WIRE_SET as readonly string[]).includes(rawClass)
  const hasCode = typeof rawCode === 'string'
  const errorClass: ClaustrumCredentialErrorClass = !hasValidClass
    ? 'unknown'
    : hasCode ? rawClass as ClaustrumCredentialErrorClass : 'transient'
  if (typeof rawClass !== 'string') logUnknownClass('unknown')
  else if (!hasValidClass) logUnknownClass(rawClass)
  const code = hasCode ? rawCode : fallbackCode
  return new ClaustrumCredentialError(
    code,
    errorClass,
    credentialErrorAction(errorClass),
    typeof rawClass === 'string' ? rawClass : undefined,
  )
}

export function hasCredentialError(response: unknown): boolean {
  return (
    isRecord(response) &&
    isRecord(response.result) &&
    isRecord(response.result.error)
  )
}
