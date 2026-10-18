import type { BindIdentity, SubcClient } from '@cortexkit/subc-client'
import { ClaustrumCredentialError } from './errors.js'

export type ScopedWatchNotice = {
  kind: 'changed'
  epoch: string
  seq: number
  view: string
  keys: string
}

export type ScopedWatchOutcome =
  | { kind: 'refused'; error: ClaustrumCredentialError }
  | { kind: 'ended' }
  | { kind: 'not_accepting' }
  | { kind: 'transport_lost'; error: unknown }
  | { kind: 'unsupported' }
  | { kind: 'stopped' }

export class ScopedWatchError extends Error {
  constructor(readonly code: 'invalid_notice' | 'callback_failed' | 'invalid_response') {
    super(`Scoped watch failed: ${code}`)
    this.name = 'ScopedWatchError'
  }
}

export type ScopedWatch = { stop(): void; closed: Promise<ScopedWatchOutcome> }
export type ScopedWatchOptions = { enrollmentToken?: string }

/** Decode only the notice schema; sequence gaps and new epochs belong to the consumer. */
export function decodeScopedWatchNotice(bytes: Uint8Array): ScopedWatchNotice {
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    if (
      value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== 'epoch,keys,kind,seq,view' ||
      value.kind !== 'changed' || typeof value.epoch !== 'string' || value.epoch.length === 0 ||
      !Number.isSafeInteger(value.seq) || value.seq <= 0 ||
      typeof value.view !== 'string' || typeof value.keys !== 'string'
    ) throw new ScopedWatchError('invalid_notice')
    return value
  } catch {
    throw new ScopedWatchError('invalid_notice')
  }
}

export function openScopedWatch(
  client: Pick<SubcClient, 'routeOpen' | 'subscribe' | 'closeRoute'>,
  identity: BindIdentity,
  onNotice: (notice: ScopedWatchNotice) => void,
  options: ScopedWatchOptions,
  readScoped: () => Promise<unknown>,
): ScopedWatch {
  let settled = false
  let notices = 0
  let subscription: ReturnType<SubcClient['subscribe']> | undefined
  let route: Awaited<ReturnType<SubcClient['routeOpen']>> | undefined
  let resolve!: (outcome: ScopedWatchOutcome) => void
  let reject!: (error: ScopedWatchError) => void
  const closed = new Promise<ScopedWatchOutcome>((yes, no) => { resolve = yes; reject = no })
  const finish = (outcome: ScopedWatchOutcome | ScopedWatchError): void => {
    if (settled) return
    settled = true
    subscription?.unsubscribe()
    if (route) void client.closeRoute(route).catch(() => {})
    if (outcome instanceof ScopedWatchError) reject(outcome)
    else resolve(outcome)
  }
  void (async () => {
    try {
      route = await client.routeOpen(
        { kind: 'management_surface', module_id: 'claustrum' }, identity, { consumerIdentity: null },
      )
      if (settled) { await client.closeRoute(route); return }
      subscription = client.subscribe(route, {
        method: 'auth.watch_scoped',
        params: options.enrollmentToken === undefined ? {} : { enrollment_token: options.enrollmentToken },
      }, (bytes) => {
        if (settled) return
        let notice: ScopedWatchNotice
        try { notice = decodeScopedWatchNotice(bytes) }
        catch { finish(new ScopedWatchError('invalid_notice')); return }
        notices++
        try { onNotice(notice) }
        catch { finish(new ScopedWatchError('callback_failed')) }
      })
      await subscription.closed
      if (settled) return
      // The SDK erases Response bodies. Only an immediate close needs a confirming
      // list read; after notices, the caller reopens once to discover a revocation.
      if (notices > 0) finish({ kind: 'ended' })
      else {
        try { await readScoped(); finish({ kind: 'not_accepting' }) }
        catch (error) {
          if (error instanceof ClaustrumCredentialError && error.code !== 'invalid_response') {
            finish({ kind: 'refused', error })
          } else if (error instanceof ClaustrumCredentialError) finish(new ScopedWatchError('invalid_response'))
          else finish({ kind: 'transport_lost', error })
        }
      }
    } catch (error) {
      const code = error !== null && typeof error === 'object' && 'code' in error ? error.code : undefined
      finish(code === 'unknown_method' ? { kind: 'unsupported' } : { kind: 'transport_lost', error })
    }
  })()
  return { stop: () => finish({ kind: 'stopped' }), closed }
}
