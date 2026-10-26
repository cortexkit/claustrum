import { AsyncLocalStorage } from 'node:async_hooks'
import type { OwnerOnlyPathAsyncOptions } from '@cortexkit/store'
import { checkPrivatePath } from '../private-path.js'
import { createManifestLock } from '../manifest-lock.js'
import { createEnrollmentWriter } from '../enrollment.js'
import { readHandleFile as readHandles } from '../handles.js'

// Fixture identities and mutable race scheduling live only in the excluded test tree.
export const privatePathContext = new AsyncLocalStorage<OwnerOnlyPathAsyncOptions>()
type LockOptions = Parameters<typeof createManifestLock>[0]
let lockOptions: LockOptions
export function setLockOptions(options?: LockOptions): void { lockOptions = options }
const checkPath: typeof checkPrivatePath = (path, options) => checkPrivatePath(path, privatePathContext.getStore() ?? options)
const lock = () => createManifestLock({ ...lockOptions, checkPath })
export const withManifestLock: ReturnType<typeof createManifestLock>['withManifestLock'] = (...args) => lock().withManifestLock(...args)
export const writeHandleFileLocked: ReturnType<typeof createManifestLock>['writeHandleFileLocked'] = (...args) => lock().writeHandleFileLocked(...args)
export const writeEnrollmentTokenFile = createEnrollmentWriter(checkPath)
export const readHandleFile: typeof readHandles = (path, io) => readHandles(path, { ...io, pathOptions: privatePathContext.getStore() ?? io?.pathOptions })
