import { AsyncLocalStorage } from 'node:async_hooks'
import type { OwnerOnlyPathAsyncOptions } from '@cortexkit/store'
import { checkPrivatePath } from '../private-path.js'
import { createEnrollmentWriter } from '../enrollment.js'

// Fixture identities live only in the test-only source tree.
export const privatePathContext = new AsyncLocalStorage<OwnerOnlyPathAsyncOptions>()
const checkPath: typeof checkPrivatePath = (path, options) => checkPrivatePath(path, privatePathContext.getStore() ?? options)
export const writeEnrollmentTokenFile = createEnrollmentWriter(checkPath)
