import { expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { decodeScopedInventory } from '../wire.js'

function producerReply(): any {
  const vector = JSON.parse(readFileSync(new URL('../../../../crates/credentials-module/tests/vectors/list-scoped-v2.json', import.meta.url), 'utf8'))
  return vector.cases[0].reply
}

test('provider catalog decodes real vault rows with service, incarnation and tier time', () => {
  const decoded = decodeScopedInventory(producerReply(), () => {})
  const kimi = decoded.rows.find((row) => row.id === 'apikey:kimi-for-coding')!
  expect(kimi.provider).toBe('kimi-for-coding')
  expect(kimi.incarnation).toBe('00000000000000000000000000000002')
  expect(kimi.planTierObservedAtMs).toBe(1_700_000_000_000)
  expect(decoded.rows.find((row) => row.id === 'apikey:exa')!.planTierObservedAtMs).toBeUndefined()
})

test('provider catalog tolerates older vault omissions and explicit nulls', () => {
  for (const nulls of [false, true]) {
    const reply = producerReply()
    for (const row of reply.result.credentials) {
      for (const field of ['provider', 'incarnation', 'plan_tier_observed_at_ms']) {
        if (nulls) row[field] = null
        else delete row[field]
      }
    }
    const decoded = decodeScopedInventory(reply, () => {})
    expect(decoded.rows).toHaveLength(4)
    for (const row of decoded.rows) {
      expect(row.provider).toBeUndefined()
      expect(row.incarnation).toBeUndefined()
      expect(row.planTierObservedAtMs).toBeUndefined()
    }
  }
})

test('provider catalog rejects malformed additive metadata', () => {
  for (const [field, value] of [['provider', 1], ['incarnation', []], ['plan_tier_observed_at_ms', 'yesterday'], ['plan_tier_observed_at_ms', 1.5]] as const) {
    const reply = producerReply()
    reply.result.credentials[0][field] = value
    expect(() => decodeScopedInventory(reply, () => {})).toThrow()
  }
})
