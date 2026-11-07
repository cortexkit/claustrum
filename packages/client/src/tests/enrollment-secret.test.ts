import { describe, expect, test } from 'bun:test'
import { createHash } from 'node:crypto'

import { enrollmentSecretHash, newEnrollmentSecret } from '../index.js'

describe('enrollment request secrets', () => {
  test('hashes decoded bytes using the core enrollment fixed vector', () => {
    // Copied from secret_and_token_hash_share_one_fixed_vector in
    // crates/credentials-core/src/enrollment.rs.
    const requestSecret = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
    const expected = '630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd'

    expect(enrollmentSecretHash(requestSecret)).toBe(expected)
  })

  test('mints 32 random bytes as lowercase hex with their decoded-byte hash', () => {
    const first = newEnrollmentSecret()
    const second = newEnrollmentSecret()

    for (const { requestSecret, requestSecretHash } of [first, second]) {
      expect(requestSecret).toHaveLength(64)
      expect(requestSecret).toMatch(/^[0-9a-f]{64}$/)
      expect(requestSecretHash).toHaveLength(64)
      expect(requestSecretHash).toMatch(/^[0-9a-f]{64}$/)
      expect(requestSecretHash).toBe(createHash('sha256').update(Buffer.from(requestSecret, 'hex')).digest('hex'))
    }
    expect(first.requestSecret).not.toBe(second.requestSecret)
  })

  test('accepts the exact lowercase hex grammar', () => {
    for (const requestSecret of ['00'.repeat(32), 'ab'.repeat(32), 'ff'.repeat(32)]) {
      expect(enrollmentSecretHash(requestSecret)).toMatch(/^[0-9a-f]{64}$/)
    }
  })

  for (const [name, requestSecret] of [
    ['empty', ''],
    ['short', 'a'.repeat(63)],
    ['long', 'a'.repeat(65)],
    ['uppercase', 'AB'.repeat(32)],
    ['non-hex', `${'a'.repeat(63)}g`],
    ['prefixed', `0x${'ab'.repeat(32)}`],
    ['leading space', ` ${'a'.repeat(63)}`],
    ['trailing space', `${'a'.repeat(63)} `],
    ['trailing newline', `${'ab'.repeat(32)}\n`],
    ['non-ASCII', 'ａ'.repeat(64)],
    ['null', null],
    ['undefined', undefined],
    ['number', 0],
    ['boxed string', new String('ab'.repeat(32))],
  ] as const) {
    test(`refuses ${name} request secrets`, () => {
      expect(() => enrollmentSecretHash(requestSecret as string)).toThrow(
        'enrollment request secret must be exactly 64 lowercase hex characters',
      )
    })
  }
})
