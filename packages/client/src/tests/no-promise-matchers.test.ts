import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { expect, test } from 'bun:test'

const matcherNames = [['resol', 'ves'].join(''), ['rejec', 'ts'].join('')]
const matcherAccess = new RegExp('\\.' + '\\s*' + `(?:${matcherNames.join('|')})` + '\\b')

function testSources(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) return testSources(path)
    return entry.isFile() && entry.name.endsWith('.test.ts') ? [path] : []
  })
}

test('client tests avoid bun:test promise matchers', () => {
  const violations = testSources(import.meta.dir).flatMap((path) => {
    const source = readFileSync(path, 'utf8')
    return [...source.matchAll(new RegExp(matcherAccess.source, 'g'))].map((match) => {
      const line = source.slice(0, match.index).split(/\r?\n/).length
      return `${path}:${line}: use a plain await with rejectionOf or throwerOf instead`
    })
  })
  expect(violations).toEqual([])
})
