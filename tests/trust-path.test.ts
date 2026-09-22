import { test, expect } from 'claude-code/testing'
import { expandTrustPath } from '../hooks/register.ts'

test('a ~/ trustFile expands against HOME', () => {
  expect(expandTrustPath('~/.claude/credential-guard/trust.json', '/Users/someone')).toBe(
    '/Users/someone/.claude/credential-guard/trust.json',
  )
})

test('a path that is already absolute is left alone', () => {
  expect(expandTrustPath('/etc/trust.json', '/Users/someone')).toBe('/etc/trust.json')
})

test('an unset HOME yields the literal path, never a half-expanded one', () => {
  // Trusting nothing is the correct failure; a corrupted path that happens to
  // exist would be worse than one that plainly does not.
  expect(expandTrustPath('~/trust.json', undefined)).toBe('~/trust.json')
  expect(expandTrustPath('~/trust.json', '')).toBe('~/trust.json')
})

test('a Promise where HOME was expected never reaches the path', () => {
  // The regression this file exists for. `$.env.get` is async; the first cut of
  // loadTrust forgot the `await`, so HOME was a Promise, the comparison against
  // '' was always true, and the path began `[object Promise]`. Types are erased
  // at runtime, so only a runtime check catches a caller that does it again.
  // The cast is the point: the compiler rejects this call, which is the first
  // line of defence. Types are erased at load, so the runtime check is the
  // second, and this asserts the second one holds.
  const unawaited = Promise.resolve('/Users/someone') as unknown as string
  const path = expandTrustPath('~/trust.json', unawaited)
  expect(path.includes('[object Promise]')).toBe(false)
  expect(path).toBe('~/trust.json')
})
