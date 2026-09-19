import { test, expect } from 'claude-code/testing'
import { harvest, isTrustableRule, parseTrust, TRUST_VERSION } from '../hooks/trust.ts'
import { fingerprint, scan } from '../hooks/scan.ts'

const KEY = 'Xq7vKpL2ZmR8tNwB4dYh6JcF9sQaZ3eT'

test('a corpus may vouch for a shape-only finding', () => {
  const page = `the miner wrote ${KEY} into its config`
  expect(scan(page).length).toBe(1)

  const trust = harvest([{ path: 'projects/incident.md', text: page }])
  expect(trust.entries.length).toBe(1)
  expect(trust.entries[0]?.fingerprint).toBe(fingerprint(KEY))
  expect(trust.entries[0]?.seenIn).toBe('projects/incident.md')
  expect(trust.refused.length).toBe(0)

  // and the detector honours it, which is the whole point
  expect(scan(page, { allow: new Set([fingerprint(KEY)]) }).length).toBe(0)
})

test('a corpus may not vouch for a provider-shaped credential', () => {
  const trust = harvest([
    { path: 'raw/review.md', text: 'the example reads ghp_0123456789abcdef0123456789abcdef01234567' },
  ])
  expect(trust.entries.length).toBe(0)
  expect(trust.refused.length).toBe(1)
  expect(trust.refused[0]?.rule).toBe('github-token')
})

test('an assignment the text called a credential is refused too', () => {
  const trust = harvest([{ path: 'notes/env.md', text: `DATABASE_PASSWORD=${KEY}` }])
  expect(trust.entries.length).toBe(0)
  expect(trust.refused.length).toBe(1)
  expect(isTrustableRule(trust.refused[0]?.rule ?? '')).toBe(false)
})

test('a value both vouched for and refused stays refused', () => {
  const trust = harvest([
    { path: 'projects/incident.md', text: `the miner wrote ${KEY} into its config` },
    { path: 'notes/env.md', text: `DATABASE_PASSWORD=${KEY}` },
  ])
  expect(trust.entries.length).toBe(0)
  expect(trust.refused.length).toBe(1)
})

test('a trust file never carries the values it vouches for', () => {
  const trust = harvest([{ path: 'projects/incident.md', text: `saw ${KEY} here` }])
  expect(JSON.stringify(trust).includes(KEY)).toBe(false)
})

test('a malformed or hand-widened trust list trusts nothing', () => {
  expect(parseTrust(null).fingerprints.size).toBe(0)
  expect(parseTrust({ version: 99, entries: [] }).error).toBeDefined()
  expect(parseTrust({ version: TRUST_VERSION }).error).toBeDefined()
  // a rule the generator would have refused is refused again on the way in
  const widened = {
    version: TRUST_VERSION,
    entries: [
      { fingerprint: 'abcdef01', rule: 'github-token' },
      { fingerprint: 'not-hex', rule: 'entropy' },
      { fingerprint: 'abcdef02', rule: 'entropy' },
    ],
  }
  const parsed = parseTrust(widened)
  expect(parsed.fingerprints.size).toBe(1)
  expect(parsed.fingerprints.has('abcdef02')).toBe(true)
})
