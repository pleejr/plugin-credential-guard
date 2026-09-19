import { test, expect, mock } from 'claude-code/testing'
import { calibrate, emptyLedger, LEDGER_KEY, parseLedger, prune, record } from '../hooks/ledger.ts'
import { fingerprint, scanAll } from '../hooks/scan.ts'

/** Sub-threshold: ratio 0.778, below the 0.85 cut. */
const WEAK = 'OAJdjljiaw82nd73jlad00d02jld892gygo'

test('a let-past candidate is recorded as shape, never as the value', () => {
  const { findings, near } = scanAll(`the build used ${WEAK} as its identifier`)
  expect(findings.length).toBe(0)
  expect(near.length).toBe(1)
  const row = near[0]
  expect(row?.fingerprint).toBe(fingerprint(WEAK))
  expect(row?.reason).toBe('ratio')
  expect(JSON.stringify(row).includes(WEAK)).toBe(false)
})

test('repeats collapse onto one row with a count and a tool list', () => {
  const l = emptyLedger()
  const { near } = scanAll(`id ${WEAK}`)
  record(l, near, 'Bash', Date.UTC(2026, 8, 18))
  record(l, near, 'Read', Date.UTC(2026, 8, 19))
  const row = l.rows[fingerprint(WEAK)]
  expect(Object.keys(l.rows).length).toBe(1)
  expect(row?.seen).toBe(2)
  expect(row?.tools).toEqual(['Bash', 'Read'])
  expect(row?.first).toBe('2026-09-18')
  expect(row?.last).toBe('2026-09-19')
})

test('pruning keeps what a threshold learns most from', () => {
  const l = emptyLedger()
  for (let i = 0; i < 10; i++) {
    l.rows[`fp${i}`] = {
      fingerprint: `fp${i}`, length: 30, alphabet: 62, entropy: 4, ratio: 0.8,
      classes: 3, vowelRatio: 0.1, cueDistance: -1, reason: 'ratio',
      seen: i, first: '2026-09-18', last: '2026-09-18', tools: ['Bash'],
    }
  }
  expect(prune(l, 3)).toBe(7)
  expect(Object.keys(l.rows).sort()).toEqual(['fp7', 'fp8', 'fp9'])
})

test('an empty ledger says there is nothing to tune on', () => {
  expect(calibrate(emptyLedger(), 0.85).includes('ledger is empty')).toBe(true)
})

test('the report names the cut and never carries a value', () => {
  const l = emptyLedger()
  record(l, scanAll(`id ${WEAK}`).near, 'Bash', Date.UTC(2026, 8, 18))
  const text = calibrate(l, 0.85)
  expect(text.includes('current cut 0.85')).toBe(true)
  expect(text.includes('0.75–0.80')).toBe(true)
  expect(text.includes(WEAK)).toBe(false)
})

test('a malformed store value degrades to an empty ledger', () => {
  expect(parseLedger('nonsense').rows).toEqual({})
  expect(parseLedger({ version: 99, rows: { a: 1 } }).rows).toEqual({})
})

// The ledger watches the surfaces the shape rules run on, and `shapeRules`
// defaults to `prompt`: a tool result contributes nothing until that option
// says `prompt+result` or `all`.
test('a prompt writes a ledger row through the engine', async ($, on) => {
  mock.clock(on)
  mock.store(on)
  on('prompt.submit', ($$, e) => ({ text: e.text }))

  await $.prompt.submit({ text: `build id ${WEAK}`, wait: false, origin: { kind: 'composer' } })
  const out = await $.command.run({
    command: 'credential-guard',
    args: '',
    origin: { kind: 'composer' },
    presentation: { isFullscreen: false, columns: 100 },
  })
  expect(out.text?.includes('1 distinct shapes')).toBe(true)
  expect(out.text?.includes(WEAK)).toBe(false)
})
