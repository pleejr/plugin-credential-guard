/**
 * The near-miss ledger: what the detector saw and let past, kept as SHAPE only.
 *
 * A ledger of maybe-secrets must not itself be a secret store, so a row holds a
 * fingerprint and a handful of numbers and never the value. Nothing here can be
 * turned back into a credential, which is why it is safe to keep on disk in
 * `$.store` and safe to print in a report.
 *
 * What it buys: the 0.85 threshold was chosen against a corpus I wrote. The
 * ledger says what YOUR traffic actually looks like just below the cut, so the
 * next threshold is picked from a distribution rather than from a guess.
 */
import type { NearMiss, RejectReason } from './scan.ts'

export const LEDGER_KEY = 'entropy-guard:ledger'
export const LEDGER_VERSION = 1

export type LedgerRow = NearMiss & {
  /** How many times this exact shape was seen. */
  seen: number
  /** First and last dates, `YYYY-MM-DD`; days, not timestamps. */
  first: string
  last: string
  /** Which tools it came through, at most eight. */
  tools: string[]
}

export type Ledger = {
  version: number
  /** By fingerprint, so a value seen five hundred times is one row. */
  rows: Record<string, LedgerRow>
}

export function emptyLedger(): Ledger {
  return { version: LEDGER_VERSION, rows: {} }
}

/** Reads what `$.store` held, tolerating anything that is not a ledger. */
export function parseLedger(raw: unknown): Ledger {
  if (raw === null || typeof raw !== 'object') return emptyLedger()
  const l = raw as Partial<Ledger>
  if (l.version !== LEDGER_VERSION || l.rows === null || typeof l.rows !== 'object') return emptyLedger()
  return { version: LEDGER_VERSION, rows: l.rows as Record<string, LedgerRow> }
}

/** `YYYY-MM-DD` for an epoch time. */
export function day(at: number): string {
  return new Date(at).toISOString().slice(0, 10)
}

/** Folds observations into the ledger, merging repeats onto one row. */
export function record(ledger: Ledger, near: readonly NearMiss[], tool: string, at: number): void {
  const today = day(at)
  for (const n of near) {
    const existing = ledger.rows[n.fingerprint]
    if (existing === undefined) {
      ledger.rows[n.fingerprint] = { ...n, seen: 1, first: today, last: today, tools: [tool] }
      continue
    }
    existing.seen += 1
    existing.last = today
    if (!existing.tools.includes(tool) && existing.tools.length < 8) existing.tools.push(tool)
  }
}

/**
 * Keeps the ledger under `max` rows. `$.store` rejects a store over 4 MiB of
 * JSON in all, and this plugin is not the only thing in it.
 *
 * What goes first is what a threshold would learn least from: seen once, and
 * oldest.
 */
export function prune(ledger: Ledger, max: number): number {
  const rows = Object.entries(ledger.rows)
  if (rows.length <= max) return 0
  rows.sort((a, b) => b[1].seen - a[1].seen || b[1].last.localeCompare(a[1].last) || b[1].ratio - a[1].ratio)
  const dropped = rows.slice(max)
  for (const [fp] of dropped) delete ledger.rows[fp]
  return dropped.length
}

const BUCKETS = [0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1.01] as const
const CUTS = [0.95, 0.9, 0.85, 0.8, 0.75, 0.7] as const

function bar(n: number, most: number, width = 28): string {
  if (most <= 0) return ''
  return '#'.repeat(Math.max(n > 0 ? 1 : 0, Math.round((n / most) * width)))
}

/**
 * The calibration report.
 *
 * It says what LOWERING the bar would cost, exactly, because every row here is
 * something the detector let past. It cannot say what lowering the bar would
 * CATCH: nothing in the ledger is labelled, and a fingerprint cannot be read
 * back into a value. That half needs you to say "that one was a secret" while
 * the value is still in the session.
 */
export function calibrate(ledger: Ledger, currentCut: number): string {
  const rows = Object.values(ledger.rows)
  if (rows.length === 0) {
    return [
      'entropy-guard — calibration',
      '',
      'The ledger is empty. Nothing has been seen and let past yet, so there is',
      'nothing to tune on. It fills as tools return output; come back later.',
    ].join('\n')
  }

  const observations = rows.reduce((n, r) => n + r.seen, 0)
  const byReason = new Map<RejectReason, number>()
  for (const r of rows) byReason.set(r.reason, (byReason.get(r.reason) ?? 0) + 1)

  const hist: number[] = BUCKETS.slice(0, -1).map(() => 0)
  for (const r of rows) {
    for (let i = BUCKETS.length - 2; i >= 0; i--) {
      const lo = BUCKETS[i]
      const hi = BUCKETS[i + 1]
      if (lo !== undefined && hi !== undefined && r.ratio >= lo && r.ratio < hi) {
        hist[i] = (hist[i] ?? 0) + 1
        break
      }
    }
  }
  const most = Math.max(...hist)

  const onRatio = rows.filter((r) => r.reason === 'ratio')
  const lines: string[] = [
    'entropy-guard — calibration',
    '',
    `${rows.length} distinct shapes, ${observations} sightings, current cut ${currentCut}.`,
    'Every row is something the detector SAW and LET PAST. Values are not kept.',
    '',
    'Normalized entropy of what was let past:',
  ]
  for (let i = 0; i < hist.length; i++) {
    const lo = BUCKETS[i]
    const hi = BUCKETS[i + 1]
    const n = hist[i] ?? 0
    if (lo === undefined || hi === undefined) continue
    lines.push(`  ${lo.toFixed(2)}–${Math.min(hi, 1).toFixed(2)}  ${String(n).padStart(5)}  ${bar(n, most)}`)
  }

  lines.push('', 'Which filter let it past:')
  for (const [reason, n] of [...byReason.entries()].sort((a, b) => b[1] - a[1])) {
    lines.push(`  ${reason.padEnd(14)} ${String(n).padStart(5)}`)
  }

  lines.push('', 'What a lower cut would newly flag (shapes rejected on ratio alone):')
  for (const cut of CUTS) {
    const n = onRatio.filter((r) => r.ratio >= cut).length
    const sightings = onRatio.filter((r) => r.ratio >= cut).reduce((a, r) => a + r.seen, 0)
    const mark = Math.abs(cut - currentCut) < 1e-9 ? '  <- current' : ''
    lines.push(`  ${cut.toFixed(2)}  ${String(n).padStart(5)} shapes  ${String(sightings).padStart(6)} sightings${mark}`)
  }

  const cued = rows.filter((r) => r.cueDistance >= 0)
  if (cued.length > 0) {
    lines.push(
      '',
      `${cued.length} of these sat within reach of a cue word ("api key", "token", ...)`,
      'and still did not clear the lowered bar; they are the best candidates to look at.',
    )
  }

  lines.push(
    '',
    'This says what a lower cut would COST. It cannot say what one would CATCH:',
    'nothing here is labelled, and a fingerprint does not read back into a value.',
  )
  return lines.join('\n')
}
