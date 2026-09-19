/**
 * The trust list: the fingerprints of values that a corpus the operator vouches
 * for already holds, so a page that passed a write-time gate stops being
 * redacted every time it is read back.
 *
 * The premise is provenance, not detection. A vault whose boundary rule says it
 * carries no secrets, and whose pre-commit gate holds that rule, has already
 * answered the question this plugin asks -- for the text it tracks. Harvesting
 * it turns that answer into fingerprints the detector can honour.
 *
 * Two limits are deliberate, because the premise is a convention rather than a
 * proof:
 *
 *   1. **Only the shape-only rules can be vouched for.** `entropy` and `hex`
 *      fire on how a run LOOKS, which is where a benign identifier in a note
 *      collides with a key. A named provider pattern, and an assignment whose
 *      own text calls the value a credential, are refused: those are not noise
 *      to trust away but a finding the vouching corpus should fix.
 *   2. **Values are never written down.** An entry is a fingerprint, a shape
 *      and the path it was seen in. A trust file that stored the trusted values
 *      would be the credential store this plugin exists to avoid.
 */
import { scan, type ScanOptions } from './scan.ts'

export const TRUST_VERSION = 1

/**
 * May a corpus vouch for this rule's finding? Only the rules that judged a run
 * by its shape alone. `assigned:*` is refused with the named patterns: the text
 * beside the value said it was a credential, and a corpus saying otherwise is
 * the disagreement worth reading, not the one worth silencing.
 */
export function isTrustableRule(rule: string): boolean {
  return rule === 'entropy' || rule === 'hex' || rule === 'entropy-cue' || rule === 'hex-cue'
}

/** One vouched-for value: its fingerprint and shape, never the value. */
export type TrustEntry = {
  fingerprint: string
  rule: string
  length: number
  ratio: number
  /** The first tracked file it was seen in, so a stale entry can be traced. */
  seenIn: string
}

/** A finding the corpus was NOT allowed to vouch for. */
export type TrustRefusal = {
  rule: string
  fingerprint: string
  seenIn: string
}

export type TrustFile = {
  version: number
  generatedAt: string
  /** The corpus root, for the record: the trust is only as good as its gate. */
  root: string
  files: number
  entries: TrustEntry[]
  refused: TrustRefusal[]
}

/**
 * Scans a corpus and returns what it may vouch for. `files` is the corpus's
 * TRACKED text -- what its write-time gate actually saw -- not a directory
 * walk, which would sweep in scratch files and other checkouts of the same
 * repository.
 */
export function harvest(
  files: Iterable<{ path: string; text: string }>,
  opts: Partial<ScanOptions> = {},
  now: Date = new Date(),
  root = '',
): TrustFile {
  const entries = new Map<string, TrustEntry>()
  const refused = new Map<string, TrustRefusal>()
  let count = 0
  for (const { path, text } of files) {
    count++
    for (const f of scan(text, opts)) {
      if (!isTrustableRule(f.rule)) {
        if (!refused.has(f.fingerprint)) {
          refused.set(f.fingerprint, { rule: f.rule, fingerprint: f.fingerprint, seenIn: path })
        }
        continue
      }
      if (entries.has(f.fingerprint)) continue
      entries.set(f.fingerprint, {
        fingerprint: f.fingerprint,
        rule: f.rule,
        length: f.value.length,
        ratio: Number(f.ratio.toFixed(3)),
        seenIn: path,
      })
    }
  }
  // A value the corpus both vouches for and is refused on stays refused: the
  // stronger rule is the one that saw more than shape.
  for (const fp of refused.keys()) entries.delete(fp)
  return {
    version: TRUST_VERSION,
    // The LOCAL date, not the UTC one: this is read beside a commit message and
    // a note, which are dated where the operator is standing.
    generatedAt: `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`,
    root,
    files: count,
    entries: [...entries.values()].sort((a, b) => a.fingerprint.localeCompare(b.fingerprint)),
    refused: [...refused.values()].sort((a, b) => a.fingerprint.localeCompare(b.fingerprint)),
  }
}

/**
 * Reads a trust file's fingerprints, tolerantly. A trust list is a SUPPRESSION
 * list, so a malformed one must yield nothing and say so rather than throw
 * inside a hook -- the failure mode of a guard is the one that matters.
 */
export function parseTrust(raw: unknown): {
  fingerprints: Set<string>
  generatedAt: string
  refused: number
  error?: string
} {
  const empty = { fingerprints: new Set<string>(), generatedAt: '', refused: 0 }
  if (raw === null || typeof raw !== 'object') return { ...empty, error: 'not an object' }
  const o = raw as Partial<TrustFile>
  if (o.version !== TRUST_VERSION) return { ...empty, error: `version ${String(o.version)} is not ${TRUST_VERSION}` }
  if (!Array.isArray(o.entries)) return { ...empty, error: 'no entries' }
  const fingerprints = new Set<string>()
  for (const e of o.entries) {
    if (e === null || typeof e !== 'object') continue
    const { fingerprint, rule } = e as TrustEntry
    if (typeof fingerprint !== 'string' || !/^[0-9a-f]{8}$/.test(fingerprint)) continue
    // The rule is re-checked on the way IN as well as on the way out: a trust
    // file is an ordinary file on disk, and a hand-edited one must not be able
    // to allow a provider-shaped credential the generator would have refused.
    if (typeof rule !== 'string' || !isTrustableRule(rule)) continue
    fingerprints.add(fingerprint)
  }
  return {
    fingerprints,
    generatedAt: typeof o.generatedAt === 'string' ? o.generatedAt : '',
    refused: Array.isArray(o.refused) ? o.refused.length : 0,
  }
}
