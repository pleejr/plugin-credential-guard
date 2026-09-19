/**
 * The vault: where a detected value lives once the transcript stops holding it.
 *
 * Two tiers.
 *   session   an in-memory map, fingerprint -> value, gone when the session is
 *   keychain  the macOS login Keychain, under one service, one item per
 *             fingerprint, so a value survives into later sessions
 *
 * An index of WHAT is held (fingerprint, label, rule, date) lives in `$.store`,
 * which is plain JSON on disk. The VALUES never go there -- only the Keychain
 * holds those, and only after the person said so.
 *
 * `security` is driven by argv with no shell, and the password is fed on stdin
 * rather than as an argument, so the value never appears in the process table.
 */

export const SERVICE = 'claude-code-credential-guard'
export const INDEX_KEY = 'credential-guard:index'

/** `$.process.run`, narrowed to what this module needs, so it can be faked. */
export type Run = (
  argv: readonly string[],
  init?: { stdin?: string; timeoutMs?: number },
) => Promise<{ exitCode: number; stdout: string; stderr: string }>

export type VaultEntry = {
  /** The name the person gave it; what `[secret:LABEL]` refers to. */
  label: string
  /** The rule that caught it, for the listing. */
  rule: string
  /** Epoch milliseconds. */
  savedAt: number
}

/** fingerprint -> entry. What `$.store` holds; never a value. */
export type VaultIndex = Record<string, VaultEntry>

/** `[redacted <rule> #<fingerprint>]`, the marker a redaction leaves behind. */
const MARKER = /\[redacted [^\]\s]+ #([0-9a-f]{8})\]/g

/** `[secret:LABEL]`, the durable reference a saved secret answers to. */
const ALIAS = /\[secret:([A-Za-z0-9_-]{1,64})\]/g

/** A label is uppercase, and is its own identifier. */
export function normalizeLabel(raw: string): string {
  const s = raw.trim().toUpperCase().replace(/[^A-Z0-9_-]+/g, '_').replace(/^_+|_+$/g, '')
  return s.length === 0 ? 'SECRET' : s.slice(0, 64)
}

/** A label worth suggesting for a finding of this rule. */
export function suggestLabel(rule: string, fingerprint: string): string {
  const assigned = /^assigned:(.+)$/.exec(rule)
  if (assigned?.[1] !== undefined) return normalizeLabel(assigned[1])
  return normalizeLabel(`${rule}_${fingerprint}`)
}

/** Every fingerprint and label referenced by markers in `text`. */
export function referencesIn(text: string): { fingerprints: string[]; labels: string[] } {
  MARKER.lastIndex = 0
  ALIAS.lastIndex = 0
  const fingerprints = [...text.matchAll(MARKER)].flatMap((m) => (m[1] === undefined ? [] : [m[1]]))
  const labels = [...text.matchAll(ALIAS)].flatMap((m) => (m[1] === undefined ? [] : [m[1]]))
  return { fingerprints, labels }
}

/**
 * `text` with every marker this can resolve replaced by the real value. A
 * marker `lookup` cannot answer is left standing, so a missing secret fails
 * loudly at the command rather than silently as an empty string.
 */
export function rehydrate(text: string, lookup: (id: string) => string | undefined): { text: string; used: string[] } {
  const used: string[] = []
  const swap = (id: string, whole: string): string => {
    const v = lookup(id)
    if (v === undefined) return whole
    used.push(id)
    return v
  }
  MARKER.lastIndex = 0
  ALIAS.lastIndex = 0
  const out = text
    .replace(MARKER, (whole, fp: string) => swap(fp, whole))
    .replace(ALIAS, (whole, label: string) => swap(normalizeLabel(label), whole))
  return { text: out, used }
}

/** The same over a tool call's arguments, which are plain JSON data. */
export function rehydrateValue(value: unknown, lookup: (id: string) => string | undefined): { value: unknown; used: string[] } {
  const used: string[] = []
  const walk = (v: unknown, d: number): unknown => {
    if (d > 24) return v
    if (typeof v === 'string') {
      const r = rehydrate(v, lookup)
      used.push(...r.used)
      return r.text
    }
    if (Array.isArray(v)) return v.map((x) => walk(x, d + 1))
    if (v !== null && typeof v === 'object') {
      const out: Record<string, unknown> = {}
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) out[k] = walk(x, d + 1)
      return out
    }
    return v
  }
  return { value: walk(value, 0), used }
}

// --- the Keychain ----------------------------------------------------------

/**
 * Writes the value under this fingerprint, replacing any item already there.
 * The value goes in on stdin (`-w` with no argument reads it, twice), so it is
 * never an argument of a process anyone can list.
 */
/**
 * The value as hexadecimal UTF-8, which is what `-X` takes.
 *
 * `encodeURIComponent` rather than `TextEncoder`: a hooks module has no Node
 * and no DOM, and this is core ECMAScript.
 */
function toHex(value: string): string {
  const encoded = encodeURIComponent(value)
  let out = ''
  for (let i = 0; i < encoded.length; i += 1) {
    if (encoded[i] === '%') {
      out += encoded.slice(i + 1, i + 3).toLowerCase()
      i += 2
    } else {
      out += (encoded.charCodeAt(i) & 0xff).toString(16).padStart(2, '0')
    }
  }
  return out
}

/** A double-quoted `security -i` argument, stripped of what its parser would eat. */
function quoted(s: string): string {
  return `"${s.replace(/[^\x20-\x7e]/g, ' ').replace(/["\\]/g, '')}"`
}

/**
 * Writes the value to the login Keychain without it touching argv or a prompt.
 *
 * `add-generic-password -w` with no value does NOT read standard input: it
 * calls readpassphrase, which opens the CONTROLLING TERMINAL. A hooks module's
 * child inherits the interactive session's terminal, so the prompt went there,
 * the piped value was never read, and the call was killed at its timeout --
 * silently, because a killed call rejects rather than returning a code. Piping
 * the value works only where there is no terminal at all, which is why a
 * headless probe passed and every real session hung.
 *
 * `-i` takes the command itself on standard input, so nothing reaches the
 * process table, and `-X` takes the value as hexadecimal, which the parser's
 * whitespace splitting cannot damage.
 */
export async function keychainSave(
  run: Run,
  fingerprint: string,
  label: string,
  rule: string,
  value: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const hex = toHex(value)
  const command = [
    'add-generic-password',
    '-U',
    '-a', fingerprint,
    '-s', SERVICE,
    '-l', quoted(`credential-guard: ${label}`),
    '-D', quoted('credential-guard secret'),
    '-j', quoted(`${rule}; saved by the credential-guard Claude Code plugin`),
    '-X', hex,
  ].join(' ')

  const r = await run(['security', '-i'], { stdin: `${command}\n`, timeoutMs: 30_000 })
  if (r.exitCode === 0) return { ok: true }
  // `security -i` echoes the command it refused, so the error is scrubbed of
  // the value before it can be logged.
  const error = (r.stderr || r.stdout).trim().split(hex).join('[value]')
  return { ok: false, error }
}

/** The value under this fingerprint, or undefined when the Keychain has none. */
export async function keychainRead(run: Run, fingerprint: string): Promise<string | undefined> {
  const r = await run(['security', 'find-generic-password', '-a', fingerprint, '-s', SERVICE, '-w'], {
    timeoutMs: 30_000,
  })
  if (r.exitCode !== 0) return undefined
  const v = r.stdout.replace(/\n$/, '')
  return v.length === 0 ? undefined : v
}

/** Removes the item. Used when the person asks to forget one. */
export async function keychainDelete(run: Run, fingerprint: string): Promise<boolean> {
  const r = await run(['security', 'delete-generic-password', '-a', fingerprint, '-s', SERVICE], {
    timeoutMs: 30_000,
  })
  return r.exitCode === 0
}

/** The context block that tells the model which secrets it may reference. */
export function indexBlock(index: VaultIndex): string | undefined {
  const rows = Object.entries(index)
  if (rows.length === 0) return undefined
  const lines = rows
    .sort((a, b) => a[1].label.localeCompare(b[1].label))
    .map(([, v]) => `- [secret:${v.label}] — ${v.rule}, saved ${new Date(v.savedAt).toISOString().slice(0, 10)}`)
  return [
    'The credential-guard plugin holds these secrets outside this conversation.',
    'Their values are not in this transcript and will not be shown to you.',
    '',
    ...lines,
    '',
    'Write a placeholder exactly as listed inside a tool call and the plugin',
    'substitutes the real value at execution time. Do not ask for the value',
    'and do not try to reconstruct it; use the placeholder.',
  ].join('\n')
}
