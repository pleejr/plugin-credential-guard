/**
 * credential-guard: keeps high-entropy values out of the session transcript while
 * keeping them usable inside it.
 *
 * The cycle, once round:
 *   1. a tool's output (or a prompt, or a delivery) carries a secret
 *   2. the transcript gets `[redacted <rule> #<fingerprint>]`; the model never
 *      reads the value, and neither does the session log
 *   3. the value goes to the session vault, and the person is offered the
 *      macOS Keychain for it
 *   4. the model writes the placeholder back into a tool call, and the plugin
 *      substitutes the real value on the way down, so the command works
 *   5. a saved secret is listed to the model next session as `[secret:NAME]`,
 *      so step 4 works in every session after this one
 *
 * Failure mode is OPEN: a hook that throws or overruns its 10 s budget is
 * skipped and the content passes unredacted. Each `.catch` says so on screen.
 */
import type { EngineInterface, Register } from 'claude-code'
import { describe, redactText, redactValue, type Finding, type NearMiss, type ScanOptions } from './scan.ts'
import {
  calibrate,
  emptyLedger,
  LEDGER_KEY,
  parseLedger,
  prune,
  record,
  type Ledger,
} from './ledger.ts'
import {
  INDEX_KEY,
  indexBlock,
  keychainRead,
  keychainSave,
  normalizeLabel,
  referencesIn,
  rehydrateValue,
  suggestLabel,
  type Run,
  type VaultIndex,
} from './vault.ts'
import { parseTrust } from './trust.ts'

type ResultAction = 'redact' | 'off'
type InputAction = 'warn' | 'deny' | 'off'
type PromptAction = 'redact' | 'block' | 'off'
type KeychainMode = 'ask' | 'auto' | 'off'

/** Tools whose arguments leave this machine. A placeholder is not expanded for
 *  one of these unless `rehydrateEgress` says so. */
const EGRESS = /^(?:mcp__|WebFetch$|WebSearch$)/

const num = (v: unknown, fallback: number): number =>
  typeof v === 'number' && Number.isFinite(v) ? v : fallback

const bool = (v: unknown, fallback: boolean): boolean => (typeof v === 'boolean' ? v : fallback)

const pick = <T extends string>(v: unknown, allowed: readonly T[], fallback: T): T =>
  typeof v === 'string' && (allowed as readonly string[]).includes(v) ? (v as T) : fallback

const fingerprints = (v: unknown): string[] =>
  typeof v === 'string' ? v.split(/[\s,]+/).filter((x) => x.length > 0) : []

// --- module state ----------------------------------------------------------
// The module is loaded once per session, so its scope is the session's scope.

/** fingerprint -> value, for this session only. Never written to disk. */
const vault = new Map<string, string>()
/**
 * Fingerprints the detector must not flag: the `allow` option, plus whatever a
 * trusted corpus vouches for. One Set, held here rather than rebuilt, so the
 * trust list can be merged into it after `scanOpts` is already in use.
 */
const allowSet = new Set<string>()
/** Where a corpus that has passed its own sensitivity gate is recorded. */
let trustFile = ''
let trustLoaded = false
/** What the Keychain holds, as `$.store` records it. Values are not here. */
let index: VaultIndex | null = null
/** Caught this session and not yet put to the person. */
const pending = new Map<string, { rule: string; value: string }>()
const offered = new Set<string>()
let askingOff = false
let draining = false
let count = 0

/** What the detector saw and let past, as shape only. Loaded once per session. */
let ledger: Ledger | null = null
let ledgerDirty = false
let ledgerOn = true
let ledgerMaxRows = 5000

let scanOpts: Partial<ScanOptions> = {}
let onToolResult: ResultAction = 'redact'
let onToolInput: InputAction = 'warn'
let onPrompt: PromptAction = 'redact'
let keychain: KeychainMode = 'ask'
let rehydrateOn = true
let rehydrateEgress = false

/** `$.process.run`, as the vault module takes it. */
const runner = ($: EngineInterface): Run => (argv, init) => $.process.run(argv, init)

/**
 * Merges a trusted corpus's fingerprints into the allow set, once per session.
 *
 * The file is read rather than the corpus scanned: walking a 2300-file vault
 * inside a hook's 10 s budget is not a thing to do on every session start, and
 * the generator (`bin/trust-vault.ts`) already refused everything a shape-only
 * rule did not find. It fails QUIET and EMPTY -- a missing or malformed trust
 * list trusts nothing, which is the direction a suppression list must fail in.
 */
async function loadTrust($: EngineInterface): Promise<void> {
  if (trustLoaded || trustFile === '') return
  trustLoaded = true
  const home = $.env.get('HOME') ?? ''
  const path = trustFile.startsWith('~/') && home !== '' ? home + trustFile.slice(1) : trustFile
  try {
    if (!(await $.fs.exists(path))) {
      $.ui.log(`credential-guard: no trust list at ${path} -- trusting nothing`, { to: 'debug' })
      return
    }
    const parsed = parseTrust(JSON.parse(await $.fs.read(path)))
    if (parsed.error !== undefined) {
      $.ui.log(`credential-guard: the trust list at ${path} is unusable (${parsed.error}) -- trusting nothing`)
      return
    }
    for (const fp of parsed.fingerprints) allowSet.add(fp)
    $.ui.log(
      `credential-guard: trusting ${parsed.fingerprints.size} fingerprint(s) vouched for on ${parsed.generatedAt}` +
        `${parsed.refused > 0 ? `, ${parsed.refused} refused at generation` : ''}`,
      { to: 'debug' },
    )
  } catch (e) {
    $.ui.log(`credential-guard: could not read the trust list at ${path} (${String(e)}) -- trusting nothing`)
  }
}

async function loadIndex($: EngineInterface): Promise<VaultIndex> {
  if (index !== null) return index
  const raw = await $.store.get(INDEX_KEY)
  index = raw !== null && typeof raw === 'object' ? (raw as VaultIndex) : {}
  return index
}

async function loadLedger($: EngineInterface): Promise<Ledger> {
  if (ledger !== null) return ledger
  ledger = parseLedger(await $.store.get(LEDGER_KEY))
  return ledger
}

/** Writes the ledger back, pruned. Called on a timer and at session end. */
async function flushLedger($: EngineInterface): Promise<void> {
  if (!ledgerDirty || ledger === null) return
  ledgerDirty = false
  const dropped = prune(ledger, ledgerMaxRows)
  if (dropped > 0) $.ui.log(`credential-guard: pruned ${dropped} ledger row(s) to stay under ${ledgerMaxRows}`, { to: 'debug' })
  await $.store.set(LEDGER_KEY, ledger)
}

/** Folds this dispatch's near misses into the ledger. Shape only, never a value. */
async function noteNear($: EngineInterface, near: readonly NearMiss[], tool: string): Promise<void> {
  if (!ledgerOn || near.length === 0) return
  const l = await loadLedger($)
  record(l, near, tool, Date.now())
  ledgerDirty = true
}

async function save($: EngineInterface, fp: string, label: string, rule: string, value: string): Promise<boolean> {
  const r = await keychainSave(runner($), fp, label, rule, value)
  if (!r.ok) {
    $.ui.log(`credential-guard: the Keychain refused #${fp} — ${r.error}`)
    return false
  }
  const idx = await loadIndex($)
  idx[fp] = { label, rule, savedAt: Date.now() }
  await $.store.set(INDEX_KEY, idx)
  $.ui.log(`credential-guard: saved #${fp} to your login Keychain as [secret:${label}]`)
  return true
}

/** Puts each caught secret to the person, one at a time, outside the dispatch. */
async function drain($: EngineInterface): Promise<void> {
  if (draining) return
  draining = true
  try {
    while (pending.size > 0 && !askingOff) {
      const entry = [...pending.entries()][0]
      if (entry === undefined) break
      const [fp, item] = entry
      pending.delete(fp)
      offered.add(fp)
      const suggested = suggestLabel(item.rule, fp)

      if (keychain === 'auto') {
        await save($, fp, suggested, item.rule, item.value)
        continue
      }

      let answer: string
      try {
        answer = await $.ui.ask(
          `credential-guard caught a ${item.rule} (#${fp}) and kept it out of the transcript. ` +
            `Save it to your macOS login Keychain so later sessions can use it?`,
          { header: 'Secret', options: ['Save to Keychain', 'Not this one', 'Stop asking this session'] },
        )
      } catch {
        // No one to ask (a -p run), or the dialog was dismissed.
        askingOff = true
        return
      }
      if (answer === 'Stop asking this session') {
        askingOff = true
        return
      }
      if (answer !== 'Save to Keychain') continue

      let name = suggested
      try {
        name = normalizeLabel(
          await $.ui.ask(`Name it. Later sessions will reference it as [secret:NAME].`, {
            header: 'Name',
            options: [suggested, `${suggested}_${fp}`],
          }),
        )
      } catch {
        // Dismissed at the naming step: keep the suggestion.
      }
      await save($, fp, name, item.rule, item.value)
    }
  } finally {
    draining = false
  }
}

/** Remembers caught values and, unless told not to, queues the offer. */
async function capture($: EngineInterface, findings: readonly Finding[]): Promise<void> {
  const idx = await loadIndex($)
  for (const f of findings) {
    vault.set(f.fingerprint, f.value)
    if (askingOff || offered.has(f.fingerprint) || idx[f.fingerprint] !== undefined) continue
    pending.set(f.fingerprint, { rule: f.rule, value: f.value })
  }
  if (pending.size > 0) $.clock.after(50, () => void drain($))
}

/** Every placeholder in `text`, resolved to a value where one is held. */
async function resolveRefs($: EngineInterface, text: string): Promise<Map<string, string>> {
  const refs = referencesIn(text)
  const out = new Map<string, string>()
  if (refs.fingerprints.length === 0 && refs.labels.length === 0) return out
  const idx = await loadIndex($)
  const byLabel = new Map(Object.entries(idx).map(([fp, v]) => [v.label, fp]))

  for (const fp of new Set(refs.fingerprints)) {
    const v = vault.get(fp) ?? (await keychainRead(runner($), fp))
    if (v === undefined) continue
    vault.set(fp, v)
    out.set(fp, v)
  }
  for (const label of new Set(refs.labels.map(normalizeLabel))) {
    const fp = byLabel.get(label)
    if (fp === undefined) continue
    const v = vault.get(fp) ?? (await keychainRead(runner($), fp))
    if (v === undefined) continue
    vault.set(fp, v)
    out.set(label, v)
  }
  return out
}

function redactAll(list: readonly string[] | undefined): { list: string[] | undefined; findings: Finding[] } {
  if (list === undefined) return { list: undefined, findings: [] }
  const findings: Finding[] = []
  const out = list.map((s) => {
    const r = redactText(s, scanOpts)
    findings.push(...r.findings)
    return r.text
  })
  return { list: out, findings }
}

export const register: Register = (on, options) => {
  scanOpts = {
    minLength: num(options.minLength, 24),
    entropyRatio: num(options.entropyRatio, 0.85),
    hexMinLength: num(options.hexMinLength, 32),
    strictHex: bool(options.strictHex, false),
    proximityWindow: num(options.proximityWindow, 60),
    proximityRatio: num(options.proximityRatio, 0.7),
    exemptRatio: num(options.exemptRatio, 0.85),
    announcedMinLength: num(options.announcedMinLength, 16),
    flagAwsKeyIds: bool(options.flagAwsKeyIds, false),
    pairWindow: num(options.pairWindow, 240),
    ledgerMinRatio: num(options.ledgerMinRatio, 0.6),
    maxScanChars: num(options.maxScanChars, 2_000_000),
    allow: allowSet,
  }
  allowSet.clear()
  for (const fp of fingerprints(options.allow)) allowSet.add(fp)
  trustFile = typeof options.trustFile === 'string' ? options.trustFile : ''
  trustLoaded = false
  onToolResult = pick<ResultAction>(options.onToolResult, ['redact', 'off'], 'redact')
  onToolInput = pick<InputAction>(options.onToolInput, ['warn', 'deny', 'off'], 'warn')
  onPrompt = pick<PromptAction>(options.onPrompt, ['redact', 'block', 'off'], 'redact')
  keychain = pick<KeychainMode>(options.keychain, ['ask', 'auto', 'off'], 'ask')
  rehydrateOn = bool(options.rehydrate, true)
  rehydrateEgress = bool(options.rehydrateEgress, false)
  ledgerOn = bool(options.ledger, true)
  ledgerMaxRows = num(options.ledgerMaxRows, 5000)
  askingOff = keychain === 'off'

  on('session.start', async ($, e, next) => {
    const r = await next(e)
    await loadTrust($)
    const idx = await loadIndex($)
    const held = Object.keys(idx).length
    if (ledgerOn) {
      await loadLedger($)
      await $.command.register({
        name: 'credential-guard',
        description: 'Calibration report: what the detector saw and let past.',
      })
      $.clock.every(30_000, () => void flushLedger($))
    }
    $.ui.log(
      `credential-guard: output ${onToolResult}, arguments ${onToolInput}, prompts ${onPrompt}, ` +
        `keychain ${keychain}, rehydrate ${rehydrateOn}; ${held} secret(s) held.`,
      { to: 'debug' },
    )
    return r
  })

  // --- tell the model which secrets it may reference ------------------------
  on('prompt.context', async ($, e, next) => {
    const r = await next(e)
    const text = indexBlock(await loadIndex($))
    if (text === undefined) return r
    return { ...r, blocks: [...r.blocks, { name: 'credentialGuardSecrets', text }] }
  })

  on('command.run', { command: 'credential-guard' }, async ($, e, next) => {
    if (!ledgerOn) return { text: 'credential-guard: the ledger is off (`ledger` option).' }
    return { text: calibrate(await loadLedger($), num(options.entropyRatio, 0.85)) }
  })

  on('session.end', async ($, e, next) => {
    await flushLedger($)
    return next(e)
  })

  // --- tool calls: placeholders down, secrets back --------------------------
  on('tool.call', async ($, e, next) => {
    const raw = JSON.stringify(e)

    if (onToolInput !== 'off') {
      const findings = redactText(raw, scanOpts).findings
      if (findings.length > 0) {
        if (onToolInput === 'deny') {
          count += findings.length
          $.ui.status(`credential-guard: ${count} caught`)
          $.ui.log(`credential-guard: refused ${e.tool} — its arguments carry ${describe(findings)}`)
          await capture($, findings)
          return {
            deny:
              `credential-guard refused this call: its arguments carry ${findings.length} high-entropy ` +
              `value(s) (${describe(findings)}). Reference the secret by its placeholder, or read it ` +
              `from the environment inside the command, instead of writing it into the call.`,
          }
        }
        $.ui.log(`credential-guard: ${e.tool} arguments carry ${describe(findings)} (recorded, not blocked)`)
        await capture($, findings)
      }
    }

    let down = e
    if (rehydrateOn && (rehydrateEgress || !EGRESS.test(e.tool))) {
      const values = await resolveRefs($, raw)
      if (values.size > 0) {
        const swapped = rehydrateValue(e, (id) => values.get(id))
        if (swapped.used.length > 0) {
          down = swapped.value as typeof e
          $.ui.log(`credential-guard: substituted ${swapped.used.length} held secret(s) into ${e.tool}`)
        }
      }
    } else if (rehydrateOn && EGRESS.test(e.tool) && referencesIn(raw).fingerprints.length + referencesIn(raw).labels.length > 0) {
      $.ui.log(`credential-guard: left placeholders alone in ${e.tool} — it sends arguments off this machine`)
    }

    const r = await next(down)
    if (onToolResult === 'off') return r
    if (r.deny !== undefined) return r

    const body = redactValue(r.result, scanOpts)
    const ctx = redactAll(r.context)
    const text = typeof r.text === 'string' ? redactText(r.text, scanOpts) : undefined
    const findings = [...body.findings, ...ctx.findings]
    await noteNear($, body.near, e.tool)
    if (findings.length === 0) return r

    count += findings.length
    $.ui.status(`credential-guard: ${count} caught`)
    $.ui.log(`credential-guard: redacted ${findings.length} value(s) from ${e.tool} — ${describe(findings)}`)
    await capture($, findings)

    // `ref` is dropped on purpose: keeping it makes core record its own
    // messages verbatim, which is exactly the unredacted text.
    if (r.isError === true) {
      return { isError: true, result: body.value, text: text?.text, context: ctx.list }
    }
    return { result: body.value as typeof r.result, context: ctx.list }
  }).catch(($, e, next) => {
    $.ui.log(
      `credential-guard: the guard failed on ${e.tool} (${next.error.kind}: ${next.error.message ?? 'no message'}) — ` +
        `this call's output was NOT scanned`,
    )
    return undefined
  })

  // --- what the person typed or pasted --------------------------------------
  on('prompt.submit', async ($, e, next) => {
    if (onPrompt === 'off') return next(e)
    const prompt = redactText(e.text, scanOpts)
    const ctx = redactAll(e.context)
    const findings = [...prompt.findings, ...ctx.findings]
    await noteNear($, prompt.near, 'prompt')
    if (findings.length === 0) return next(e)

    count += findings.length
    $.ui.status(`credential-guard: ${count} caught`)
    await capture($, findings)
    if (onPrompt === 'block') {
      $.ui.log(`credential-guard: held back your prompt — it carries ${describe(findings)}`)
      return {
        drop: `credential-guard: the prompt carries ${findings.length} high-entropy value(s) (${describe(findings)}) and was not sent.`,
      }
    }
    $.ui.log(`credential-guard: redacted ${findings.length} value(s) from your prompt — ${describe(findings)}`)
    return next({ ...e, text: prompt.text, context: ctx.list })
  }).catch(($, e, next) => {
    $.ui.log(`credential-guard: the guard failed on your prompt (${next.error.kind}) — it was NOT scanned`)
    return undefined
  })

  // --- what a peer session, relay or webhook delivered ----------------------
  on('session.receive', async ($, e, next) => {
    if (onPrompt === 'off') return next(e)
    const body = redactText(e.text, scanOpts)
    await noteNear($, body.near, `delivery:${e.origin.kind}`)
    if (body.findings.length === 0) return next(e)

    count += body.findings.length
    $.ui.status(`credential-guard: ${count} caught`)
    await capture($, body.findings)
    $.ui.log(
      `credential-guard: redacted ${body.findings.length} value(s) from a ${e.origin.kind} delivery — ${describe(body.findings)}`,
    )
    if (onPrompt === 'block') {
      return { consumed: `credential-guard: the delivery carried ${body.findings.length} high-entropy value(s) and was not queued.` }
    }
    return next({ ...e, text: body.text })
  }).catch(($, e, next) => {
    $.ui.log(`credential-guard: the guard failed on a ${e.origin.kind} delivery (${next.error.kind}) — it was NOT scanned`)
    return undefined
  })
}
