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
 * `promptOnly` collapses the watching to one door -- only what the person typed
 * and submitted is scanned -- and leaves the rest of the cycle alone. See
 * resolveDoors.
 *
 * Failure mode is OPEN: a hook that throws or overruns its 10 s budget is
 * skipped and the content passes unredacted. Each `.catch` says so on screen.
 */
import type { EngineInterface, PluginOptions, Register } from 'claude-code'
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
  pruneOrphans,
  keychainSave,
  normalizeLabel,
  referencesIn,
  rehydrateValue,
  suggestLabel,
  type Run,
  type VaultIndex,
} from './vault.ts'

type ResultAction = 'redact' | 'off'
type InputAction = 'warn' | 'deny' | 'off'
type PromptAction = 'redact' | 'block' | 'off'
type KeychainMode = 'ask' | 'auto' | 'off'
/** Which surfaces the shape-only rules (`entropy`, `hex`, `-cue`) run on. */
type ShapeScope = 'prompt' | 'prompt+result' | 'all' | 'off'

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

/**
 * Which doors this activation watches, after `promptOnly` has had its say.
 * Kept as one pure function so the mode can be tested without the engine:
 * the option is not mockable in a test, the resolution is.
 */
export type Doors = {
  result: ResultAction
  input: InputAction
  prompt: PromptAction
  /** Whether a peer session, relay or webhook delivery is scanned. */
  delivery: boolean
  keychain: KeychainMode
}

/**
 * `promptOnly` narrows WHERE the detector looks, and nothing else: scan what
 * the person typed and submitted, and judge no other surface. It closes the
 * tool doors and the delivery door rather than lowering a threshold, so under
 * it a value the person did not type cannot become a finding, and cannot
 * become a warning -- no tool output, no tool argument, no peer delivery.
 *
 * It overrides `onToolResult` and `onToolInput` outright, because a mode whose
 * promise is "nothing but my prompts" cannot be half-held by an option set
 * earlier. What happens to a finding is untouched: `onPrompt` still chooses
 * redact or block, and `keychain` still decides whether a caught secret is
 * offered to the Keychain -- a prompt finding is exactly the one worth saving.
 *
 * It is not the default. It gives up every catch that happens in a tool's
 * output, which is where a `cat .env` or an `aws sts` leak comes from.
 */
export function resolveDoors(options: PluginOptions): Doors {
  const prompt = pick<PromptAction>(options.onPrompt, ['redact', 'block', 'off'], 'redact')
  const keychain = pick<KeychainMode>(options.keychain, ['ask', 'auto', 'off'], 'ask')
  if (bool(options.promptOnly, false)) {
    return { result: 'off', input: 'off', prompt, delivery: false, keychain }
  }
  return {
    result: pick<ResultAction>(options.onToolResult, ['redact', 'off'], 'redact'),
    input: pick<InputAction>(options.onToolInput, ['warn', 'deny', 'off'], 'warn'),
    prompt,
    delivery: true,
    keychain,
  }
}

/**
 * The `prompt.submit` origins a person typed: Enter at the terminal, the
 * Remote Control bridge, an SDK host's turn, the owner's Slack ping. Everything
 * else reaching `prompt.submit` -- a task notification, a schedule, a peer, a
 * plugin -- was written by the harness or by another session. An origin this
 * build does not name is not presumed typed.
 */
const TYPED = new Set(['composer', 'bridge', 'sdk', 'slack-ping'])

export function typedByPerson(kind: string): boolean {
  return TYPED.has(kind)
}

/**
 * How a `prompt.submit` text is judged. A task notification carries a
 * `<tool-use-id>` the shape rules read as a key, so machine-written text never
 * gets the prompt's shape rules: under `promptOnly` it is not scanned at all,
 * and ordinarily it is scanned as a tool's output is.
 */
export function promptSurface(kind: string, promptOnly: boolean): 'prompt' | 'machine' | 'skip' {
  if (typedByPerson(kind)) return 'prompt'
  return promptOnly ? 'skip' : 'machine'
}

// --- module state ----------------------------------------------------------
// The module is loaded once per session, so its scope is the session's scope.

/** fingerprint -> value, for this session only. Never written to disk. */
const vault = new Map<string, string>()
/**
 * Fingerprints the detector must not flag, from the `allow` option. One Set,
 * held here rather than rebuilt, so it stays the same object `scanOpts` took.
 */
const allowSet = new Set<string>()
/** What the Keychain holds, as `$.store` records it. Values are not here. */
let index: VaultIndex | null = null
/** Caught this session and not yet put to the person. */
const pending = new Map<string, { rule: string; value: string }>()
const offered = new Set<string>()
/**
 * Accepted for the Keychain but refused by it, held to try again. A session
 * outside the login window's security session -- over SSH, under a detached
 * multiplexer -- cannot unlock the login Keychain, and `security` answers
 * -25308 until someone does. The value stays in memory only: there is nowhere
 * safer to put it while the Keychain is shut.
 */
const deferred = new Map<string, { label: string; rule: string; value: string }>()
let retrying = false
let askingOff = false
let draining = false
let count = 0

/** What the detector saw and let past, as shape only. Loaded once per session. */
let ledger: Ledger | null = null
let ledgerDirty = false
let ledgerOn = true
let ledgerMaxRows = 5000

let scanOpts: Partial<ScanOptions> = {}
/**
 * `scanOpts` with the shape-only rules turned on or off for each surface. A
 * person types a secret into a PROMPT; a tool's arguments and its output are
 * mostly machine text, where a random-looking run is far likelier to be an
 * identifier than a key -- so shape is scoped, and the rules that read what the
 * text calls a value keep running everywhere.
 */
let promptOpts: Partial<ScanOptions> = {}
let resultOpts: Partial<ScanOptions> = {}
let inputOpts: Partial<ScanOptions> = {}
let shapeScope: ShapeScope = 'prompt'
let onToolResult: ResultAction = 'redact'
let onToolInput: InputAction = 'warn'
let onPrompt: PromptAction = 'redact'
/** Whether a peer delivery is scanned at all. `promptOnly` closes this door. */
let onDelivery = true
/** Watch nothing but the person's own prompts, and never offer the Keychain. */
let promptOnly = false
let keychain: KeychainMode = 'ask'
let rehydrateOn = true
let rehydrateEgress = false

/** `$.process.run`, as the vault module takes it. */
const runner = ($: EngineInterface): Run => (argv, init) => $.process.run(argv, init)

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
  if (dropped > 0) $.ui.log(`pruned ${dropped} ledger row(s) to stay under ${ledgerMaxRows}`, { to: 'debug' })
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
  // `$.process.run` REJECTS where `security` merely fails: a timeout, a refused
  // call, a noun this build does not hand a hooks module. keychainSave reports
  // only the non-zero exit, so without this catch the rejection travelled up
  // into `void drain($)` and died there -- no item, no line, nothing to read.
  let r: { ok: true } | { ok: false; error: string }
  try {
    r = await keychainSave(runner($), fp, label, rule, value)
  } catch (e) {
    $.ui.log(`the Keychain write for #${fp} threw — ${String(e)}`)
    return false
  }
  if (!r.ok) {
    $.ui.log(`the Keychain refused #${fp} — ${r.error}`)
    const wasHeld = deferred.has(fp)
    deferred.set(fp, { label, rule, value })
    // A log line is dim and scrolls away; a refusal is the one outcome the
    // person needs to know about, so it is said once, in words, as a toast.
    if (!wasHeld) {
      $.ui.toast(
        isKeychainLocked(r.error)
          ? `credential-guard: your login Keychain is locked in this session (it can't ask for your password here, e.g. over SSH). ` +
              `[secret:${label}] works for now and is saved as soon as the Keychain unlocks.`
          : `credential-guard: the Keychain didn't save [secret:${label}] (${plainReason(r.error)}). It works for now; I'll try again on your next prompt.`,
        { timeoutMs: 15_000 },
      )
    }
    return false
  }
  const wasHeld = deferred.delete(fp)
  const idx = await loadIndex($)
  idx[fp] = { label, rule, savedAt: Date.now() }
  await $.store.set(INDEX_KEY, idx)
  $.ui.log(`saved #${fp} to your login Keychain as [secret:${label}]`)
  if (wasHeld) $.ui.toast(`credential-guard: saved [secret:${label}] to your login Keychain.`, { timeoutMs: 8_000 })
  return true
}

/** errSecInteractionNotAllowed: no one can be asked to unlock the Keychain here. */
function isKeychainLocked(error: string): boolean {
  return /User interaction is not allowed|-25308|errSecInteractionNotAllowed/i.test(error)
}

/** The refusal without `security`'s API name and status code. */
function plainReason(error: string): string {
  const line = error.split('\n')[0] ?? error
  return line.replace(/^security:\s*/, '').replace(/^[A-Za-z]+\s*\([^)]*\):\s*/, '').replace(/\s*\(?-?\d{4,}\)?\.?$/, '').trim() || 'no reason given'
}

/** Tries each held secret again, outside the dispatch that noticed. */
async function retryDeferred($: EngineInterface): Promise<void> {
  if (retrying || deferred.size === 0) return
  retrying = true
  try {
    for (const [fp, item] of [...deferred.entries()]) {
      const saved = await save($, fp, item.label, item.rule, item.value)
      // Still shut: the rest will be refused for the same reason.
      if (!saved) break
    }
  } finally {
    retrying = false
  }
}

/** Queues a retry of held secrets, if any, for just after this dispatch. */
function scheduleRetry($: EngineInterface): void {
  if (deferred.size === 0) return
  $.clock.after(50, () => {
    retryDeferred($).catch((e: unknown) => $.ui.log(`the Keychain retry failed — ${String(e)}`))
  })
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
  // A timer callback discards what it returns, so drain's own failure needs a
  // handler here or it is an unhandled rejection the person never sees.
  if (pending.size > 0) {
    $.clock.after(50, () => {
      drain($).catch((e: unknown) => $.ui.log(`the Keychain offer failed — ${String(e)}`))
    })
  }
}

/** Every placeholder in `text`, resolved to a value where one is held. */
async function resolveRefs($: EngineInterface, text: string): Promise<Map<string, string>> {
  const refs = referencesIn(text)
  const out = new Map<string, string>()
  if (refs.fingerprints.length === 0 && refs.labels.length === 0) return out
  const idx = await loadIndex($)
  const byLabel = new Map(Object.entries(idx).map(([fp, v]) => [v.label, fp]))

  // A fingerprint the index names but the Keychain cannot return is an orphan:
  // the value was deleted and the row outlived it. Collected here and pruned
  // below, so the next session does not offer a secret it cannot resolve.
  const unresolved: string[] = []

  for (const fp of new Set(refs.fingerprints)) {
    const v = vault.get(fp) ?? (await keychainRead(runner($), fp))
    if (v === undefined) {
      unresolved.push(fp)
      continue
    }
    vault.set(fp, v)
    out.set(fp, v)
  }
  for (const label of new Set(refs.labels.map(normalizeLabel))) {
    const fp = byLabel.get(label)
    if (fp === undefined) continue
    const v = vault.get(fp) ?? (await keychainRead(runner($), fp))
    if (v === undefined) {
      unresolved.push(fp)
      continue
    }
    vault.set(fp, v)
    out.set(label, v)
  }

  const pruned = pruneOrphans(idx, unresolved)
  if (pruned.dropped.length > 0) {
    index = pruned.index
    await $.store.set(INDEX_KEY, pruned.index)
    for (const fp of pruned.dropped) {
      $.ui.log(`#${fp} is no longer in your Keychain — dropped it from the index`)
    }
  }
  return out
}

function redactAll(
  list: readonly string[] | undefined,
  opts: Partial<ScanOptions>,
): { list: string[] | undefined; findings: Finding[] } {
  if (list === undefined) return { list: undefined, findings: [] }
  const findings: Finding[] = []
  const out = list.map((s) => {
    const r = redactText(s, opts)
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
  shapeScope = pick<ShapeScope>(options.shapeRules, ['prompt', 'prompt+result', 'all', 'off'], 'prompt')
  promptOpts = { ...scanOpts, shapeRules: shapeScope !== 'off' }
  resultOpts = { ...scanOpts, shapeRules: shapeScope === 'prompt+result' || shapeScope === 'all' }
  inputOpts = { ...scanOpts, shapeRules: shapeScope === 'all' }
  promptOnly = bool(options.promptOnly, false)
  const doors = resolveDoors(options)
  onToolResult = doors.result
  onToolInput = doors.input
  onPrompt = doors.prompt
  onDelivery = doors.delivery
  keychain = doors.keychain
  rehydrateOn = bool(options.rehydrate, true)
  rehydrateEgress = bool(options.rehydrateEgress, false)
  ledgerOn = bool(options.ledger, true)
  ledgerMaxRows = num(options.ledgerMaxRows, 5000)
  askingOff = keychain === 'off'

  on('session.start', async ($, e, next) => {
    const r = await next(e)
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
      `${promptOnly ? 'prompt-only: your prompts alone are scanned; ' : ''}` +
        `output ${onToolResult}, arguments ${onToolInput}, prompts ${onPrompt}, deliveries ` +
        `${onDelivery ? 'scanned' : 'off'}, shape rules on ${shapeScope}, keychain ${keychain}, ` +
        `rehydrate ${rehydrateOn}; ${held} secret(s) held.`,
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
    const report = calibrate(await loadLedger($), num(options.entropyRatio, 0.85))
    // A report is only as good as the population behind it: under promptOnly
    // nothing but prompts is ever scanned, so nothing but prompts is counted.
    return { text: promptOnly ? `${report}\n\nPopulation: prompts only (promptOnly is on).` : report }
  })

  on('session.end', async ($, e, next) => {
    await flushLedger($)
    return next(e)
  })

  // --- tool calls: placeholders down, secrets back --------------------------
  on('tool.call', async ($, e, next) => {
    const raw = JSON.stringify(e)

    if (onToolInput !== 'off') {
      const findings = redactText(raw, inputOpts).findings
      if (findings.length > 0) {
        if (onToolInput === 'deny') {
          count += findings.length
          $.ui.status(`credential-guard: ${count} caught`)
          $.ui.log(`refused ${e.tool} — its arguments carry ${describe(findings)}`)
          await capture($, findings)
          return {
            deny:
              `credential-guard refused this call: its arguments carry ${findings.length} high-entropy ` +
              `value(s) (${describe(findings)}). Reference the secret by its placeholder, or read it ` +
              `from the environment inside the command, instead of writing it into the call.`,
          }
        }
        $.ui.log(`${e.tool} arguments carry ${describe(findings)} (recorded, not blocked)`)
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
          $.ui.log(`substituted ${swapped.used.length} held secret(s) into ${e.tool}`)
        }
      }
    } else if (rehydrateOn && EGRESS.test(e.tool) && referencesIn(raw).fingerprints.length + referencesIn(raw).labels.length > 0) {
      $.ui.log(`left placeholders alone in ${e.tool} — it sends arguments off this machine`)
    }

    const r = await next(down)
    if (onToolResult === 'off') return r
    if (r.deny !== undefined) return r

    const body = redactValue(r.result, resultOpts)
    const ctx = redactAll(r.context, resultOpts)
    const text = typeof r.text === 'string' ? redactText(r.text, resultOpts) : undefined
    const findings = [...body.findings, ...ctx.findings]
    await noteNear($, body.near, e.tool)
    if (findings.length === 0) return r

    count += findings.length
    $.ui.status(`credential-guard: ${count} caught`)
    $.ui.log(`redacted ${findings.length} value(s) from ${e.tool} — ${describe(findings)}`)
    await capture($, findings)

    // `ref` is dropped on purpose: keeping it makes core record its own
    // messages verbatim, which is exactly the unredacted text.
    if (r.isError === true) {
      return { isError: true, result: body.value, text: text?.text, context: ctx.list }
    }
    return { result: body.value as typeof r.result, context: ctx.list }
  }).catch(($, e, next) => {
    $.ui.log(
      `the guard failed on ${e.tool} (${next.error.kind}: ${next.error.message ?? 'no message'}) — ` +
        `this call's output was NOT scanned`,
    )
    return undefined
  })

  // --- what the person typed or pasted --------------------------------------
  on('prompt.submit', async ($, e, next) => {
    // Each prompt is a chance the Keychain was unlocked since the last refusal.
    scheduleRetry($)
    if (onPrompt === 'off') return next(e)
    const surface = promptSurface(e.origin.kind, promptOnly)
    if (surface === 'skip') return next(e)
    const prompt = redactText(e.text, surface === 'prompt' ? promptOpts : resultOpts)
    // `context` is what hooks attached beside the prompt; no person typed it.
    const ctx = promptOnly ? { list: e.context, findings: [] } : redactAll(e.context, resultOpts)
    const findings = [...prompt.findings, ...ctx.findings]
    await noteNear($, prompt.near, 'prompt')
    if (findings.length === 0) return next(e)

    count += findings.length
    $.ui.status(`credential-guard: ${count} caught`)
    await capture($, findings)
    if (onPrompt === 'block') {
      $.ui.log(`held back your prompt — it carries ${describe(findings)}`)
      return {
        drop: `the prompt carries ${findings.length} high-entropy value(s) (${describe(findings)}) and was not sent.`,
      }
    }
    $.ui.log(`redacted ${findings.length} value(s) from your prompt — ${describe(findings)}`)
    return next({ ...e, text: prompt.text, context: ctx.list })
  }).catch(($, e, next) => {
    $.ui.log(`the guard failed on your prompt (${next.error.kind}) — it was NOT scanned`)
    return undefined
  })

  // --- what a peer session, relay or webhook delivered ----------------------
  on('session.receive', async ($, e, next) => {
    if (!onDelivery || onPrompt === 'off') return next(e)
    const body = redactText(e.text, promptOpts)
    await noteNear($, body.near, `delivery:${e.origin.kind}`)
    if (body.findings.length === 0) return next(e)

    count += body.findings.length
    $.ui.status(`credential-guard: ${count} caught`)
    await capture($, body.findings)
    $.ui.log(
      `redacted ${body.findings.length} value(s) from a ${e.origin.kind} delivery — ${describe(body.findings)}`,
    )
    if (onPrompt === 'block') {
      return { consumed: `the delivery carried ${body.findings.length} high-entropy value(s) and was not queued.` }
    }
    return next({ ...e, text: body.text })
  }).catch(($, e, next) => {
    $.ui.log(`the guard failed on a ${e.origin.kind} delivery (${next.error.kind}) — it was NOT scanned`)
    return undefined
  })
}
