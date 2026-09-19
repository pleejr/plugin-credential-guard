/**
 * The command-hook fallback for `prompt.submit`.
 *
 * The plugin's own `prompt.submit` hook only runs when the engine seats plugin
 * hooks modules. When the `tengu_plugin_hooks_modules` rollout flag resolves
 * off -- which a cold GrowthBook cache does on its own, with no error -- the
 * engine logs `Registered 0 hooks from 9 plugins` and every prompt reaches the
 * model unscanned. A guard that never ran reads exactly like a guard that
 * passed, so this path exists to be seated by `settings.json` instead, where
 * no rollout flag governs it.
 *
 * A `UserPromptSubmit` command hook cannot REWRITE the prompt -- the engine
 * exposes `additionalContext`, never an edited prompt -- so this path blocks
 * where the plugin would have redacted. Exit 2 holds the prompt back and shows
 * stderr to the person; the value never reaches the model or the transcript.
 *
 * Failure mode is OPEN, as in the plugin, but never silent: an unreadable
 * payload or a missing runtime exits 0 with a notice on stdout, which the
 * engine hands the model as context. Silence here would reproduce the bug
 * this file exists for.
 */
import { redactText, describe, type Finding } from '../scan.ts'

/** Already-redacted text: the plugin's hook ran first, so this path stands down. */
const MARKER = /\[redacted [a-z-]+ #[0-9a-f]{8}\]|\[secret:[A-Za-z0-9_]+\]/

function read(): Promise<string> {
  return new Promise((resolve) => {
    let buf = ''
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', (c) => (buf += c))
    process.stdin.on('end', () => resolve(buf))
  })
}

const main = async (): Promise<void> => {
  const raw = await read()
  let prompt: string
  try {
    const payload = JSON.parse(raw) as { prompt?: unknown }
    if (typeof payload.prompt !== 'string') {
      process.stdout.write('credential-guard fallback: the hook payload carried no prompt — it was NOT scanned.\n')
      return
    }
    prompt = payload.prompt
  } catch {
    process.stdout.write('credential-guard fallback: the hook payload did not parse — the prompt was NOT scanned.\n')
    return
  }

  if (MARKER.test(prompt)) return

  let findings: readonly Finding[]
  try {
    findings = redactText(prompt).findings
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    process.stdout.write(`credential-guard fallback: the detector threw (${msg}) — the prompt was NOT scanned.\n`)
    return
  }
  if (findings.length === 0) return

  process.stderr.write(
    `credential-guard: the prompt carries ${findings.length} high-entropy value(s) ` +
      `(${describe(findings)}) and was not sent.\n` +
      `The plugin's own hook is not seated in this session, and a command hook cannot redact in place, ` +
      `so the prompt is held back whole. Remove the value, or reference it from the environment.\n`,
  )
  process.exit(2)
}

void main()
