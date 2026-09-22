/**
 * What the command-hook fallback decides before it scans anything.
 *
 * Kept apart from `prompt-guard.ts` because that file runs `main()` at module
 * scope and blocks on stdin: a test that imported it would hang. These are pure
 * and take their world as arguments.
 */

/**
 * Whether the plugin's own `prompt.submit` module is seated, as far as the
 * environment can say.
 *
 * The engine resolves seating as
 * `env.CLAUDE_CODE_ENABLE_FUNCTION_HOOKS ?? growthbook('tengu_plugin_hooks_modules')`.
 * A set variable therefore decides outright; unset means the rollout flag does,
 * which is exactly the window this fallback exists to cover, so unset reads as
 * NOT seated and the fallback runs.
 *
 * This is what the stand-down hangs on rather than the redaction marker. The
 * marker only works if the command hook is handed the text the module rewrote,
 * and that is not established: the fallback was observed standing down on
 * 2026-09-18 and blocking a prompt the module had demonstrably redacted on
 * 2026-09-21. Reading the environment is correct under either ordering.
 */
export function moduleIsSeated(value: string | undefined): boolean {
  if (value === undefined) return false
  const v = value.trim().toLowerCase()
  if (v === '' || v === '0' || v === 'false' || v === 'off' || v === 'no') return false
  return true
}

/**
 * Whether the prompt was written by the harness rather than by a person.
 *
 * Blocking one is never actionable: a task notification carries identifiers no
 * person chose and no person can remove, so exit 2 costs the delivery and
 * offers nothing in return. Deliberately narrow -- a whole prompt that IS one
 * harness element -- because every name added here is a name a person could put
 * at the top of their own prompt to skip the guard.
 */
export function isMachineWritten(prompt: string): boolean {
  return /^\s*<(task-notification|system-reminder)\b/.test(prompt.trimStart())
}
