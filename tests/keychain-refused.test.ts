import { test, expect, mock } from 'claude-code/testing'
import { INDEX_KEY } from '../hooks/vault.ts'

// A session over SSH, or anything else outside the login window's security
// session, cannot unlock the login Keychain: `security` answers -25308.
const REFUSED = 'security: SecKeychainItemCreateFromContent (<default>): User interaction is not allowed.'
const SECRET = 'gh' + 'p_16C7e42F292c6912E7710c838347Ae178B4a'

test('a Keychain the session cannot reach keeps the secret queued and says so plainly', async ($, on) => {
  const clock = mock.clock(on)
  const store = new Map<string, unknown>()
  on('store.get', ($$, e) => ({ value: store.get(e.key) ?? null }))
  on('store.set', ($$, e) => {
    store.set(e.key, e.value)
    return { value: undefined }
  })

  // The person answers the offer: save it, under the suggested name.
  // `$.ui.ask` travels as an AskUserQuestion call, which this build's generated
  // tool types do not list: matched by pattern, read through `unknown`.
  on('tool.call', { tool: /^AskUserQuestion$/ }, ($$, e) => {
    const questions = (e as unknown as { questions: { question: string }[] }).questions
    const question = String(questions[0]?.question ?? '')
    const answer = question.includes('Save it to your macOS login Keychain') ? 'Save to Keychain' : 'GITHUB_TOKEN'
    return { result: { questions, answers: { [question]: answer } } }
  })

  let locked = true
  let writes = 0
  on('process.run', ($$, e) => {
    if (e.argv[0] !== 'security') return { value: { exitCode: 1, stdout: '', stderr: '' } }
    writes++
    return locked
      ? { value: { exitCode: 36, stdout: '', stderr: REFUSED } }
      : { value: { exitCode: 0, stdout: '', stderr: '' } }
  })

  const toasts: string[] = []
  on('ui.toast', ($$, e) => {
    toasts.push(e.text)
    return { value: undefined }
  })
  on('ui.log', () => ({ value: undefined }))
  on('ui.status', () => ({ value: undefined }))
  on('prompt.submit', ($$, e) => ({ text: e.text }))

  await $.prompt.submit({ text: `token: ${SECRET}`, wait: false, origin: { kind: 'composer' } })
  await clock.advance(100)

  await clock.advance(1000)
  // Refused: nothing indexed, and the person is told why in words, not a code.
  expect(writes).toBe(1)
  expect(Object.keys((store.get(INDEX_KEY) as object | undefined) ?? {}).length).toBe(0)
  expect(toasts.some((t) => /locked|can't reach|cannot reach/i.test(t) && !/-25308/.test(t))).toBe(true)

  // The Keychain becomes reachable; the next prompt retries without asking again.
  locked = false
  await $.prompt.submit({ text: 'carry on', wait: false, origin: { kind: 'composer' } })
  await clock.advance(1000)
  expect(writes).toBe(2)
  const idx = (store.get(INDEX_KEY) ?? {}) as Record<string, { label: string }>
  expect(Object.values(idx).map((v) => v.label)).toEqual(['GITHUB_TOKEN'])
  expect(toasts.some((t) => /saved/i.test(t))).toBe(true)
})
