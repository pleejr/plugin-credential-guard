import { test, expect, mock } from 'claude-code/testing'
import { INDEX_KEY, indexBlock, keychainSave, normalizeLabel, referencesIn, rehydrate, suggestLabel } from '../hooks/vault.ts'
import { fingerprint } from '../hooks/scan.ts'

const SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
const FP = fingerprint(SECRET)

test('a marker and an alias are both recognised as references', () => {
  const refs = referencesIn('run [secret:AWS_TEST] and [redacted aws-access-key #abcd1234] now')
  expect(refs.labels).toEqual(['AWS_TEST'])
  expect(refs.fingerprints).toEqual(['abcd1234'])
})

test('an unresolvable placeholder is left standing rather than emptied', () => {
  const r = rehydrate('echo [secret:MISSING]', () => undefined)
  expect(r.text).toBe('echo [secret:MISSING]')
  expect(r.used.length).toBe(0)
})

test('labels are normalized and suggested from the rule', () => {
  expect(normalizeLabel(' aws prod key ')).toBe('AWS_PROD_KEY')
  expect(suggestLabel('assigned:AWS_SECRET_ACCESS_KEY', 'abcd1234')).toBe('AWS_SECRET_ACCESS_KEY')
})

test('the context block names the placeholder and never the value', () => {
  const text = indexBlock({ [FP]: { label: 'AWS_TEST', rule: 'aws-access-key', savedAt: 0 } }) ?? ''
  expect(text.includes('[secret:AWS_TEST]')).toBe(true)
  expect(text.includes(SECRET)).toBe(false)
})

test('a saved secret is substituted into a tool call from the Keychain', async ($, on) => {
  mock.clock(on)
  mock.store(on, { [INDEX_KEY]: { [FP]: { label: 'AWS_TEST', rule: 'aws-access-key', savedAt: 0 } } })

  // Stand in for the `security` binary.
  on('process.run', ($$, e) => {
    const argv = e.argv
    if (argv[0] !== 'security' || argv[1] !== 'find-generic-password') return { value: { exitCode: 1, stdout: '', stderr: 'no' } }
    return { value: { exitCode: 0, stdout: `${SECRET}\n`, stderr: '' } }
  })

  let ran = ''
  on('tool.call', ($$, e) => {
    ran = e.tool === 'Bash' ? e.command : ''
    return { result: { stdout: 'done', stderr: '', interrupted: false } }
  })

  await $.tool.call({ tool: 'Bash', command: 'aws configure set aws_secret_access_key [secret:AWS_TEST]' })
  expect(ran.includes(SECRET)).toBe(true)
  expect(ran.includes('[secret:AWS_TEST]')).toBe(false)
})

test('a placeholder is left alone for a tool that sends arguments off the machine', async ($, on) => {
  mock.clock(on)
  mock.store(on, { [INDEX_KEY]: { [FP]: { label: 'AWS_TEST', rule: 'aws-access-key', savedAt: 0 } } })
  on('process.run', () => ({ value: { exitCode: 0, stdout: `${SECRET}\n`, stderr: '' } }))

  let sent = ''
  on('tool.call', ($$, e) => {
    sent = JSON.stringify(e)
    return { result: { code: 200 } }
  })

  await $.tool.call({ tool: 'WebFetch', url: 'https://example.com', prompt: 'send [secret:AWS_TEST]' })
  expect(sent.includes(SECRET)).toBe(false)
  expect(sent.includes('[secret:AWS_TEST]')).toBe(true)
})

test('the Keychain write puts nothing on argv and never prompts a terminal', async () => {
  let argv: readonly string[] = []
  let stdin = ''
  const run = async (a: readonly string[], init?: { stdin?: string }) => {
    argv = a
    stdin = init?.stdin ?? ''
    return { exitCode: 0, stdout: '', stderr: '' }
  }

  const value = 'ghp_0123456789abcdef0123456789abcdef0123'
  const r = await keychainSave(run, 'abcd1234', 'GITHUB_TOKEN', 'github-token', value)

  expect(r.ok).toBe(true)
  // `-w` with no value reads the controlling terminal and hangs; `-i` does not.
  expect(argv).toEqual(['security', '-i'])
  expect(argv.includes(value)).toBe(false)
  expect(stdin.includes(value)).toBe(false)
  expect(stdin.includes('-X 6768705f')).toBe(true)
  expect(stdin.endsWith('\n')).toBe(true)
})

test('a value the parser would split survives as hex', async () => {
  let stdin = ''
  const run = async (_a: readonly string[], init?: { stdin?: string }) => {
    stdin = init?.stdin ?? ''
    return { exitCode: 0, stdout: '', stderr: '' }
  }

  const value = 'pass word "with" quotes and ünicode'
  await keychainSave(run, 'abcd1234', 'AWKWARD', 'entropy', value)

  const hex = /-X ([0-9a-f]+)/.exec(stdin)?.[1] ?? ''
  const bytes = hex.match(/../g) ?? []
  const decoded = decodeURIComponent(bytes.map((b) => `%${b}`).join(''))
  expect(decoded).toBe(value)
  expect(stdin.split('\n')[0]?.includes(' ' + value)).toBe(false)
})

test('a refused write reports the reason without the value in it', async () => {
  const value = 'ghp_0123456789abcdef0123456789abcdef0123'
  const run = async (_a: readonly string[], init?: { stdin?: string }) => {
    const hex = /-X ([0-9a-f]+)/.exec(init?.stdin ?? '')?.[1] ?? ''
    // security echoes back the command line it refused.
    return { exitCode: 1, stdout: '', stderr: `add-generic-password -X ${hex}: returned 1` }
  }

  const r = await keychainSave(run, 'abcd1234', 'GITHUB_TOKEN', 'github-token', value)
  expect(r.ok).toBe(false)
  if (!r.ok) {
    expect(r.error.includes('[value]')).toBe(true)
    expect(r.error.includes('6768705f')).toBe(false)
  }
})
