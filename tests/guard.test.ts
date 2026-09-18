import { test, expect, mock } from 'claude-code/testing'

test('a tool result reaches the transcript redacted', async ($, on) => {
  mock.store(on)
  mock.clock(on)
  const secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  on('tool.call', () => ({ result: { stdout: `AWS_SECRET_ACCESS_KEY=${secret}`, stderr: '', interrupted: false } }))

  const r = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
  const seen = JSON.stringify(r.result)
  expect(seen.includes(secret)).toBe(false)
  expect(seen.includes('[redacted')).toBe(true)
})

test('a clean tool result is passed through untouched', async ($, on) => {
  mock.store(on)
  mock.clock(on)
  on('tool.call', () => ({ result: { stdout: 'ok: 3 files changed', stderr: '', interrupted: false } }))
  const r = await $.tool.call({ tool: 'Bash', command: 'git status' })
  expect(JSON.stringify(r.result).includes('[redacted')).toBe(false)
})

test('a prompt is redacted before it reaches the model', async ($, on) => {
  mock.store(on)
  mock.clock(on)
  const secret = 'ghp_16C7e42F292c6912E7710c838347Ae178B4a'
  let arrived = ''
  on('prompt.submit', ($$, e) => {
    arrived = e.text
    return { text: e.text }
  })

  await $.prompt.submit({ text: `use ${secret} for the api`, wait: false, origin: { kind: 'composer' } })
  expect(arrived.includes(secret)).toBe(false)
  expect(arrived.includes('[redacted github-token')).toBe(true)
})
