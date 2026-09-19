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

test('a random-looking run in a tool argument is let past, and in a prompt is not', async ($, on) => {
  mock.store(on)
  mock.clock(on)
  const shaped = 'Xq7Vb2Np9Kd4Rt6Wm1Zy8Lc3Hj5Ff0Gs'
  const logged: string[] = []
  let arrived = ''
  on('tool.call', () => ({ result: { stdout: 'ok', stderr: '', interrupted: false } }))
  on('prompt.submit', ($$, e) => {
    arrived = e.text
    return { text: e.text }
  })
  on('ui.log', ($$, e, next) => {
    logged.push(e.text)
    return next(e)
  })

  // `shapeRules` defaults to `prompt`, so the argument goes by unremarked --
  // this is the line the person was seeing on every other Bash call.
  await $.tool.call({ tool: 'Bash', command: `deploy --build ${shaped}` })
  expect(logged.some((t) => t.includes('entropy'))).toBe(false)

  await $.prompt.submit({ text: `here it is: ${shaped}`, wait: false, origin: { kind: 'composer' } })
  expect(arrived.includes(shaped)).toBe(false)
})

test('a named credential in a tool argument is still caught', async ($, on) => {
  mock.store(on)
  mock.clock(on)
  on('tool.call', () => ({ result: { stdout: 'ok', stderr: '', interrupted: false } }))
  const seen: string[] = []
  on('ui.log', ($$, e, next) => {
    seen.push(e.text)
    return next(e)
  })

  await $.tool.call({ tool: 'Bash', command: 'curl -H "Authorization: Bearer ' + 'gh' + 'p_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" https://api.github.com' })
  expect(seen.some((t) => t.includes('github-token'))).toBe(true)
})
