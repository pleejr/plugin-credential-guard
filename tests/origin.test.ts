import { test, expect, mock } from 'claude-code/testing'
import { promptSurface, typedByPerson } from '../hooks/register.ts'

// A task notification reaches `prompt.submit` like a typed prompt, carrying a
// `<tool-use-id>` the shape rules read as a key. Observed on 2026-09-22 under
// promptOnly: eleven `[redacted entropy]` placeholders, every one a tool-use id.

test("the person's own channels count as typed", () => {
  for (const kind of ['composer', 'bridge', 'sdk', 'slack-ping']) {
    expect(typedByPerson(kind)).toBe(true)
  }
})

test('harness and peer origins do not count as typed', () => {
  for (const kind of [
    'task-notification',
    'scheduled-trigger',
    'peer',
    'peer-send-message',
    'projects-relay',
    'channel',
    'coordinator',
    'observer',
    'observer-activity',
    'auto-continuation',
    'unclassified',
    'plugin',
  ]) {
    expect(typedByPerson(kind)).toBe(false)
  }
})

test('an origin this build does not know is not treated as typed', () => {
  expect(typedByPerson('something-new')).toBe(false)
})

test('under promptOnly a task notification is not scanned at all', () => {
  expect(promptSurface('task-notification', true)).toBe('skip')
})

test('under promptOnly a typed prompt keeps the prompt rules', () => {
  expect(promptSurface('composer', true)).toBe('prompt')
})

test('ordinarily a task notification is scanned as machine text, without shape rules', () => {
  expect(promptSurface('task-notification', false)).toBe('machine')
  expect(promptSurface('composer', false)).toBe('prompt')
})

// Event level, default options. The option itself is not mockable here, so the
// promptOnly `skip` branch is covered by promptSurface above.
const notification = (id: string, extra = ''): string =>
  `<task-notification>\n<task-id>b6au65pvv</task-id>\n<tool-use-id>${id}</tool-use-id>\n` +
  `<status>completed</status>\n<summary>Background command "Wait for CI" completed (exit code 0)${extra}</summary>\n</task-notification>`

test('a tool-use id in a task notification is let past, and typed is not', async ($, on) => {
  mock.store(on)
  mock.clock(on)
  const id = 'toolu_01Xq7Vb2Np9Kd4Rt6Wm1Zy8Lc3'
  let arrived = ''
  on('prompt.submit', ($$, e) => {
    arrived = e.text
    return { text: e.text }
  })

  await $.prompt.submit({ text: notification(id), wait: false, origin: { kind: 'task-notification' } })
  expect(arrived.includes(id)).toBe(true)

  // control: the same id typed at the composer trips the shape rules
  await $.prompt.submit({ text: `look at ${id}`, wait: false, origin: { kind: 'composer' } })
  expect(arrived.includes(id)).toBe(false)
})

test('a named credential inside a task notification is still redacted', async ($, on) => {
  mock.store(on)
  mock.clock(on)
  const secret = 'gh' + 'p_16C7e42F292c6912E7710c838347Ae178B4a'
  let arrived = ''
  on('prompt.submit', ($$, e) => {
    arrived = e.text
    return { text: e.text }
  })

  await $.prompt.submit({
    text: notification('toolu_01Xq7Vb2Np9Kd4Rt6Wm1Zy8Lc3', ` ${secret}`),
    wait: false,
    origin: { kind: 'task-notification' },
  })
  expect(arrived.includes(secret)).toBe(false)
  expect(arrived.includes('[redacted github-token')).toBe(true)
})
