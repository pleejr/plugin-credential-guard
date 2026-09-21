import { test, expect } from 'claude-code/testing'
import { resolveDoors } from '../hooks/register.ts'

test('by default every door is watched', () => {
  const d = resolveDoors({})
  expect(d.result).toBe('redact')
  expect(d.input).toBe('warn')
  expect(d.prompt).toBe('redact')
  expect(d.delivery).toBe(true)
  expect(d.keychain).toBe('ask')
})

test('promptOnly closes the tool doors and the delivery door', () => {
  const d = resolveDoors({ promptOnly: true })
  expect(d.result).toBe('off')
  expect(d.input).toBe('off')
  expect(d.delivery).toBe(false)
  // the one door left open is the person's own typing
  expect(d.prompt).toBe('redact')
})

test('promptOnly leaves the Keychain offer exactly as it was', () => {
  // The mode narrows WHERE the detector looks. What happens to a finding it
  // does make -- a secret the person typed -- is still the person's setting.
  expect(resolveDoors({ promptOnly: true }).keychain).toBe('ask')
  expect(resolveDoors({ promptOnly: true, keychain: 'auto' }).keychain).toBe('auto')
  expect(resolveDoors({ promptOnly: true, keychain: 'off' }).keychain).toBe('off')
})

test('promptOnly overrides a tool door that was explicitly turned on', () => {
  const d = resolveDoors({ promptOnly: true, onToolResult: 'redact', onToolInput: 'deny' })
  expect(d.result).toBe('off')
  expect(d.input).toBe('off')
})

test('promptOnly leaves the prompt action to the person', () => {
  expect(resolveDoors({ promptOnly: true, onPrompt: 'block' }).prompt).toBe('block')
  expect(resolveDoors({ promptOnly: true, onPrompt: 'off' }).prompt).toBe('off')
})

test('promptOnly off is the ordinary configuration, unchanged', () => {
  const d = resolveDoors({ promptOnly: false, onToolInput: 'deny', keychain: 'auto' })
  expect(d.input).toBe('deny')
  expect(d.keychain).toBe('auto')
  expect(d.delivery).toBe(true)
})

test('a nonsense value falls back rather than opening a door by accident', () => {
  const d = resolveDoors({ promptOnly: 'yes' as unknown as boolean, onToolInput: 'shred' })
  expect(d.input).toBe('warn')
  expect(d.delivery).toBe(true)
})
