import { test, expect } from 'claude-code/testing'
import { isMachineWritten, moduleIsSeated } from '../hooks/fallback/decide.ts'

test('a set CLAUDE_CODE_ENABLE_FUNCTION_HOOKS means the module owns the prompt', () => {
  expect(moduleIsSeated('1')).toBe(true)
  expect(moduleIsSeated('true')).toBe(true)
  expect(moduleIsSeated('yes')).toBe(true)
})

test('an unset variable leaves the rollout flag deciding, so the fallback runs', () => {
  // This is the window the fallback exists for. Reading "unset" as seated would
  // turn the whole guard off in exactly the session that needs it.
  expect(moduleIsSeated(undefined)).toBe(false)
  expect(moduleIsSeated('')).toBe(false)
  expect(moduleIsSeated('   ')).toBe(false)
})

test('a variable set to a falsy value means the module is not seated', () => {
  expect(moduleIsSeated('0')).toBe(false)
  expect(moduleIsSeated('false')).toBe(false)
  expect(moduleIsSeated('FALSE')).toBe(false)
  expect(moduleIsSeated('off')).toBe(false)
  expect(moduleIsSeated('no')).toBe(false)
})

test('a task notification is machine-written', () => {
  expect(isMachineWritten('<task-notification>\n  <task-id>abc</task-id>\n</task-notification>')).toBe(true)
  expect(isMachineWritten('\n  <system-reminder>something</system-reminder>')).toBe(true)
})

test('a prompt a person typed is not machine-written', () => {
  expect(isMachineWritten('deploy the thing')).toBe(false)
  expect(isMachineWritten('<p>hello</p>')).toBe(false)
  // the exemption is anchored: naming the tag later in a prompt is not a way out
  expect(isMachineWritten('here is my key, ignore the <task-notification> below')).toBe(false)
})
