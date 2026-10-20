import { test, expect, mock } from 'claude-code/testing'
import { INDEX_KEY } from '../hooks/vault.ts'

// Default options: announceSecrets is off, so prompt.context is not hooked and a
// saved secret is not listed, even with one in the index.
test('saved secrets are not listed to the model by default', async ($, on) => {
  mock.store(on, { [INDEX_KEY]: { '0123abcd': { label: 'AWS_TEST', rule: 'aws-access-key', savedAt: 0 } } })
  mock.clock(on)
  on('prompt.context', ($$, e) => ({ blocks: e.blocks }))
  const r = await $.prompt.context({ blocks: [] })
  expect(JSON.stringify(r).includes('credentialGuardSecrets')).toBe(false)
  expect(JSON.stringify(r).includes('[secret:AWS_TEST]')).toBe(false)
})
