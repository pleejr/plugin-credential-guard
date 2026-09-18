import { test, expect } from 'claude-code/testing'
import { entropyRatioOf, fingerprint, redactText, scan } from '../hooks/scan.ts'

test('flags a random base64 key and leaves a git SHA alone', () => {
  expect(scan('token: k3Jd8vQm2XpLzRf7TnWbHy4CsGu9AeVx').length).toBe(1)
  expect(scan('commit 9f2c1a7b3e5d84c6f0a9b2d1e7c4f8a6b3d5e2c1').length).toBe(0)
})

test('normalized entropy separates key material from a filesystem path', () => {
  expect(entropyRatioOf('k3Jd8vQm2XpLzRf7TnWbHy4CsGu9AeVx')).toBeGreaterThan(0.9)
  expect(entropyRatioOf('/Users/dev/Documents/repos/infra-aws-tf-example-prod')).toBeLessThan(0.85)
})

test('named patterns fire regardless of length or entropy', () => {
  expect(scan('AKIAIOSFODNN7EXAMPLE')[0]?.rule).toBe('aws-access-key')
  expect(scan('sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc')[0]?.rule).toBe('stripe-key')
})

test('a redaction carries the rule and a stable fingerprint, never the value', () => {
  const secret = 'k3Jd8vQm2XpLzRf7TnWbHy4CsGu9AeVx'
  const out = redactText(`export KEY=${secret}`).text
  expect(out.includes(secret)).toBe(false)
  expect(out.includes(fingerprint(secret))).toBe(true)
})

test('the allow list stops a fingerprint from being flagged again', () => {
  const secret = 'k3Jd8vQm2XpLzRf7TnWbHy4CsGu9AeVx'
  expect(scan(secret, { allow: new Set([fingerprint(secret)]) }).length).toBe(0)
})

test('a cue word in prose lowers the bar for a nearby weak key', () => {
  const key = 'OAJdjljiaw82nd73jlad00d02jld892gygo'
  expect(scan(key).length).toBe(0)
  const found = scan(`here's a fake api key for apitester ${key}`)
  expect(found.length).toBe(1)
  expect(found[0]?.rule).toBe('entropy-cue')
})

test('a cue word alone does not flag ordinary text near it', () => {
  expect(scan('the total_tokens field says 14998361 tokens left in this window').length).toBe(0)
  expect(scan('rotate the api key in terraform-aws-module-config before the deploy').length).toBe(0)
})

test('the proximity window is bounded', () => {
  const key = 'OAJdjljiaw82nd73jlad00d02jld892gygo'
  expect(scan(`api key ${'.'.repeat(200)} ${key}`).length).toBe(0)
  expect(scan(`api key ${key}`, { proximityWindow: 0 }).length).toBe(0)
})

test('a url or path carrying a uuid or a git sha is not key material', () => {
  expect(scan('https://github.com/example-org/example-wiki/pull/new/wt/95f1b764-64bf-445a-993f-7d8061bbf252').length).toBe(0)
  expect(scan('/var/lib/buildkite/builds/4d8e1f0a9b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e/artifacts/report.xml').length).toBe(0)
  expect(scan('/Users/dev/Documents/repos/example-wiki/.worktrees/95f1b764-64bf-445a-993f-7d8061bbf252').length).toBe(0)
})

test('a slash inside key material still does not make it a path', () => {
  expect(scan('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY').length).toBe(1)
  expect(scan('k3jd8vqm2xplzrf7/tnwbhy4csgu9aevx').length).toBe(1)
})

test('strictHex stops a sha segment from excusing the path around it', () => {
  const p = '/var/lib/builds/4d8e1f0a9b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e/out'
  expect(scan(p).length).toBe(0)
  expect(scan(p, { strictHex: true }).length).toBeGreaterThan(0)
})

test('an identifier spelled out of words and acronyms is not key material', () => {
  expect(scan('the alarm watches HTTPCode_ELB_5XX_Count on prod-alb').length).toBe(0)
  expect(scan('run AWS-RunPatchBaseline then AWSEC2-ConfigureSTIG').length).toBe(0)
  expect(scan('the diagram shows VPC/subnets/NAT/IGW/route wiring').length).toBe(0)
  expect(scan('attach AWSLambda_FullAccess to the execution role').length).toBe(0)
})

test('a published run, trigger or rule id is not a secret', () => {
  expect(scan('run-2dpEth3mLTP3g73n finished applying').length).toBe(0)
  expect(scan('trig_01564HvjAymVrZkqfnX2bjS7 fired the run').length).toBe(0)
  expect(scan('sgr-0590b743d0db69ea3 allows 443 from the office').length).toBe(0)
})

test('a path segment may begin with a dot or a hyphen', () => {
  const p = '/Users/dev/.claude/projects/-private-tmp/beaf7dc3-6bd2-43e5-933e-50d1dea7b329.jsonl'
  expect(scan(p).length).toBe(0)
})

test('a cue word lowers the length floor without un-exempting the path around it', () => {
  expect(scan('/Users/dev/repos/skills/handle-a-found-credential/SKILL.md').length).toBe(0)
  const short = 'Xq7vKpL2ZmR8tNwB4d'
  expect(short.length).toBeLessThan(24)
  expect(scan(`api key: ${short}`).length).toBe(1)
  expect(scan(`the build id is ${short}`).length).toBe(0)
})

test('a service namespace is not a credential name', () => {
  expect(scan('the role needs secretsmanager:GetSecretValue').length).toBe(0)
  expect(scan('metadata_options { http_tokens = "required" }').length).toBe(0)
})

test('a one-word value still counts when the name says password', () => {
  expect(scan('PASSWORD=correcthorse').length).toBe(1)
})
