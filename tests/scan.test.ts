import { test, expect } from 'claude-code/testing'
import { entropyRatioOf, fingerprint, redactText, scan, scanAll } from '../hooks/scan.ts'

test('flags a random base64 key and leaves a git SHA alone', () => {
  expect(scan('token: k3Jd8vQm2XpLzRf7TnWbHy4CsGu9AeVx').length).toBe(1)
  expect(scan('commit 9f2c1a7b3e5d84c6f0a9b2d1e7c4f8a6b3d5e2c1').length).toBe(0)
})

test('normalized entropy separates key material from a filesystem path', () => {
  expect(entropyRatioOf('k3Jd8vQm2XpLzRf7TnWbHy4CsGu9AeVx')).toBeGreaterThan(0.9)
  expect(entropyRatioOf('/Users/dev/Documents/repos/infra-aws-tf-example-prod')).toBeLessThan(0.85)
})

test('named patterns fire regardless of length or entropy', () => {
  expect(scan('AKIAIOSFODNN7EXAMPLE', { flagAwsKeyIds: true })[0]?.rule).toBe('aws-access-key')
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

test('what sits before a value can declare it public', () => {
  expect(scan('fingerprint `SHA256:hjoBns2C9Wxq57SjAAtaY3bpXUKkiVdJQ1w2e3R4t5Y`').length).toBe(0)
  expect(scan('serial = 5E386EADB55F01504CAE8BCF7198F4B714ABFC68').length).toBe(0)
  expect(scan('`AUTH0_CLIENT_ID` = `aBcD3fGh1JkLmN0pQrStUvWxYz123456`').length).toBe(0)
  expect(scan('against account `0D8784105F40400308CE42C527B85A02`').length).toBe(0)
})

test('a declaration does not reach past its window or into a query string', () => {
  const key = 'Xq7vKpL2ZmR8tNwB4dHc9YgT3sFj6QaZ'
  expect(scan(`fingerprint ${'.'.repeat(60)} ${key}`).length).toBe(1)
  expect(scan(`https://example.com/callback?token=${key}`).length).toBe(1)
})

test('an access key id counts only with its secret half beside it', () => {
  const id = 'AKIA' + 'IOSFODNN7EXAMPLE'
  expect(scan(`key ${id} active since 2026-02-20`).length).toBe(0)
  expect(scan(`key ${id} active since 2026-02-20`, { flagAwsKeyIds: true }).length).toBe(1)
  expect(scan(`${id} / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`).length).toBeGreaterThan(0)
})

test('a long CamelCase word inside an identifier does not make it key material', () => {
  expect(scan('max_connections is LEAST({DBInstanceClassMemory},5000)').length).toBe(0)
})

test('a one-word value still counts when the name says password', () => {
  expect(scan('PASSWORD=correcthorse').length).toBe(1)
})

test('an assignment whose value is a key name or a shell fragment is not a credential', () => {
  expect(scan('secrets: TERRAFORM_TOKEN: required: true').length).toBe(0)
  expect(scan('TOKEN=$(jq -r .credentials.token ~/.terraform.d/credentials.tfrc.json)').length).toBe(0)
  expect(scan('SECRET_RE = re.compile(r"[0-9a-f]{12}")').length).toBe(0)
  expect(scan("aws rds describe-db-clusters --query 'DBClusters[0].{Secret:MasterUserSecret}'").length).toBe(0)
})

test('a prose label does not make the word after it a secret', () => {
  expect(scan('Secrets: encrypted env/*.ejson decrypted locally to .env files.').length).toBe(0)
})

test('an elided credential id is a redaction, not a leak', () => {
  expect(scan('CREDENTIAL_ID=32b00056-… was the real BitBucket access key').length).toBe(0)
  expect(scan('aws configure set aws_secret_access_key [secret:AWS_PROD]').length).toBe(0)
})

test('a published identifier stays published: a turnstile site key, an ecs task id', () => {
  expect(scan('the widget renders with 0x4AAAAAABc1dEfGhIjKlMnO in the page').length).toBe(0)
  expect(scan('aws ecs describe-tasks --tasks 0de381fa1b284946a0f3b7c25e4d19cc').length).toBe(0)
  // the declaration binds to the whole list, not only to its first element
  expect(scan('--tasks 0de381fa1b284946a0f3b7c25e4d19cc 9c286fe6b26048ea8c1d7f40a2b5e3d1').length).toBe(0)
  expect(scan('--tasks 0de381fa1b284946a0f3b7c25e4d19cc --key 9c286fe6b26048ea8c1d7f40a2b5e3d1').length).toBe(1)
})

test('shapeRules off keeps the rules that read what the text calls a value', () => {
  const opts = { shapeRules: false }
  // The entropy rule is the one that goes quiet.
  const random = 'Xq7Vb2Np9Kd4Rt6Wm1Zy8Lc3Hj5Ff0Gs'
  expect(scan(random).length).toBe(1)
  expect(scan(random, opts).length).toBe(0)
  // A named pattern and an announced assignment still fire.
  expect(scan('ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8', opts)[0]?.rule).toBe('github-token')
  expect(scan(`API_KEY=${random}`, opts)[0]?.rule).toBe('assigned:API_KEY')
})

test('shapeRules off still catches an access key beside its secret half', () => {
  const pair = 'AKIAIOSFODNN7EXAMPLE and wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  expect(scan(pair, { shapeRules: false }).some((f) => f.rule === 'aws-access-key')).toBe(true)
})

test('shapeRules off records no near miss, because no shape rule judged one', () => {
  const text = 'HTTPCode_ELB_5XX_Count and 0de381fa1b284946a0f3b7c25e4d19cc'
  expect(scanAll(text, { shapeRules: false }).near.length).toBe(0)
})

test('a vendor prefix of words does not make a key a name', () => {
  // `<vendor>_<kind>_<key>`: two word segments carried the whole run past
  // looksLikeName. Fabricated: base64 of a Laravel-style {iv,value,mac,tag}.
  const key = 'testmo_api_' + 'eyJpdiI6IlZZTUtNZnJaVTF1WjlONlJqcTdCWVE9PSIsInZhbHVlIjoiWGt5UThkbUgzV1NvZXRMZnJycE11UGxMN2sveDFYcnZlWHVkZ1FyOFE0MD03ZmJoSmROVmV2d1dycnZGNDVXY2FnPT0iLCJtYWMiOiI0MjljNGZkMmQ5YzBiNWQ5MGJlNzRmYmJjOTIzOWVmY2Q0NmM3YTNiNDAyNGJiYjQxNWU5YWEwOTE2ZWUyZjYyIiwidGFnIjoiIn0='
  expect(scan(key).length).toBe(1)
  expect(scan(`generated the following API key:\n${key}`).length).toBe(1)
  expect(scan('service_watchtower_processor_7d9f8c6b54_xk2mq').length).toBe(0)
})
