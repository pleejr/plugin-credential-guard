import { test, expect } from 'claude-code/testing'
import { scan } from '../hooks/scan.ts'

// Fabricated values. Vendor-prefixed fixtures are split `'prefix' + 'body'` so
// the source carries no literal that push protection reads as a live key.
const HEX32 = '7210ce8397794385781f51b8b1d129c9'
const HEX40 = 'd713a03b26354ab050f57617f49f44dd83063b2b'
const HEX64 = '5bfb192c356eb8cc54403556bd2a239623672edc6ddd2308953268841e33c387'
const UUID = 'a62e3fc3-7812-4fa4-a1d3-73e447a77bb2'
const MIXED40 = 'eNN1EnmyLVS8k2wlola2Xs0QblwBmKi6lQVvWCsE'

const caught = (text: string): boolean => scan(text).length > 0

test('a weak public word does not outrank a cue word before it', () => {
  // "account", "tenant", "client" name containers as often as identifiers.
  expect(caught('here is the api key for the new account: ' + 'lin_api_' + MIXED40)).toBe(true)
  expect(caught('the token for our tenant: ' + MIXED40)).toBe(true)
  // A strong declaration still wins, cue or not.
  expect(caught('the signing key fingerprint SHA256:k3Jd8vQm2XpLzRf7TnWbHy4CsGu9AeVxQw3rTy7UiOp')).toBe(false)
  expect(caught('account: 123456789012')).toBe(false)
})

test('a directly announced password is judged with its punctuation', () => {
  expect(caught('the password is Summer2026!')).toBe(true)
  expect(caught('password: pAlZkH00rMvd!#Et')).toBe(true)
  expect(caught('my pw is Tr0ub4dor&3')).toBe(true)
  expect(caught('the passphrase is river-tiger-summer-horse')).toBe(true)
})

test('prose about a password is not a password', () => {
  expect(caught('the password is required')).toBe(false)
  expect(caught('the password is stored in 1Password')).toBe(false)
  expect(caught('reset the password: see the runbook')).toBe(false)
  expect(caught('the password is ********')).toBe(false)
  expect(caught('password: <redacted>')).toBe(false)
  expect(caught('secret: arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf')).toBe(false)
  expect(caught('token: vault:kv/data/payments/prod-api-credentials')).toBe(false)
  expect(caught('api key: jdoe@example.com:' + 'Qw3rTy7UiOp1AsDfGh5JkLzX')).toBe(true)
  expect(caught('the password is in the vault, rotated monthly')).toBe(false)
})

test('a directly announced uuid or 40-hex key is a key', () => {
  expect(caught('the api key is ' + UUID)).toBe(true)
  expect(caught('API_KEY=' + UUID)).toBe(true)
  expect(caught('app key: ' + HEX40)).toBe(true)
  // Unannounced, both stay what they usually are: an id and a git sha.
  expect(caught(UUID)).toBe(false)
  expect(caught('commit ' + HEX40)).toBe(false)
  expect(caught('the token fix landed in ' + HEX40)).toBe(false)
  expect(caught('CREDENTIAL_ID=' + UUID)).toBe(false)
})

test('a short prefix in front of a hex body is judged on the hex', () => {
  expect(caught('shpat_' + HEX32)).toBe(true)
  expect(caught('key-' + HEX32)).toBe(true)
  expect(caught('SK' + HEX32)).toBe(true)
  expect(caught('API_KEY=dop_v1_' + HEX64)).toBe(true)
  expect(caught('dop_v1_' + HEX64)).toBe(true)
  // A content hash keeps its exemption.
  expect(caught('sha256-' + HEX64)).toBe(false)
})

test('a prefix that names itself a key announces its own body', () => {
  expect(caught('acme_api_' + '90ca2m8e2fyeza1ofisoc5hzm3v0uvmv')).toBe(true)
  expect(caught('aws_api_gateway_integration_response')).toBe(false)
  expect(caught('google_api_key_restrictions')).toBe(false)
  expect(caught('my_token_bucket_ratelimiter')).toBe(false)
})

test('named vendor formats fire', () => {
  expect(caught('glpat-' + 'jf8M5GSHbbJMjOJ2JWte')).toBe(true)
  expect(caught('SG.' + 'J7MeJ49pocOUdaHrTQB3b1' + '.' + '3HaE1NKGjTUoQrWWz0gSgaEvxHVUFyO39fjKWbN1WFS')).toBe(true)
  expect(caught('PMAK-' + 'a1372bd4f473bc724b042433' + '-' + '736d542c621b3e46680babaf12b599b437')).toBe(true)
  expect(caught('pat-na1-' + UUID)).toBe(true)
  expect(caught('xkeysib-' + HEX64 + '-OUpQAdWju92pGaTM')).toBe(true)
})

test('base64 of structured data is judged as data, not as prose', () => {
  // base64 of a fabricated {"iv","value","mac","tag"} -- JSON, not a sentence.
  const body =
    'eyJpdiI6Im9DRzdOODg0UzAzLzZGNjFZY0Vvc1E9PSIsInZhbHVlIjoiTERVeEk1eHAyc0R3SVgyZGdDeWo0TjEvK28ybDRXam12aXF4WjhKRzd0NFhMMWo5Q044SElJak85MXlrWDZ4TyIsIm1hYyI6IjA1N2FmM2E0NmRjYzU3ZWFhNzkzZjM5ZmNjZjhkNzI0YjM1OWYyNTNkYjdkNDc2OWNiZWM3YWI5Y2VkYzVmZDYiLCJ0YWciOiIifQ=='
  expect(caught(body)).toBe(true)
  expect(caught('VGhpcyBpcyBqdXN0IGEgc2VudGVuY2UgZW5jb2RlZA==')).toBe(false)
})
