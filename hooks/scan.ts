/**
 * The detector. Pure: no engine, no I/O, so it is unit-testable on its own
 * and cheap enough to run on every tool result inside a hook's 10 s budget.
 *
 * The core measure is Shannon entropy per character, NORMALIZED by the most
 * a token of that length could carry (log2(min(length, 64))). Raw bits/char
 * is length-biased -- a 20-character random key cannot exceed 4.32 bits/char
 * while a 200-character one approaches 6 -- so a single raw threshold either
 * misses short keys or flags long prose. The ratio is flat across lengths:
 * random base64 sits at 0.87-0.99, filesystem paths and English at 0.65-0.81.
 */

/**
 * Characters a secret is made of. `.` is excluded so a JWT splits into its
 * three segments and a dotted hostname or version never forms one token; `=`
 * is taken only as trailing base64 padding, so `KEY=<secret>` splits at the
 * `=` and the fingerprint is of the value alone.
 */
const TOKEN = /[A-Za-z0-9+/_-]{8,}={0,2}/g

/** Shapes that are a credential whatever their entropy. */
const PATTERNS: readonly (readonly [string, RegExp])[] = [
  ['private-key', /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,20000}?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----/g],
  ['aws-access-key', /\b(?:AKIA|ASIA|ABIA|ACCA|AIDA|AROA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b/g],
  ['aws-session-token', /\b(?:FwoG|IQoJb3JpZ2lu|FQoG)[A-Za-z0-9+/=_-]{40,}/g],
  ['github-token', /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g],
  ['github-pat', /\bgithub_pat_[A-Za-z0-9_]{50,}\b/g],
  ['slack-token', /\bxox[abeoprs]-[A-Za-z0-9-]{10,}/g],
  ['slack-webhook', /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9+/_-]{20,}/g],
  ['anthropic-key', /\bsk-ant-[A-Za-z0-9_-]{24,}/g],
  ['openai-key', /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/g],
  ['google-api-key', /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ['stripe-key', /\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}\b/g],
  ['npm-token', /\bnpm_[A-Za-z0-9]{36}\b/g],
  ['pypi-token', /\bpypi-[A-Za-z0-9_-]{32,}/g],
  ['jwt', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g],
  ['url-credential', /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]{1,64}:([^\s@/]{4,})@/g],
  ['bearer-header', /\b(?:[Aa]uthorization:\s*)?[Bb]earer\s+[A-Za-z0-9+/=_.-]{20,}/g],
]

/** `SECRET=<value>`: the name says it is a credential, so the entropy bar for
 *  the value drops -- a weak password is still a secret. */
const ASSIGNED = /\b([A-Za-z0-9_]*(?:SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_?KEY|ACCESS_KEY|AUTH_?TOKEN|TOKEN|CREDENTIAL)[A-Za-z0-9_]*)\s*[:=]\s*["']?([^\s"'`,;]{8,})/gi

/**
 * Words that announce a credential in prose. Near one of these the entropy bar
 * drops, the way it already drops on the left of `SECRET=`: a person who wrote
 * "here's my api key" has said what the next token is, and a key chosen by hand
 * is often too repetitive to clear the ordinary threshold on its own.
 */
const CUE = /\b(?:api[\s_-]?keys?|access[\s_-]?keys?|secret[\s_-]?keys?|signing[\s_-]?keys?|private[\s_-]?keys?|auth[\s_-]?tokens?|access[\s_-]?tokens?|tokens?|secrets?|passwords?|passwd|passphrases?|credentials?|creds?|bearer|api[\s_-]?secrets?)\b/gi

/**
 * Text immediately to the LEFT of a candidate that declares what follows to be
 * public. The mirror of CUE: "here's my api key" lowers the bar, and
 * `fingerprint SHA256:` raises it out of reach. These prefixes are not part of
 * the candidate -- the token regex stops at `:` and at whitespace -- so the
 * declaration can only be seen by looking behind.
 */
const PUBLIC_LEAD = new RegExp(
  [
    // `fingerprint SHA256:<43 chars>` -- the hash name is not part of the token.
    String.raw`(?:SHA256|SHA512|SHA1|MD5)\s*[:=]\s*$`,
    // A word that names an identifier, then up to eight characters of quoting.
    // `(?:\b|_)` so `AUTH0_CLIENT_ID` matches: `_CLIENT` carries no word boundary.
    String.raw`(?:\b|_)(?:` +
      [
        'fingerprints?', 'thumbprint', 'serials?', 'serial[\\s_-]?numbers?',
        'clients?', 'client[\\s_-]?id', 'key[\\s_-]?id', 'public[\\s_-]?key', 'pubkey',
        'site[\\s_-]?key', 'sitekey', 'issuer', 'subject', 'checksums?', 'digest',
        'commit', 'sha', 'etag', 'accounts?', 'tenants?', 'wallet', 'address',
        'request[\\s_-]?id', 'trace[\\s_-]?id', 'correlation[\\s_-]?id',
        // An ECS task id is 32 lowercase hex and appears in every describe-tasks
        // call: measured 6 times in 8957 shell commands to 2026-09-18.
        'tasks?', 'task[\\s_-]?ids?',
      ].join('|') +
      String.raw`)\b["'\`\s:=(,-]{0,8}$`,
    // The path of an ordinary URL. A query string is excluded on purpose --
    // `?token=<value>` is exactly the leak this plugin exists to catch.
    String.raw`https?://[A-Za-z0-9.-]+(?:/[A-Za-z0-9._~-]*)*/$`,
  ].join('|'),
  'i',
)

/** How far back a public declaration is still binding. */
const PUBLIC_LEAD_WINDOW = 48

/** Identifiers that look random and are not secrets. */
const KNOWN_PUBLIC: readonly (readonly [string, RegExp])[] = [
  ['uuid', /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/],
  ['aws-resource-id', /^(?:ami|i|subnet|vpc|sg|sgr|vol|snap|eni|rtb|igw|nat|acl|pl|lt|tgw|vpce|eipalloc|dopt|fl|r)-(?:[0-9a-f]{8}|[0-9a-f]{17})$/],
  // Terraform Cloud ids are random and published in every run URL and webhook.
  ['tfc-id', /^(?:run|ws|pol|ot|at|org|user|team|apply|plan|sv|cv|ing)-[A-Za-z0-9]{16}$/],
  ['tfc-trigger-id', /^trig_[A-Za-z0-9]{20,}$/],
  // Vercel project and team ids appear in every deployment URL.
  ['vercel-id', /^(?:prj|team)_[A-Za-z0-9]{16,}$/],
  // A Cloudflare Turnstile SITE key is the half meant to be in the page.
  ['turnstile-site-key', /^0x4AAAA[A-Za-z0-9_-]{12,}$/],
  // RDS and DocumentDB cluster resource ids, which name a Secrets Manager path.
  ['aws-cluster-resource-id', /^cluster-[A-Z0-9]{20,}$/],
  // A Jenkins plugin version: `1511.v2e3cb_0008e`.
  ['jenkins-version', /^[0-9]+(?:\.[0-9]+)*\.v[0-9a-f_]+$/],
  // A Tailscale key id -- the public half; the secret follows it in the string.
  ['tailscale-key-id', /^k[A-Za-z0-9]{10,12}CNTRL$/],
  ['git-ref', /^(?:refs\/|origin\/|heads\/)/],
  ['content-hash-uri', /^(?:sha256|sha512|md5|sha1)[-:]/i],
]

export type ScanOptions = {
  minLength: number
  entropyRatio: number
  hexMinLength: number
  strictHex: boolean
  /** How far from a cue word a candidate still counts as announced; 0 disables. */
  proximityWindow: number
  /** The entropy bar inside that window. */
  proximityRatio: number
  /**
   * The bar a path segment or identifier segment must clear before it stops
   * counting as benign. Deliberately NOT `entropyRatio`: lowering the detection
   * bar near a cue word must not also lower the bar that exempts structure, or
   * `.../handle-a-found-credential/SKILL` stops reading as a path.
   */
  exemptRatio: number
  /** The length floor for a candidate a cue word or an assignment announced. */
  announcedMinLength: number
  /**
   * Flag a bare AWS access key ID with no secret beside it. An AKIA is the
   * public half of the pair -- it appears in IAM listings, CloudTrail and every
   * audit note -- so by default it is flagged only when a 40-character
   * secret-shaped run sits within `pairWindow` characters of it.
   */
  flagAwsKeyIds: boolean
  /** How far from an access key ID its secret half may sit. */
  pairWindow: number
  /** The lowest ratio worth recording as a near miss; below this, nothing. */
  ledgerMinRatio: number
  /**
   * Run the shape-only rules -- `entropy`, `hex` and their `-cue` variants.
   * Off leaves the named patterns and the announced-assignment rule, which
   * judge a value by what the surrounding text CALLS it rather than by how the
   * run itself looks. Shape is the clause that carries the false positives, so
   * a surface where a person never types a secret can be scanned without it.
   */
  shapeRules: boolean
  maxScanChars: number
  allow: ReadonlySet<string>
}

export const DEFAULTS: ScanOptions = {
  // 24, not 20. Measured over 2293 wiki markdown files: a floor of 20 flags
  // 1586 runs, of which the overwhelming majority are 20-23 character
  // identifiers -- `HTTPCode_ELB_5XX_Count`, `AWS-RunPatchBaseline`,
  // `AWSLambda_FullAccess`. Raising it to 24 leaves 211 and costs no recall on
  // the labelled corpus, because every credential shorter than 24 that matters
  // is caught by a named pattern or by its announcement instead.
  minLength: 24,
  entropyRatio: 0.85,
  hexMinLength: 32,
  strictHex: false,
  proximityWindow: 60,
  proximityRatio: 0.7,
  exemptRatio: 0.85,
  announcedMinLength: 16,
  flagAwsKeyIds: false,
  pairWindow: 240,
  ledgerMinRatio: 0.6,
  shapeRules: true,
  maxScanChars: 2_000_000,
  allow: new Set<string>(),
}

export type Finding = {
  /** Offset of the flagged run in the scanned text. */
  start: number
  end: number
  /**
   * The flagged text itself. It stays inside the plugin's own environment --
   * the vault keys on it, `describe()` never prints it, and nothing that
   * reaches the transcript or the model reads this field.
   */
  value: string
  /** Which rule fired: `entropy`, `hex`, `assigned:<NAME>`, or a pattern name. */
  rule: string
  /** Shannon bits per character. */
  entropy: number
  /** entropy / log2(min(length, 64)); 0 for a rule that did not measure. */
  ratio: number
  /** 8 hex characters of FNV-1a over the value: stable, and not the value. */
  fingerprint: string
}

/** Shannon entropy of `s` in bits per character. */
export function entropyOf(s: string): number {
  if (s.length === 0) return 0
  const counts = new Map<string, number>()
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1)
  let h = 0
  for (const n of counts.values()) {
    const p = n / s.length
    h -= p * Math.log2(p)
  }
  return h
}

/**
 * The size of the alphabet the token was plausibly drawn from. Hex is 16, so
 * a hex key measured against a 64-symbol ceiling scores far below a base64 one
 * of the same randomness; this is what makes one threshold serve both.
 */
export function alphabetOf(s: string): number {
  if (/^[0-9a-f]+$/.test(s) || /^[0-9A-F]+$/.test(s)) return 16
  let n = 0
  if (/[a-z]/.test(s)) n += 26
  if (/[A-Z]/.test(s)) n += 26
  if (/[0-9]/.test(s)) n += 10
  n += new Set((s.match(/[+/=_-]/g) ?? [])).size
  return Math.max(n, 2)
}

/** Entropy as a fraction of the most a string of this length and alphabet could carry. */
export function entropyRatioOf(s: string): number {
  const ceiling = Math.log2(Math.min(s.length, alphabetOf(s)))
  return ceiling <= 0 ? 0 : entropyOf(s) / ceiling
}

/** FNV-1a, 32 bit, as 8 lowercase hex characters. */
export function fingerprint(s: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h.toString(16).padStart(8, '0')
}

function classesOf(s: string): number {
  let n = 0
  if (/[a-z]/.test(s)) n++
  if (/[A-Z]/.test(s)) n++
  if (/[0-9]/.test(s)) n++
  if (/[+/=_-]/.test(s)) n++
  return n
}

function vowelRatio(s: string): number {
  const v = s.match(/[aeiouAEIOU]/g)
  return v === null ? 0 : v.length / s.length
}

function isKnownPublic(t: string): boolean {
  return KNOWN_PUBLIC.some(([, re]) => re.test(t))
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

function b64Bytes(t: string): number[] | null {
  const s = t.replace(/=+$/, '')
  if (!/^[A-Za-z0-9+/]+$/.test(s)) return null
  const out: number[] = []
  let acc = 0
  let bits = 0
  for (const c of s) {
    const v = B64.indexOf(c)
    if (v < 0) return null
    acc = (acc << 6) | v
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out.push((acc >> bits) & 0xff)
    }
  }
  return out
}

/**
 * Base64 of ordinary text. Encoded prose has the entropy of random bytes at
 * the character level and none at all once decoded, which is the only honest
 * way to tell `VGhpcyBpcyBq...` from a 32-byte key.
 */
function decodesToProse(t: string, depth: number): boolean {
  if (t.length < 16 || t.length % 4 !== 0) return false
  const bytes = b64Bytes(t)
  if (bytes === null || bytes.length < 12) return false
  let printable = 0
  let letters = 0
  let vowels = 0
  for (const b of bytes) {
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) printable++
    if ((b >= 65 && b <= 90) || (b >= 97 && b <= 122)) {
      letters++
      if ('aeiouAEIOU'.includes(String.fromCharCode(b))) vowels++
    }
  }
  if (printable / bytes.length < 0.95) return false
  if (letters / bytes.length < 0.5) return false
  if (vowels / Math.max(letters, 1) < 0.25) return false
  // It decodes to text -- but base64 of a key is still a key, so the decoded
  // text goes through the detector once before the token is let past.
  const decoded = bytes.map((b) => String.fromCharCode(b)).join('')
  if (depth > 0) return true
  return scan(decoded, { maxScanChars: 8192 }, depth + 1).length === 0
}

/**
 * A `/`-bearing token that is a filesystem path, not a base64 blob: every
 * segment reads like a name (no segment is long enough and mixed enough to be
 * key material) and the whole thing carries a path's vowel load.
 */
function looksLikePath(t: string, o: ScanOptions): boolean {
  if (!t.includes('/')) return false
  if (/[+=]/.test(t)) return false
  const segs = t.split('/').filter((s) => s.length > 0)
  if (segs.length < 2) return false
  // A leading `-` or `.` is ordinary in a path: dotfiles, and Claude Code's own
  // encoded project directories (`-private-tmp`, `-Users-pleejr-...`).
  if (!segs.every((s) => /^[A-Za-z0-9._-]+$/.test(s) && /[A-Za-z0-9]/.test(s))) return false
  // A path is made of names: most of its segments are lowercase words. Key
  // material split by its own `/` characters is not.
  const lower = segs.filter((s) => /^[a-z0-9._-]+$/.test(s)).length
  if (lower / segs.length < 0.5) return false
  // ...and no single segment is itself key material. Judging the WHOLE token's
  // vowel load instead was wrong: one UUID or commit sha in a branch name drags
  // a real URL below any vowel floor, and the path reads as a secret.
  return segs.every((s) => segmentIsBenign(s, o))
}

/** 40- or 64-character lowercase hex: a git sha or a sha256 sum. */
function isShaLike(s: string): boolean {
  // Case-insensitive: a certificate serial and an OpenSSL digest print in
  // uppercase, and flagging those was most of what the hex rule still caught.
  return /^[0-9a-fA-F]+$/.test(s) && (s.length === 40 || s.length === 64)
}

/** A path segment that is a name, a known identifier, or too short to be a key. */
function segmentIsBenign(s: string, o: ScanOptions): boolean {
  if (s.length < 16) return true
  if (isKnownPublic(s)) return true
  if (!o.strictHex && isShaLike(s)) return true
  return entropyRatioOf(s) < o.exemptRatio
}

/**
 * Split a CamelCase or ALLCAPSCamel run into its words: `HTTPCode` -> HTTP,
 * Code; `ConfigureSTIG` -> Configure, STIG.
 */
function camelWords(s: string): string[] {
  return s
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(' ')
    .filter((w) => w.length > 0)
}

/**
 * A value that is spelled out of words: `GetSecretValue`, `required`,
 * `unused-example-prod-manages-no-vpn-policy`. The NAME beside it said
 * "secret", but a credential is not a sentence.
 */
function looksLikeWords(v: string): boolean {
  if (!/^[A-Za-z][A-Za-z-]*$/.test(v)) return false
  const parts = v.split('-').filter((x) => x.length > 0).flatMap(camelWords)
  return parts.length > 0 && parts.every(isWordy)
}

/** A word, an acronym, or a small number -- the parts identifiers are built from. */
function isWordy(s: string): boolean {
  if (/^[0-9]+$/.test(s)) return true
  // `wwx`, `rds`, `qa2`: a resource name is built from abbreviations as well as
  // words, and key material does not arrive in four-character hyphen-split runs.
  if (/^[a-z]{1,4}[0-9]{0,2}$/.test(s)) return true
  if (/^[A-Z][A-Z0-9]{1,5}$/.test(s)) return true
  return /^[A-Za-z]{2,}$/.test(s) && /[aeiouAEIOU]/.test(s)
}

/**
 * A structured identifier rather than key material: `HTTPCode_ELB_500_Count`,
 * `AWS-RunPatchBaseline`, `VPC/subnets/NAT/IGW/route`. Entropy cannot tell these
 * apart from a key -- at 20-30 characters a mixed-case identifier carries almost
 * as many bits per character as a random one -- but their VOCABULARY can: they
 * are made of words, acronyms and small numbers, and a key is not.
 */
function looksLikeIdentifier(t: string, o: ScanOptions): boolean {
  const parts = t
    .split(/[-_/.]/)
    .filter((s) => s.length > 0)
    .flatMap(camelWords)
  const wordy = parts.filter(isWordy).length
  if (parts.length < 2) return false
  if (parts.length < 3 ? wordy < parts.length : wordy / parts.length < 0.6) return false
  // ...and nothing inside it is itself key material, so `api-key-<blob>` is
  // still caught on the blob.
  return t
    .split(/[-_/.]/)
    .filter((s) => s.length > 0)
    // A long CamelCase word (`DBInstanceClassMemory`) clears the entropy bar on
    // its own, so judge a segment by its words before judging it by its bits.
    .every((s) => camelWords(s).every(isWordy) || segmentIsBenign(s, o))
}

/**
 * A hyphen- or underscore-joined name (`service-watchtower-processor-7d9f8c-xk2mq`,
 * a Kubernetes pod, a resource label): most of its segments are lowercase words.
 */
function looksLikeName(t: string): boolean {
  const segs = t.split(/[-_]/).filter((s) => s.length > 0)
  if (segs.length < 3) return false
  const words = segs.filter((s) => /^[a-z]{3,}$/.test(s) && /[aeiou]/.test(s)).length
  return words / segs.length >= 0.5
}

/** The entropy rule, applied to one candidate run. */
/** Why a candidate was let past, for the ledger. */
export type RejectReason =
  | 'known-public'
  | 'declared-public'
  | 'path'
  | 'identifier'
  | 'words'
  | 'name'
  | 'base64-prose'
  | 'hex-off'
  | 'hex-short'
  | 'hex-sha'
  | 'hex-ratio'
  | 'short'
  | 'classes'
  | 'vowels'
  | 'ratio'

type Verdict = { rule: string; entropy: number; ratio: number }
type Judgement = { ok: Verdict; reject?: undefined } | { ok?: undefined; reject: RejectReason; ratio: number }

/**
 * A candidate the detector saw and let past, recorded as SHAPE only. The value
 * never appears here and cannot be recovered from the fingerprint -- that is
 * the whole point: a ledger of maybe-secrets must not itself be a secret store.
 */
export type NearMiss = {
  fingerprint: string
  length: number
  alphabet: number
  entropy: number
  ratio: number
  classes: number
  vowelRatio: number
  /** Characters to the nearest cue word, or -1 when none was close. */
  cueDistance: number
  /** Which filter let it past. */
  reason: RejectReason
}

/**
 * Is a 40-character secret-shaped run sitting near this match? That is the AWS
 * secret access key's shape, and its presence is what turns a published key ID
 * into a leaked pair.
 */
function hasSecretNeighbour(body: string, start: number, length: number, o: ScanOptions): boolean {
  const from = Math.max(0, start - o.pairWindow)
  const to = Math.min(body.length, start + length + o.pairWindow)
  const around = body.slice(from, start) + ' ' + body.slice(start + length, to)
  for (const m of around.matchAll(/[A-Za-z0-9+/]{40}/g)) {
    if (entropyRatioOf(m[0]) >= o.entropyRatio) return true
  }
  return false
}

/**
 * A name written as CODE (`API_KEY`, `client_secret`, `apiKey`, `password`)
 * rather than as prose (`**Secrets:** ejson-managed`, `Credentials: rotated`).
 * The one-word exception below exists for `PASSWORD=hunter`, where a person
 * chose a weak value; a capitalized markdown label followed by a colon is a
 * sentence, and the word after it is what the sentence says, not a credential.
 */
function isCodeName(name: string): boolean {
  return /^[A-Z0-9_]+$/.test(name) || /_/.test(name) || /^[a-z][A-Za-z0-9]*$/.test(name)
}

/**
 * An assignment's right-hand side that is not a value at all. The NAME already
 * said "secret", so the entropy bar is down to 0.55 -- which is where every
 * identifier, YAML key and shell fragment on the line clears it. The entropy
 * path rejects these structurally BEFORE it measures a single bit; this is that
 * same rejection, applied where the name lowered the bar. Measured over a
 * 2301-file markdown vault and 8935 shell commands on 2026-09-18: the
 * assignment rule produced 15 of the vault's 27 findings and 27 of the shell's
 * 52, every one of them an identifier, a key name or a shell fragment.
 */
function assignedIsStructural(value: string, name: string, o: ScanOptions): boolean {
  // An elision is what a careful note writes INSTEAD of the credential, so
  // flagging `CREDENTIAL_ID=32b00056-\u2026` redacts a redaction.
  if (/\u2026|\.\.\.$/.test(value)) return true
  // A YAML key or a variable name, not its value: `secrets: TERRAFORM_TOKEN:
  // required: true` names the secret a workflow needs and carries none of it.
  if (value.endsWith(':')) return true
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(value)) return true
  // Shell and code punctuation a credential cannot carry: `TOKEN=$(python3 -c
  // ...)`, `re.compile(r`, `MasterUserSecret}`. What follows the `=` is an
  // expression that PRODUCES the secret; the secret itself is not on the line.
  if (/[(){}\[\]\\]/.test(value) || value.startsWith('$')) return true
  // A path is never a credential, whatever the name beside it says.
  if (looksLikePath(value, o)) return true
  // The VOCABULARY suppressors are gated on the name, for the same reason the
  // one-word exception above is: `TOKEN` and `CREDENTIAL_ID` name config
  // attributes constantly and their values are identifiers, while a value under
  // `PASSWORD` or `SECRET` is allowed to be spelled out of words -- a password a
  // person chose usually is, and it is still a password.
  if (/secret|password|passwd|private_?key/i.test(name)) return false
  return looksLikeIdentifier(value, o) || looksLikeName(value)
}

/** The entropy rule, applied to one candidate run. */
function judge(t: string, o: ScanOptions, depth: number): Judgement {
  const ratioOf = (): number => entropyRatioOf(t)
  if (isKnownPublic(t)) return { reject: 'known-public', ratio: ratioOf() }
  if (looksLikePath(t, o)) return { reject: 'path', ratio: ratioOf() }

  const isHex = /^[0-9a-fA-F]+$/.test(t)
  if (isHex) {
    if (o.hexMinLength <= 0) return { reject: 'hex-off', ratio: ratioOf() }
    if (t.length < o.hexMinLength) return { reject: 'hex-short', ratio: ratioOf() }
    // Every git SHA and sha256 sum is 40/64 lowercase hex at near-maximum
    // entropy. Flagging them is noise, so they pass unless strictHex.
    if (!o.strictHex && isShaLike(t)) return { reject: 'hex-sha', ratio: ratioOf() }
    const ratio = entropyRatioOf(t)
    return ratio >= o.entropyRatio ? { ok: { rule: 'hex', entropy: entropyOf(t), ratio } } : { reject: 'hex-ratio', ratio }
  }

  if (t.length < o.minLength) return { reject: 'short', ratio: ratioOf() }
  if (classesOf(t) < 3) return { reject: 'classes', ratio: ratioOf() }
  if (vowelRatio(t) > 0.35) return { reject: 'vowels', ratio: ratioOf() }
  if (looksLikeWords(t)) return { reject: 'words', ratio: ratioOf() }
  if (looksLikeIdentifier(t, o)) return { reject: 'identifier', ratio: ratioOf() }
  if (looksLikeName(t)) return { reject: 'name', ratio: ratioOf() }
  if (decodesToProse(t, depth)) return { reject: 'base64-prose', ratio: ratioOf() }
  const ratio = entropyRatioOf(t)
  if (ratio < o.entropyRatio) return { reject: 'ratio', ratio }
  return { ok: { rule: 'entropy', entropy: entropyOf(t), ratio } }
}

/** The start offset of every cue word in `text`, ascending. */
function cuePositions(text: string): number[] {
  CUE.lastIndex = 0
  return [...text.matchAll(CUE)].map((m) => m.index)
}

/** Characters from [start, end) to the nearest cue, or -1 beyond `bound`. */
function cueDistance(cues: readonly number[], start: number, end: number, bound: number): number {
  let best = -1
  for (const c of cues) {
    const d = c < start ? start - c : c > end ? c - end : 0
    if (d <= bound && (best === -1 || d < best)) best = d
    if (best === 0) break
  }
  return best
}

function push(out: Finding[], seen: Set<string>, f: Finding): void {
  const key = `${f.start}:${f.end}`
  if (seen.has(key)) return
  seen.add(key)
  out.push(f)
}

function overlaps(out: readonly Finding[], start: number, end: number): boolean {
  return out.some((f) => start < f.end && end > f.start)
}

/**
 * Every run of `text` this would keep out of the transcript, in source order,
 * non-overlapping, and every candidate it saw and let past.
 *
 * Named patterns win over the entropy rule on the same span.
 */
export function scanAll(
  text: string,
  opts: Partial<ScanOptions> = {},
  depth = 0,
): { findings: Finding[]; near: NearMiss[] } {
  const o: ScanOptions = { ...DEFAULTS, ...opts }
  const body = text.length > o.maxScanChars ? text.slice(0, o.maxScanChars) : text
  const out: Finding[] = []
  const near: NearMiss[] = []
  const seen = new Set<string>()

  for (const [rule, re] of PATTERNS) {
    re.lastIndex = 0
    for (const m of body.matchAll(re)) {
      const value = m[0]
      const start = m.index
      const fp = fingerprint(value)
      if (o.allow.has(fp)) continue
      // An access key ID on its own is an identifier, not a credential. It
      // becomes one when its secret half is beside it, so look for a
      // 40-character secret-shaped run in the surrounding text.
      if (rule === 'aws-access-key' && !o.flagAwsKeyIds && !hasSecretNeighbour(body, start, value.length, o)) continue
      push(out, seen, {
        start,
        end: start + value.length,
        value,
        rule,
        entropy: entropyOf(value),
        ratio: entropyRatioOf(value),
        fingerprint: fp,
      })
    }
  }

  ASSIGNED.lastIndex = 0
  for (const m of body.matchAll(ASSIGNED)) {
    const name = m[1] ?? ''
    const value = m[2] ?? ''
    if (value.length === 0) continue
    const start = m.index + m[0].length - value.length
    const end = start + value.length
    if (overlaps(out, start, end)) continue
    // The name already says "secret", so the bar is only "not a placeholder".
    if (/^(?:\$\{?[A-Za-z_]|<|\[|changeme$|placeholder$|xxx+$|\*+$|null$|true$|false$|none$)/i.test(value)) continue
    if (entropyRatioOf(value) < 0.55) continue
    // `secretsmanager:GetSecretValue` is a service namespace, not a variable
    // called SECRET: an all-lowercase name with no underscore only counts when
    // it IS the credential word, never when the word is buried in a longer one.
    if (/^[a-z]+$/.test(name) && !/^(?:secret|password|passwd|token|credential|apikey)s?$/.test(name)) continue
    // A published identifier, and a value spelled out of words, are not keys.
    if (isKnownPublic(value)) continue
    if (assignedIsStructural(value, name, o)) continue
    // `http_tokens = "required"` is config; `PASSWORD=correcthorse` is not.
    // A one-word value is let past only when the name is a weak signal --
    // "token" and "credential" name config attributes constantly, "secret"
    // and "password" do not.
    if (looksLikeWords(value)) {
      const multiWord = value.split('-').filter((x) => x.length > 0).flatMap(camelWords).length >= 2
      if (multiWord || !/secret|password|passwd|private_?key/i.test(name) || !isCodeName(name)) continue
    }
    const fp = fingerprint(value)
    if (o.allow.has(fp)) continue
    push(out, seen, {
      start,
      end,
      value,
      rule: `assigned:${name}`,
      entropy: entropyOf(value),
      ratio: entropyRatioOf(value),
      fingerprint: fp,
    })
  }

  // The shape-only rules end here. With them off, a value is a finding only
  // where a named pattern matched it or the text announced it, and nothing is
  // recorded as a near miss: a rule that did not run is not tunable.
  if (!o.shapeRules) {
    out.sort((a, b) => a.start - b.start)
    return { findings: out, near }
  }

  const cues = o.proximityWindow > 0 ? cuePositions(body) : []
  // Where the last candidate a declaration covered ended, so the declaration can
  // bind to a LIST rather than to its first element only. `--tasks <id> <id>`
  // declares both, and measuring it showed the second one flagged while the
  // first passed. -1 once anything but a separator intervenes.
  let declaredEnd = -1
  TOKEN.lastIndex = 0
  for (const m of body.matchAll(TOKEN)) {
    const value = m[0]
    const start = m.index
    const end = start + value.length
    if (overlaps(out, start, end)) continue
    const distance = cueDistance(cues, start, end, Math.max(o.proximityWindow, 200))

    // What sits immediately before the candidate can declare it public, the
    // way a cue word declares it secret. `fingerprint SHA256:<43 chars>` is an
    // ssh public key fingerprint and `serial = <40 hex>` a certificate serial;
    // both clear 0.85 and neither is a credential.
    const lead = body.slice(Math.max(0, start - PUBLIC_LEAD_WINDOW), start)
    const inherited = declaredEnd >= 0 && /^[\s,]+$/.test(body.slice(declaredEnd, start))
    declaredEnd = -1
    if (PUBLIC_LEAD.test(lead) || inherited) {
      declaredEnd = end
      if (depth === 0 && value.length >= o.minLength) {
        const ratio = entropyRatioOf(value)
        if (ratio >= o.ledgerMinRatio) {
          near.push({
            fingerprint: fingerprint(value),
            length: value.length,
            alphabet: alphabetOf(value),
            entropy: entropyOf(value),
            ratio,
            classes: classesOf(value),
            vowelRatio: vowelRatio(value),
            cueDistance: distance,
            reason: 'declared-public',
          })
        }
      }
      continue
    }

    let j = judge(value, o, depth)
    if (j.ok === undefined && distance >= 0 && distance <= o.proximityWindow) {
      // Announced as a credential: the same filters, a lower entropy bar.
      // The announcement lowers the entropy bar AND the length floor -- a
      // hand-chosen password is both short and repetitive. `exemptRatio` is
      // untouched, so structure stays exempt at the ordinary bar.
      const lowered = judge(
        value,
        { ...o, entropyRatio: o.proximityRatio, minLength: Math.min(o.minLength, o.announcedMinLength) },
        depth,
      )
      if (lowered.ok !== undefined) j = { ok: { ...lowered.ok, rule: `${lowered.ok.rule}-cue` } }
    }

    if (j.ok === undefined) {
      // Let past. Record its shape if it was close enough to be worth tuning on.
      if (depth === 0 && value.length >= o.minLength && j.ratio >= o.ledgerMinRatio) {
        near.push({
          fingerprint: fingerprint(value),
          length: value.length,
          alphabet: alphabetOf(value),
          entropy: entropyOf(value),
          ratio: j.ratio,
          classes: classesOf(value),
          vowelRatio: vowelRatio(value),
          cueDistance: distance,
          reason: j.reject,
        })
      }
      continue
    }

    const fp = fingerprint(value)
    if (o.allow.has(fp)) continue
    push(out, seen, {
      start,
      end,
      value,
      rule: j.ok.rule,
      entropy: j.ok.entropy,
      ratio: j.ok.ratio,
      fingerprint: fp,
    })
  }

  out.sort((a, b) => a.start - b.start)
  return { findings: out, near }
}

/** Every run of `text` this would keep out of the transcript. */
export function scan(text: string, opts: Partial<ScanOptions> = {}, depth = 0): Finding[] {
  return scanAll(text, opts, depth).findings
}

export function marker(f: Finding): string {
  return `[redacted ${f.rule} #${f.fingerprint}]`
}

/** `text` with every finding replaced by its marker. */
export function redactText(
  text: string,
  opts: Partial<ScanOptions> = {},
): { text: string; findings: Finding[]; near: NearMiss[] } {
  const { findings, near } = scanAll(text, opts)
  if (findings.length === 0) return { text, findings, near }
  let out = ''
  let at = 0
  for (const f of findings) {
    out += text.slice(at, f.start) + marker(f)
    at = f.end
  }
  out += text.slice(at)
  return { text: out, findings, near }
}

/**
 * The same over an arbitrary tool result: every string leaf, keys included,
 * with the shape kept so the engine's per-tool output schema still validates.
 */
export function redactValue(
  value: unknown,
  opts: Partial<ScanOptions> = {},
  depth = 0,
): { value: unknown; findings: Finding[]; near: NearMiss[] } {
  const findings: Finding[] = []
  const near: NearMiss[] = []
  const walk = (v: unknown, d: number): unknown => {
    if (d > 24) return v
    if (typeof v === 'string') {
      const r = redactText(v, opts)
      findings.push(...r.findings)
      near.push(...r.near)
      return r.text
    }
    if (Array.isArray(v)) return v.map((x) => walk(x, d + 1))
    if (v !== null && typeof v === 'object') {
      const out: Record<string, unknown> = {}
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) out[k] = walk(x, d + 1)
      return out
    }
    return v
  }
  const next = walk(value, depth)
  return { value: next, findings, near }
}

/** A one-line summary for a log line: rules and fingerprints, never values. */
export function describe(findings: readonly Finding[]): string {
  const byRule = new Map<string, string[]>()
  for (const f of findings) {
    const list = byRule.get(f.rule) ?? []
    list.push(f.fingerprint)
    byRule.set(f.rule, list)
  }
  return [...byRule.entries()].map(([rule, fps]) => `${rule} (${fps.join(', ')})`).join('; ')
}
