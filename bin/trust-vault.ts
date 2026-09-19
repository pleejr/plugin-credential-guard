/**
 * Builds the trust list from a corpus that has already passed a write-time
 * sensitivity gate -- a wiki vault, a runbook repository, any tracked tree
 * whose rule is "no secrets in here".
 *
 * It reads the corpus's TRACKED files (`git ls-files`), not a directory walk:
 * what the gate saw is what may vouch for anything. Untracked scratch, other
 * checkouts of the same repository and ignored build output are exactly the
 * text no gate ever read.
 *
 * Run:
 *   node --experimental-strip-types bin/trust-vault.ts --root "$WIKI_PATH"
 *   node --experimental-strip-types bin/trust-vault.ts --root . --dry-run
 *
 * Exits 1 when the corpus holds a finding it may NOT vouch for -- a named
 * provider pattern or an assignment the text itself called a credential. That
 * is not noise to suppress; it is a credential sitting in a tree whose rule
 * says it holds none, and the corpus is what has to change.
 */
import { execFileSync } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { harvest } from '../hooks/trust.ts'

const DEFAULT_OUT = join(homedir(), '.claude', 'credential-guard', 'trust.json')

const args = process.argv.slice(2)
let root = process.env.WIKI_PATH ?? ''
let out = DEFAULT_OUT
let dryRun = false
let exts = ['.md']
const exclude: string[] = []

for (let i = 0; i < args.length; i++) {
  const a = args[i]
  if (a === '--root') root = args[++i] ?? ''
  else if (a === '--out') out = args[++i] ?? DEFAULT_OUT
  else if (a === '--ext') exts = (args[++i] ?? '.md').split(',').map((s) => (s.startsWith('.') ? s : `.${s}`))
  else if (a === '--exclude') exclude.push(args[++i] ?? '')
  else if (a === '--dry-run') dryRun = true
  else if (a === '-h' || a === '--help') {
    console.log('trust-vault.ts --root DIR [--out FILE] [--ext .md,.txt] [--exclude SUBSTRING] [--dry-run]')
    process.exit(0)
  } else {
    console.error(`trust-vault: unknown argument ${a}`)
    process.exit(2)
  }
}

if (root === '') {
  console.error('trust-vault: set --root DIR or $WIKI_PATH -- the corpus whose gate is being trusted')
  process.exit(2)
}

let tracked: string[]
try {
  tracked = execFileSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8', maxBuffer: 64 << 20 })
    .split('\0')
    .filter((p) => p.length > 0)
} catch {
  console.error(`trust-vault: ${root} is not a git checkout -- only a tracked tree has a write-time gate to trust`)
  process.exit(2)
}

const files = tracked
  .filter((p) => exts.some((e) => p.endsWith(e)))
  .filter((p) => !exclude.some((x) => x.length > 0 && p.includes(x)))
  .map((p) => {
    try {
      return { path: p, text: readFileSync(join(root, p), 'utf8') }
    } catch {
      return null
    }
  })
  .filter((f): f is { path: string; text: string } => f !== null)

const trust = harvest(files, {}, new Date(), root)

console.log(`trust-vault: ${trust.files} tracked file(s) under ${root}`)
console.log(`trust-vault: ${trust.entries.length} fingerprint(s) vouched for, ${trust.refused.length} refused`)
for (const r of trust.refused) {
  console.log(`  REFUSED  ${r.rule.padEnd(20)} #${r.fingerprint}  ${r.seenIn}`)
}

if (dryRun) {
  console.log('trust-vault: --dry-run, nothing written')
} else {
  mkdirSync(dirname(out), { recursive: true })
  writeFileSync(out, `${JSON.stringify(trust, null, 2)}\n`)
  console.log(`trust-vault: wrote ${out}`)
  console.log('trust-vault: point the plugin at it with the `trustFile` option')
}

// A refusal is the corpus's problem, not the detector's: something that reads
// as a credential is sitting in a tree whose rule says it holds none.
process.exit(trust.refused.length > 0 ? 1 : 0)
