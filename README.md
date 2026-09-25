# credential-guard

A Claude Code plugin of function hooks that keeps credentials out of the session
transcript **while keeping them usable inside it**. It decides what a credential
is from several requirements together — a named provider pattern, length,
normalized Shannon entropy, what the surrounding text declares the value to be,
and whether it is spelled out of words — then redacts it behind a placeholder,
vaults the value, and offers the macOS login Keychain so later sessions can use
it too.

It was called `entropy-guard` while entropy was the whole decision. It is not:
entropy is one clause of the test, and the weakest one.

## The cycle

1. A tool's output (or a prompt, or a peer delivery) carries a secret.
2. The transcript gets `[redacted <rule> #<fingerprint>]`. The model never reads
   the value, and neither do the `user` and `last-prompt` records in the session
   log on disk. One record escapes it — see the `queue-operation` limit below.
3. The value goes to an in-memory session vault, and you are offered the
   Keychain for it.
4. The model writes the placeholder back into a tool call; the plugin
   substitutes the real value on the way down, so the command works.
5. A saved secret is listed to the model at the start of every later session as
   `[secret:NAME]`, so step 4 keeps working after this session ends.

So a redacted secret is **not destroyed** — it is moved out of the conversation
and referenced by placeholder. `aws configure set aws_secret_access_key
[secret:AWS_PROD]` runs with the real key; the transcript keeps the placeholder.

## What it watches

| Door | Event | Default | Shape rules |
|---|---|---|---|
| A tool's output (`cat .env`, `aws sts`, `curl`, `terraform output`) | `tool.call` return | redact | off |
| A tool call's own arguments | `tool.call` input | warn | off |
| What you typed or pasted | `prompt.submit` | redact | **on** |
| What a peer session, relay or webhook delivered | `session.receive` | redact | **on** |
| Which secrets the model may reference | `prompt.context` | listed by name | — |

`promptOnly` closes every door but the third — see below.

The last column is `shapeRules`, and it separates the two kinds of rule. A
**named pattern** (`ghp_`, `AKIA` beside its secret half, a PEM block, a JWT)
and an **assignment the text itself called a credential** (`API_KEY=…`) run on
every door: they read what the text says the value IS. The **shape-only** rules
— `entropy`, `hex`, and their `-cue` variants — judge a run by how it looks, and
that is where the false positives live: a build id, an opaque resource name, a
digest nobody declared. A person pastes a secret into a prompt; a tool argument
and a tool result are mostly machine text, so shape runs on the prompt doors by
default and `shapeRules` moves it (`prompt+result`, `all`, `off`).

A finding becomes `[redacted <rule> #<fingerprint>]`. The fingerprint is FNV-1a
of the value: the same secret reads the same everywhere, and the value itself is
never written down.

## Watching only what you type

`promptOnly` narrows the plugin to one surface — the prompts you submit — and
changes nothing about what it then does with what it finds:

| Door | Ordinarily | Under `promptOnly` |
|---|---|---|
| A tool's output | redact | **not scanned** |
| A tool call's arguments | warn | **not scanned** |
| What you typed or pasted | redact | redact (or `block`) |
| A peer or webhook delivery | redact | **not scanned** |
| A task notification, schedule or plugin prompt | redact, without shape rules | **not scanned** |

No entropy from a `terraform output`, a `curl` response or a peer delivery is
judged at all, so nothing outside your own typing can produce a finding, a
warning line, or a status count. It overrides `onToolResult` and `onToolInput`
outright, because a mode promising "nothing but my prompts" cannot be half-held
by an option set earlier.

"Typed" is read from the submission's `origin`, not its text: Enter at the
terminal, the Remote Control bridge, an SDK host's turn, or your Slack ping.
A task notification arrives through the same event carrying a `<tool-use-id>`
the shape rules would read as a key, so it is skipped here, as is the context
other hooks attach beside a prompt.

What happens to a finding is untouched. `onPrompt` still chooses redact or
block, `keychain` still offers each caught secret to the login Keychain — a
value you typed is exactly the one worth saving — and a placeholder still
substitutes back into a tool call. The near-miss ledger still records shapes,
of prompts only, which `/credential-guard` says at the foot of its report.

It is not the default. A prompt is where a person pastes a key, but a tool's
output is where `cat .env`, `aws sts` and `terraform output` put one, and this
mode gives up every catch there.

## The measure

Raw bits-per-character is length-biased. A 20-character random key cannot exceed
`log2(20) = 4.32` bits/char while a 200-character one approaches 6, so one raw
threshold either misses short keys or flags long prose. This normalizes:

```
ratio = H(token) / log2(min(length, alphabetSize(token)))
```

`alphabetSize` is inferred from the characters present — 16 for hex, 62–64 for
base64 — which is what lets one threshold serve both. Measured on the bundled
corpus: random key material sits at 0.87–0.99, filesystem paths and English at
0.65–0.81. The default cut is **0.85**.

**Entropy is the weakest of the requirements, not the strongest.** Measured over
a 2293-file markdown vault on 2026-09-18, a length floor of 20 flagged 1586 runs
and a floor of 24 flagged 211 — the same corpus, the same threshold, 87% of the
noise gone on length alone. Raising the entropy cut from 0.85 to 0.92 at a floor
of 20 removed only 36%. The reason is in the formula: at length 20 the
denominator is `log2(20) = 4.32`, so a mixed-case identifier with a digit clears
0.85 without being random at all. The normalizer is weakest exactly at the floor,
which is where every false positive lives.

So a flag needs a **conjunction**, and entropy is one clause of it:

1. **Named patterns** fire whatever the entropy: AWS access keys and session
   tokens, GitHub tokens and fine-grained PATs, Slack tokens and webhooks,
   Anthropic, OpenAI, Google, Stripe, npm and PyPI keys, JWTs, `Bearer` headers,
   URL credentials, and PEM private-key blocks. A second list of vendor formats
   — GitLab, SendGrid, Postman, HubSpot, Brevo, Shopify, DigitalOcean, Linear,
   Notion, Atlassian, Sentry, Vault, Terraform Cloud, Doppler, Slack app,
   Hugging Face, age — keeps an entropy floor of 0.5 on the match, so a
   documentation placeholder (`glpat-xxxxxxxxxxxxxxxxxxxx`) has the shape and
   still passes.
2. **Assignment context** lowers the bar: `*SECRET*`, `*PASSWORD*`, `*API_KEY*`,
   `*TOKEN*` and kin on the left of `=` or `:` flag a value at ratio 0.55, since
   a weak password is still a secret. The name has to *be* the credential word,
   though — `secretsmanager:GetSecretValue` is a service namespace, not a
   variable called SECRET — and a value spelled out of words (`required`,
   `GetSecretValue`) is config, not a key. **Lowering the entropy bar does not
   lower the structural ones**: the value still has to be a value. A YAML key
   (`secrets: TERRAFORM_TOKEN:`), a shell fragment (`TOKEN=$(jq …)`,
   `re.compile(r`, `MasterUserSecret}`), an elision (`CREDENTIAL_ID=32b00056…`),
   this plugin's own placeholder (`[secret:AWS_PROD]`) and a path are rejected
   before a single bit is measured; under a name that is only a weak signal —
   `TOKEN`, `CREDENTIAL_ID` — so is an identifier, while `PASSWORD` and
   `SECRET` keep the one-word exception a chosen password needs.
3. **Proximity to a cue word** does the same in prose. Within 60 characters of
   "api key", "token", "password", "credentials", "bearer" and kin, the bar
   drops to 0.70 **and the length floor drops to 16** — a person who writes
   *here's my api key …* has already said what the next token is, and a key
   picked by hand is often both short and too repetitive to clear the ordinary
   threshold. The structural filters still apply, so the cue alone flags
   nothing: `the total_tokens field says 14998361 tokens left` and `rotate the
   api key in terraform-aws-module-config` both pass clean. The cue lowers the
   *detection* bar only; `exemptRatio` holds the *exemption* bar steady, so a
   path like `…/skills/handle-a-found-credential/SKILL.md` does not stop being
   a path merely because it contains the word "credential".
4. **A public declaration to the left** puts a value out of reach, the way a cue
   word to the left brings one into it. `fingerprint SHA256:<43 characters>` is
   an ssh public key fingerprint, `serial = <40 hex>` a certificate serial,
   `AUTH0_CLIENT_ID = <32 characters>` an OAuth client id — all three clear 0.85
   and none is a credential. The declaring word is never part of the candidate,
   because the token regex stops at `:` and at whitespace, so it can only be
   seen by looking behind: 48 characters, no further, and a URL's query string
   is excluded on purpose, since `?token=<value>` is the leak this exists to
   catch. A declaration binds to the LIST it introduces, not to its first
   element only: `--tasks <id> <id>` declares both, and a run of separators is
   what holds the list together.
5. **An AWS access key ID is an identifier until its secret is beside it.** An
   `AKIA` appears in every IAM listing, CloudTrail event and audit note; the
   40-character secret access key is the credential. So a lone key ID is let
   past, and the pair is flagged when a secret-shaped run sits within
   `pairWindow` characters. Set `flagAwsKeyIds` to catch a lone one.
6. **Shape suppressors** drop what looks random and is not: UUIDs, AWS resource
   ids (`ami-`, `i-`, `subnet-`, `sgr-`…), Terraform Cloud ids (`run-`, `ws-`,
   `trig_`…), git refs, `sha512-` content hashes, filesystem paths and URLs
   (most segments are lowercase names, a segment may begin with `.` or `-`, and
   no single segment is itself key material — a UUID branch or a commit sha
   inside one does not make the path a secret), and hyphenated names
   (`service-watchtower-processor-7d9f8c6b54-xk2mq`).
7. **Vocabulary** separates an identifier from a key. `HTTPCode_ELB_5XX_Count`,
   `AWS-RunPatchBaseline`, `AWSLambda_FullAccess` and `VPC/subnets/NAT/IGW/route`
   all clear 0.85, and all split on `-_/.` and CamelCase into words, acronyms
   and small numbers. Key material does not. This is the clause entropy cannot
   supply: at 20–30 characters a structured identifier and a random key carry
   almost the same bits per character, but they are drawn from different
   vocabularies.
8. **Base64 is decoded before judging.** Encoded prose carries full entropy per
   character and none once decoded, which is the only honest way to tell
   `VGhpcyBpcyBq…` from a 32-byte key. The decoded text goes through the detector
   once, so base64 **of** a secret is still caught. Only text with spaces counts
   as prose: base64 of JSON or of `k=v` config is data, judged on its own
   entropy, because its inner values are usually the secret.
9. **A direct announcement is read with its punctuation.** `the password is
   Summer2026!` and `api key: <value>` capture the value up to whitespace — the
   token regex would split `Summer2026!` at the `!` — and judge it by entropy:
   0.55 and 6 characters for a value a person chose (password, passphrase),
   the cue bar (0.70, 16 characters) for a key or token. A UUID or a 40-hex run
   announced this way is a key; unannounced, it stays an id and a git sha.
   Prose about a password (`the password is required`, `stored in 1Password`,
   `password: rds_password`) is rejected before a bit is measured.
10. **A prefix can announce its own body.** `acme_api_<body>`, `sk_<body>`:
    the body alone is judged at the cue bar, since a lowercase-and-digit key has
    two character classes and fails the three-class rule a whole run is held to.
    `shpat_<32 hex>`, `key-<32 hex>`, `dop_v1_<64 hex>` are judged on the hex
    body against 16 symbols; measured whole, the prefix mixes the alphabet and
    drags the ratio to ~0.77. A hash prefix (`sha256-`, `g`, `commit-`) keeps
    the digest exemption.
11. **A cue outranks a weak public word.** `account`, `tenant`, `client`,
    `address`, `wallet`, `issuer`, `subject` and `task` name a container as
    often as an id: `the api key for the new account: <key>` is a key. The
    exception is an id-shaped run — pure hex or a UUID — which stays declared
    public, because `token against account <32 hex>` is a Cloudflare account id.
    Strong declarations (`fingerprint`, `SHA256:`, `commit`, `serial`, `key id`)
    are never outranked.

Git SHAs and sha256 sums (40 and 64 lowercase hex) pass by default — flagging
every commit id would make the plugin unusable. Set `strictHex` to catch them.

## Measured

`node --experimental-strip-types bench/corpus.ts` — 36 labelled secrets, 82
labelled clean samples drawn from ordinary infrastructure session traffic (git
log, terraform plan, ARNs, k8s names, npm integrity, AWS CLI JSON, paths, URLs,
and prose that merely mentions keys and tokens).

```
secrets caught     36/36
clean passed       82/82
```

CI runs it, with `claude plugin test`, on every pull request.

**Measured 2026-09-25, rules 9–11 and the vendor list.** 31 credential formats
built to each vendor's published shape, 100 random samples each, in five
phrasings (bare; after "here is the api key for the new account:"; after "the
password is"; on the line after unrelated prose; as `API_KEY=`). Before, 0.4.2
caught 0 of 100 in the second phrasing for most formats, and 0 in every
phrasing for `dop_v1_` keys, UUID keys and passphrases. After, every vendor
format of 24 characters or more is caught at 92–100 bare, except a 40-hex key.
A 32-hex key after "…account:" stays missed on purpose (rule 11). Still missed without a label: a bare 40-hex key
(indistinguishable from a git sha), a bare UUID key, a 20-character key, any
password, and a passphrase outside a `passphrase` cue. False positives over 5489
markdown files of a vault and the 1603 prompts typed into this machine's past
sessions: 46 and 11 before, 46 and 11 after.


That is the corpus in `bench/corpus.ts`, not a claim about the field. Add your
own false positives and false negatives there; it exits non-zero on any miss.

Measured against the same vault — 2293 files when the first three columns
were taken, 2301 when the fourth was, on 2026-09-18:

| | floor 20, entropy only | conjunction | + public declarations | + structural assignment |
|---|---|---|---|---|
| all findings | 1750 | 180 | 27 | 11 |
| `entropy` + `hex` | 1586 | 118 | 12 | 6 |
| `assigned:*` | — | — | 15 | 0 |
| labelled recall | 26/26 | 26/26 | 26/26 | 26/26 |

**The assignment rule was the noise, and entropy was not.** Measured 2026-09-18
over 8970 `Bash` commands from 386 session transcripts, alongside the vault
column above: `assigned:*` produced 27 of the 52 findings that were neither a
test fixture nor a redaction marker, every one of them a key name, a shell
fragment or an identifier — `TOKEN=$(python3`, `MasterUserSecret}`,
`secrets: TERRAFORM_TOKEN:`. Running the structural filters on that path took it
to 3, and binding a public declaration to its list took `hex` from 10 to 4.
Removing the entropy family instead, as the shape of the noise first suggested,
costs 11 of the 26 labelled secrets — the AWS secret access key, both hex keys,
every base64 key and everything announced in prose — and would have left the
class that was actually firing untouched.

**A clean corpus is not a clean field, and this one proved it.** The corpus
scored 49/49 while the same detector produced 1750 findings over 2293 markdown
files of a real vault — the labelled negatives were too few and too easy to
detect the identifier class at all. The fix ran against both: 1750 → 180 on the
vault, 1586 → 118 for the entropy and hex rules specifically, with recall held at
26/26. The fourteen measured false positives were then folded back into `CLEAN`,
which is what raised it to 63. Run the detector over a corpus you did not write
before believing a threshold.

## The Keychain

On the first sighting of a value, the plugin asks — outside the turn, so it
never blocks a tool — whether to keep it:

```
credential-guard caught a github-token (#ef5029cc) and kept it out of the
transcript. Save it to your macOS login Keychain so later sessions can use it?
  [ Save to Keychain ]  [ Not this one ]  [ Stop asking this session ]
```

Say yes and it asks for a name, then writes one generic-password item:

| field | value |
|---|---|
| service (`-s`) | `claude-code-credential-guard` |
| account (`-a`) | the fingerprint, e.g. `ef5029cc` |
| label (`-l`) | `credential-guard: AWS_PROD` |
| password | the secret, fed on **stdin**, never as an argument |

Feeding it on stdin matters: `security add-generic-password -w <value>` would
put the secret in the process table where any `ps` could read it.

`$.store` keeps the index — fingerprint, name, rule, date — as plain JSON.
**Values live only in the Keychain.** Inspect or revoke with:

```
security find-generic-password -s claude-code-credential-guard -a <fingerprint> -w
security delete-generic-password -s claude-code-credential-guard -a <fingerprint>
```

Deleting the item is enough. The index row naming it is dropped the next time a
placeholder for it fails to resolve, so the two stores cannot drift into a state
where a secret is offered by a name nothing can produce. That covers the item
removed by hand, as above, and the rows stranded when the plugin's store changes
— its key is `<name>@<source>`, so installing from a different source starts an
empty store while the Keychain, keyed by service and fingerprint, keeps every
value.

Set `keychain` to `auto` to save without being asked, or `off` to never ask.

**When the Keychain refuses.** A session outside the login window's security
session — over SSH, or under a multiplexer started from one — cannot unlock the
login Keychain, and `security` answers `User interaction is not allowed`
(-25308) to every write. The plugin then says so once, as a toast, keeps the
secret queued in memory, and tries again each time you submit a prompt, so an
unlock on the Mac itself, or `security unlock-keychain` in the same session, is
enough for it to land. The placeholder keeps working in the meantime. A secret
still queued when the session ends is gone: there is nowhere safer to put it.

## The near-miss ledger

The 0.85 cut was chosen against a corpus I wrote. The ledger says what *your*
traffic looks like just below it, so the next cut comes from a distribution
rather than a guess.

Every candidate the detector sees and lets past is recorded as **shape only** —
fingerprint, length, alphabet size, entropy, normalized ratio, character
classes, vowel ratio, distance to the nearest cue word, which filter let it
past, the tools it came through, and first/last dates. **No value is ever
recorded**, and a fingerprint does not read back into one. A ledger of
maybe-secrets that stored the maybe-secrets would be the leak this plugin
exists to prevent.

The ledger is fed by the doors the shape rules run on, since it exists to tune
their cut: under the default `shapeRules` it is a record of prompts, and it
takes in tool traffic again the moment that option says `prompt+result` or
`all`.

Repeats collapse onto one row with a count, so a git SHA seen five hundred times
is one row. Rows are pruned to `ledgerMaxRows`, dropping what a threshold would
learn least from — seen once, and oldest. The whole plugin store is capped at
4 MiB by the engine.

Read it with the slash command the plugin registers:

```
/credential-guard
```

```
credential-guard — calibration

9 distinct shapes, 27 sightings, current cut 0.85.
Every row is something the detector SAW and LET PAST. Values are not kept.

Normalized entropy of what was let past:
  0.65–0.70      2  ###################
  0.70–0.75      1  #########
  0.75–0.80      1  #########
  0.85–0.90      3  ############################
  0.90–0.95      1  #########
  0.95–1.00      1  #########

Which filter let it past:
  hex-sha            2
  known-public       2
  path               1
  ...

What a lower cut would newly flag (shapes rejected on ratio alone):
  0.80      0 shapes       0 sightings
  0.75      1 shapes       3 sightings  <- the cost of dropping to 0.75
```

Rows sitting *above* the cut are the interesting ones: they were let past by an
exemption rather than by entropy, so they measure what `hex-sha`,
`known-public` and the base64 decoder are carrying for you.

**What it cannot tell you.** Nothing in the ledger is labelled, so it measures
what a lower cut would *cost*, never what one would *catch*. Labelling needs the
real string, which only exists in memory during the session that saw it.

## Install and run

From the `pleejr` marketplace, which carries this plugin by reference — the
code stays in this repo:

```
/plugin marketplace add pleejr/skills
/plugin install credential-guard@pleejr
```

This repo no longer publishes a marketplace of its own. It did, under the name
`pleejr`, which is the name `pleejr/skills` already uses, so a machine adding
both had one name for two sources.

Or from a checkout, permanently as `credential-guard@skills-dir`:

```
ln -sfn "$PWD" ~/.claude/skills/credential-guard   # run from the checkout
claude plugin list          # credential-guard@skills-dir — Status: loaded
```

Or load it for one session only:

```
claude --plugin-dir "$PWD"
```

Options live in `/plugin manage` (or settings `pluginConfigs`). Saving a file in
the folder reloads the module in place.

```
claude plugin validate .    # manifest + what the module hooks and calls
claude plugin test .        # unit tests and the hooks through the real engine
```

The type declarations are generated, not committed. In a session inside this
folder run `/plugin-types .claude/types` once, then:

```
npm install                 # typescript only; nothing here ships
npm run typecheck           # tsc -p .
```

The typechecker earns its place: `$.env.get` and `$.env.set` are async, and a
forgotten `await` on one of them reads as a plain string everywhere the engine
strips types. `npm run typecheck` is what catches it.

## Options

| Option | Default | Meaning |
|---|---|---|
| `promptOnly` | false | Judge your submitted prompts and nothing else; overrides the two tool doors |
| `shapeRules` | prompt | Where `entropy`/`hex` run: `prompt`, `prompt+result`, `all`, `off` |
| `minLength` | 24 | Shortest run the entropy rule considers |
| `entropyRatio` | 0.85 | Normalized entropy needed to flag |
| `exemptRatio` | 0.85 | The bar a path or identifier segment must clear to stop counting as benign |
| `hexMinLength` | 32 | Shortest pure-hex run; 0 disables the hex rule |
| `strictHex` | false | Also flag 40/64-char lowercase hex (git SHAs, sha256) |
| `onToolResult` | redact | `redact` or `off` |
| `onToolInput` | warn | `warn`, `deny` or `off` |
| `onPrompt` | redact | `redact`, `block` or `off` |
| `maxScanChars` | 2000000 | Characters scanned per value |
| `allow` | "" | Comma-separated fingerprints to stop flagging |
| `proximityWindow` | 60 | Characters from a cue word that still count as announced; 0 disables |
| `proximityRatio` | 0.70 | The entropy bar inside that window |
| `announcedMinLength` | 16 | The length floor inside that window, or beside an assignment |
| `flagAwsKeyIds` | false | Flag a lone `AKIA` with no secret beside it |
| `pairWindow` | 240 | How far from an access key ID its secret half may sit |
| `ledger` | true | Record the shape of every candidate let past |
| `ledgerMinRatio` | 0.60 | Below this ratio a candidate is not worth recording |
| `ledgerMaxRows` | 5000 | Rows kept before pruning |
| `keychain` | ask | `ask`, `auto` or `off` |
| `rehydrate` | true | Substitute a placeholder back into a tool call |
| `rehydrateEgress` | false | Also substitute for MCP tools, `WebFetch`, `WebSearch` |

Take a fingerprint out of a redaction marker and put it in `allow` to stop
flagging that one value.

## The command-hook fallback

The plugin's `prompt.submit` hook runs only when the engine seats plugin hooks
modules, and that is governed by the `tengu_plugin_hooks_modules` rollout flag.
When the flag resolves off — a cold GrowthBook cache does it on its own, with no
error — the engine logs

```
hooks module credential-guard@skills-dir not loaded: the rollout flag (tengu_plugin_hooks_modules) is off
Registered 0 hooks from 9 plugins
```

and every prompt reaches the model unscanned. `claude plugin list` still reports
the plugin `✔ loaded`, because it is: the module is read and enabled, only the
hooks are never seated. A guard that never ran reads exactly like a guard that
passed.

**Taking seating off the rollout.** `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS` overrides
the flag outright — the engine resolves seating as
`env.CLAUDE_CODE_ENABLE_FUNCTION_HOOKS ?? growthbook('tengu_plugin_hooks_modules')`
— so an `env` block in `settings.json` makes it deterministic:

```json
{ "env": { "CLAUDE_CODE_ENABLE_FUNCTION_HOOKS": "1" } }
```

Measured on Claude Code 2.1.277, 2026-09-18: with it set, a prompt carrying
`AKIAZZCANARYTEST7788` reached the model as `[redacted aws-access-key #27764921]`,
the `user` and `last-prompt` transcript records held the marker rather than the
key, and the command-hook fallback stood down as designed.

`hooks/fallback/prompt-guard.sh` covers that window. It is seated by
`settings.json`, where no rollout flag governs it:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "$HOME/.claude/skills/credential-guard/hooks/fallback/prompt-guard.sh",
            "timeout": 10,
            "statusMessage": "entropy guard"
          }
        ]
      }
    ]
  }
}
```

It **blocks** where the plugin would have redacted. A `UserPromptSubmit` command
hook is given `additionalContext` and no way to return an edited prompt, so the
whole prompt is held back on exit 2 and the reason is shown to the person.

**It stands down whenever `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS` says the module is
seated**, which is the only stand-down that does not depend on hook ordering. A
variable set to anything but `0`, `false`, `off`, `no` or empty means the module
owns the prompt and redacts it; unset means the rollout flag decides, which is
the window this path covers, so it runs. Set it to `1` and wire both without
them fighting.

The older stand-down — the text already carrying a redaction marker or a
`[secret:NAME]` reference — is still checked, but it is **not** load-bearing and
should not be relied on. It only works if this hook is handed the text the
module rewrote, and that is unresolved: the fallback was observed standing down
on 2026-09-18, and on 2026-09-21 it blocked a prompt the module had
demonstrably redacted, exiting 2 on 4 of 5 realistic task notifications.

A prompt the harness wrote — a `<task-notification>`, a `<system-reminder>` — is
passed rather than blocked. No person typed it and no person can edit it, so
exit 2 costs the delivery and offers nothing back. The check is anchored at the
start of the prompt on purpose: every name added there is a name someone could
paste above their own text to skip the guard.

Failure is open and loud: no `node` on `PATH`, an unparseable payload or a
throwing detector exits 0 with a notice on stdout, which the engine hands the
model as context. Silence would reproduce the bug the fallback exists for.

## Limits, stated plainly

- **A password needs a label.** `Summer2026!` on its own line is
  indistinguishable from any other word with a digit; `password: Summer2026!` or
  `the password is Summer2026!` is caught. The same holds for a bare UUID key, a
  bare 40-hex key and a key shorter than 24 characters.

- **A queued prompt is logged before any hook runs.** Headless `claude -p`, and
  anything else that enqueues a prompt, writes a
  `{"type":"queue-operation","operation":"enqueue","content":…}` record to
  `~/.claude/projects/<project>/<session>.jsonl` holding the prompt verbatim.
  Neither `prompt.submit` redaction nor a block from the command-hook fallback
  reaches it, because the record predates both. Interactive sessions do not
  write it — zero such records across 14 prompts in a session measured
  2026-09-18 — so this is a headless-only gap, and a secret typed into `-p`
  should be treated as written to disk.
- **It fails open.** A hook that throws or overruns its 10 s budget is skipped
  and the content passes through unredacted. Each hook has a `.catch` that says
  so in the transcript, so silence means the guard ran — but a crash is a gap,
  not a block.
- **A tool call's arguments cannot be redacted**, only refused: rewriting a
  command would break it. Hence `warn` by default, `deny` if you want the block.
- **Substitution puts the real value into the executed command.** That is the
  point, but it means a rehydrated secret reaches the tool, its child processes
  and anything they write. `rehydrateEgress` is off by default so a placeholder
  is never expanded into an MCP call, `WebFetch` or `WebSearch`; every
  substitution writes a line in the transcript naming the tool and the count.
- **The Keychain write path was first exercised live on 2026-09-25, over SSH,**
  and refused with -25308, as above. A write from a session at the Mac itself
  has still not been observed end to end; `tests/vault.test.ts` and
  `tests/keychain-refused.test.ts` cover the wiring against a faked
  `process.run`.
- **Reading a saved value may raise a macOS authorization prompt** the first
  time another binary asks for the item.
- **It does not read the model's own output.** A secret the model composes
  itself is out of scope; `turn.step` is where that would go.
- **It cannot see what it is not shown.** MCP servers that write to their own
  logs, and anything outside these four events, are untouched.
- A long base64 blob that is genuinely data (an image piped through `base64`)
  is high entropy and will be redacted.
- `onToolResult` drops core's `ref` when it redacts, so the engine re-records
  the call from the redacted result. That is what makes the redaction stick.
- This reduces exposure; it is not a control you should rely on for a secret
  that must never leave a machine.
