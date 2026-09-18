# entropy-guard

A Claude Code plugin of function hooks that keeps high-entropy values out of the
session transcript **while keeping them usable inside it**. It measures Shannon
entropy, redacts what it finds, vaults the value, and offers to keep it in the
macOS login Keychain so later sessions can use it too.

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

| Door | Event | Default |
|---|---|---|
| A tool's output (`cat .env`, `aws sts`, `curl`, `terraform output`) | `tool.call` return | redact |
| A tool call's own arguments | `tool.call` input | warn |
| What you typed or pasted | `prompt.submit` | redact |
| What a peer session, relay or webhook delivered | `session.receive` | redact |
| Which secrets the model may reference | `prompt.context` | listed by name |

A finding becomes `[redacted <rule> #<fingerprint>]`. The fingerprint is FNV-1a
of the value: the same secret reads the same everywhere, and the value itself is
never written down.

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
   URL credentials, and PEM private-key blocks.
2. **Assignment context** lowers the bar: `*SECRET*`, `*PASSWORD*`, `*API_KEY*`,
   `*TOKEN*` and kin on the left of `=` or `:` flag a value at ratio 0.55, since
   a weak password is still a secret. The name has to *be* the credential word,
   though — `secretsmanager:GetSecretValue` is a service namespace, not a
   variable called SECRET — and a value spelled out of words (`required`,
   `GetSecretValue`) is config, not a key.
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
4. **Shape suppressors** drop what looks random and is not: UUIDs, AWS resource
   ids (`ami-`, `i-`, `subnet-`, `sgr-`…), Terraform Cloud ids (`run-`, `ws-`,
   `trig_`…), git refs, `sha512-` content hashes, filesystem paths and URLs
   (most segments are lowercase names, a segment may begin with `.` or `-`, and
   no single segment is itself key material — a UUID branch or a commit sha
   inside one does not make the path a secret), and hyphenated names
   (`service-watchtower-processor-7d9f8c6b54-xk2mq`).
5. **Vocabulary** separates an identifier from a key. `HTTPCode_ELB_5XX_Count`,
   `AWS-RunPatchBaseline`, `AWSLambda_FullAccess` and `VPC/subnets/NAT/IGW/route`
   all clear 0.85, and all split on `-_/.` and CamelCase into words, acronyms
   and small numbers. Key material does not. This is the clause entropy cannot
   supply: at 20–30 characters a structured identifier and a random key carry
   almost the same bits per character, but they are drawn from different
   vocabularies.
6. **Base64 is decoded before judging.** Encoded prose carries full entropy per
   character and none once decoded, which is the only honest way to tell
   `VGhpcyBpcyBq…` from a 32-byte key. The decoded text goes through the detector
   once, so base64 **of** a secret is still caught.

Git SHAs and sha256 sums (40 and 64 lowercase hex) pass by default — flagging
every commit id would make the plugin unusable. Set `strictHex` to catch them.

## Measured

`node --experimental-strip-types bench/corpus.ts` — 26 labelled secrets, 63
labelled clean samples drawn from ordinary infrastructure session traffic (git
log, terraform plan, ARNs, k8s names, npm integrity, AWS CLI JSON, paths, URLs,
and prose that merely mentions keys and tokens).

```
secrets caught     26/26
clean passed       63/63
```

That is the corpus in `bench/corpus.ts`, not a claim about the field. Add your
own false positives and false negatives there; it exits non-zero on any miss.

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
entropy-guard caught a github-token (#ef5029cc) and kept it out of the
transcript. Save it to your macOS login Keychain so later sessions can use it?
  [ Save to Keychain ]  [ Not this one ]  [ Stop asking this session ]
```

Say yes and it asks for a name, then writes one generic-password item:

| field | value |
|---|---|
| service (`-s`) | `claude-code-entropy-guard` |
| account (`-a`) | the fingerprint, e.g. `ef5029cc` |
| label (`-l`) | `entropy-guard: AWS_PROD` |
| password | the secret, fed on **stdin**, never as an argument |

Feeding it on stdin matters: `security add-generic-password -w <value>` would
put the secret in the process table where any `ps` could read it.

`$.store` keeps the index — fingerprint, name, rule, date — as plain JSON.
**Values live only in the Keychain.** Inspect or revoke with:

```
security find-generic-password -s claude-code-entropy-guard -a <fingerprint> -w
security delete-generic-password -s claude-code-entropy-guard -a <fingerprint>
```

Set `keychain` to `auto` to save without being asked, or `off` to never ask.

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

Repeats collapse onto one row with a count, so a git SHA seen five hundred times
is one row. Rows are pruned to `ledgerMaxRows`, dropping what a threshold would
learn least from — seen once, and oldest. The whole plugin store is capped at
4 MiB by the engine.

Read it with the slash command the plugin registers:

```
/entropy-guard
```

```
entropy-guard — calibration

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

From the marketplace this repo publishes:

```
/plugin marketplace add pleejr/plugin-entropy-guard
/plugin install entropy-guard@pleejr
```

Or from a checkout, permanently as `entropy-guard@skills-dir`:

```
ln -sfn "$PWD" ~/.claude/skills/entropy-guard   # run from the checkout
claude plugin list          # entropy-guard@skills-dir — Status: loaded
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
folder run `/plugin-types .claude/types` once, then `tsc -p .` typechecks.

## Options

| Option | Default | Meaning |
|---|---|---|
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
hooks module entropy-guard@skills-dir not loaded: the rollout flag (tengu_plugin_hooks_modules) is off
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
            "command": "$HOME/.claude/skills/entropy-guard/hooks/fallback/prompt-guard.sh",
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
whole prompt is held back on exit 2 and the reason is shown to the person. It
stands down when the text already carries a redaction marker or a
`[secret:NAME]` reference, so with the flag on the plugin's own hook still owns
the prompt.

Failure is open and loud: no `node` on `PATH`, an unparseable payload or a
throwing detector exits 0 with a notice on stdout, which the engine hands the
model as context. Silence would reproduce the bug the fallback exists for.

## Limits, stated plainly

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
- **The Keychain write path has not been exercised end to end in a live
  session** — it needs the interactive dialog. The `security` argv form was
  probed directly (write, read back, delete, exit 0) and the plugin's wiring is
  covered by `tests/vault.test.ts` against a faked `process.run`.
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
