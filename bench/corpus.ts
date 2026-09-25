/**
 * Measures the detector against a labelled corpus and prints the confusion
 * matrix. Run: node --experimental-strip-types tests/corpus.ts
 */
import { scan, entropyRatioOf } from '../hooks/scan.ts'

/**
 * Must be caught. Values are fabricated or published examples, never real.
 *
 * Provider-prefixed fixtures are written as `'prefix' + 'body'`. The runtime
 * string is identical -- the detector sees the whole token -- but the source
 * no longer contains a literal that GitHub's push protection reads as a live
 * Slack or Stripe credential and blocks the push over.
 */
const SECRETS: readonly (readonly [string, string])[] = [
  ['aws access key id beside its secret', 'AKIA' + 'IOSFODNN7EXAMPLE' + ' / ' + 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'],
  ['aws secret access key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'],
  ['aws session token', 'FwoGZXIvYXdzEBYaDHRlc3RzZXNzaW9uSyLnAVRlc3RUb2tlblZhbHVlSGVyZQ'],
  ['github classic pat', 'ghp_' + '16C7e42F292c6912E7710c838347Ae178B4a'],
  ['github fine-grained pat', 'github_pat_' + '11ABCDEFG0aBcDeFgHiJkL_9MnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOp'],
  ['slack bot token', 'xoxb-' + '2345678901-2345678901234-Tr4ZgXiLzQwErTyUiOpAsDfG'],
  ['anthropic key', 'sk-ant-' + 'api03-Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0LzXcVbNmQwErTyUiOp-AAAAAA'],
  ['openai key', 'sk-proj-' + 'Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4Yz5Ab6Cd7Ef8'],
  ['google api key', 'AIza' + 'SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY'],
  ['stripe live key', 'sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc'],
  ['jwt', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'],
  ['npm token', 'npm_' + 'iJkLmNoPqRsTuVwXyZ0123456789AbCdEf012345'],
  ['bare base64 secret', 'k3Jd8vQm2XpLzRf7TnWbHy4CsGu9AeVx'],
  ['lowercase key split by a slash', 'k3jd8vqm2xplzrf7/tnwbhy4csgu9aevx'],
  ['bare base64 secret 2', 'Zm9vYmFyc2VjcmV0MTIzNDU2Nzg5MFFXRVJUWQ=='],
  ['hex api key 32', 'a3f9c1e8b7d4602f5e1a9c8b3d7f4e20'],
  ['hex api key 48', 'f0e1d2c3b4a5968778695a4b3c2d1e0fa1b2c3d4e5f60718'],
  ['db url password', 'postgres://svc_reports:Xq7Lm2Pv9Tz4Ry8Kw@db.internal:5432/reports'],
  ['env assignment', 'DATABASE_PASSWORD=hunter2SuperSecret'],
  ['env assignment weak', 'SLACK_SIGNING_SECRET=8f3a9b1c'],
  ['terraform tfvars', 'api_key = "Qw3rTy7UiOp1AsDfGh5JkLzXcVbN"'],
  ['private key block', '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA2Qh8vX3nR7mLpK4tYz9wJfGdSb1cHvNxQe5rAiUoT0MyPkLj\nWnB6XsFdEgHcVtRyUiOpAsDfGhJkLzXcVbNmQwErTyUiOpAsDfGhJkLzXcVbNmQw\n-----END RSA PRIVATE KEY-----'],
  ['bearer header', 'Authorization: Bearer pZm9vYmFyMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTA'],
  ['prose-announced key', "here's a fake api key to use with a fake api called apitester OAJdjljiaw82nd73jlad00d02jld892gygo"],
  ['weak key after a colon', 'api key: Qw3rty7UiOp1AsDfGh5JkLzX'],
  ['vendor-prefixed key', 'testmo_api_' + 'eyJpdiI6IlZZTUtNZnJaVTF1WjlONlJqcTdCWVE9PSIsInZhbHVlIjoiWGt5UThkbUgzV1NvZXRMZnJycE11UGxMN2sveDFYcnZlWHVkZ1FyOFE0MD03ZmJoSmROVmV2d1dycnZGNDVXY2FnPT0iLCJtYWMiOiI0MjljNGZkMmQ5YzBiNWQ5MGJlNzRmYmJjOTIzOWVmY2Q0NmM3YTNiNDAyNGJiYjQxNWU5YWEwOTE2ZWUyZjYyIiwidGFnIjoiIn0='],
  ['token announced in chat', 'my token is 8vQm2XpLzRf7TnWbHy4CsGu9 — use it for the staging call'],
]

/** Must NOT be caught: the ordinary traffic of this operator's sessions. */
const CLEAN: readonly (readonly [string, string])[] = [
  ['git sha', '9f2c1a7b3e5d84c6f0a9b2d1e7c4f8a6b3d5e2c1'],
  ['git sha in log', 'commit 4d8e1f0a9b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e Author: someone'],
  ['sha256 checksum', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
  ['uuid', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'],
  ['ami id', 'ami-0abcdef1234567890'],
  ['instance id', 'i-0123456789abcdef0'],
  ['subnet id', 'subnet-0a1b2c3d4e5f60718'],
  ['arn', 'arn:aws:iam::123456789012:role/terraform-aws-module-core-exec'],
  ['absolute path', '/Users/dev/Documents/repos/infra-aws-tf-example-prod/modules/core/main.tf'],
  ['relative path', 'terraform-aws-module-backend-ec2/templates/userdata.sh.tftpl'],
  ['url', 'https://example.atlassian.net/browse/SER-642'],
  ['long url with query', 'https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#logsV2:log-groups/log-group/service-polling'],
  ['terraform address', 'module.backend.aws_autoscaling_group.this[0]'],
  ['tf plan line', '  ~ user_data = "3d4a1f9c" -> "7b2e5c8d" # forces replacement'],
  ['english prose', 'The apply succeeded but the launch template version was never promoted to the group.'],
  ['camelcase identifiers', 'getUserAccountBalanceByAccountIdentifier'],
  ['snake identifiers', 'aws_cloudwatch_log_subscription_filter_destination'],
  ['semver list', 'v2.14.3 v2.14.4-rc.1 v3.0.0-beta.12'],
  ['base64 of words', 'VGhpcyBpcyBqdXN0IGEgc2VudGVuY2UgZW5jb2RlZA=='],
  ['iso timestamps', '2026-09-18T11:20:34.512Z 2026-09-17T08:00:00.000Z'],
  ['docker image ref', 'ghcr.io/pleejr/service-polling:sha-4d8e1f0'],
  ['k8s resource name', 'service-watchtower-processor-7d9f8c6b54-xk2mq'],
  ['snake resource name', 'service_watchtower_processor_7d9f8c6b54_xk2mq'],
  ['npm integrity absent', 'node_modules/@anthropic-ai/claude-code/package.json'],
  ['jira keys', 'SER-642 SER-659 SER-673 DEVOPS-1204'],
  ['account id', '123456789012'],
  ['log line', '2026-09-18 11:20:34 INFO  [poller-3] fetched 1428 rows in 212ms'],
  ['hcl block', 'resource "aws_security_group_rule" "allow_internal_https" {'],
  ['token talk', 'the total_tokens field says 14998361 tokens left in this context window'],
  ['tokenizer note', 'the tokenizer splits aws_cloudwatch_log_subscription_filter into subwords'],
  ['api key rotation prose', 'rotate the api key in terraform-aws-module-config before the next deploy'],
  ['secretsmanager call', 'aws secretsmanager get-secret-value --secret-id prod/service-polling/database'],
  ['password policy prose', 'the password policy requires MinimumPasswordLength set to fourteen characters'],
  ['access key audit prose', 'list every access key older than ninety days across infra-aws-tf-example-prod'],
  ['credential file path', 'credentials live in ~/.aws/credentials under the profile example-prod-admin'],
  ['url with a uuid branch', 'https://github.com/example-org/example-wiki/pull/new/wt/95f1b764-64bf-445a-993f-7d8061bbf252'],
  ['path with a git sha segment', '/var/lib/buildkite/builds/4d8e1f0a9b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e/artifacts/report.xml'],
  ['s3 key with a uuid', 's3://example-prod-uploads/tournaments/3f2504e0-4f89-11d3-9a0c-0305e82c3301/entry.json'],
  ['worktree path', '/Users/dev/Documents/repos/example-wiki/.worktrees/95f1b764-64bf-445a-993f-7d8061bbf252'],
  ['npm integrity', '"integrity": "sha512-dxsgKSAJCCJI7KhVYoEeIjZ4A1xt5bkLVLJ7oqW1kPrK5jQm4vJRCg=="'],
  ['terraform plan diff', '  ~ tags = { "Name" = "svc-example-prod-asg" "ManagedBy" = "terraform" }'],
  ['git log block', 'commit a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4\nAuthor: someone <someone@example.com>\nDate: Thu Sep 18 11:20:34 2026 -0400'],
  // An access key ID with no secret beside it is the published half of the
  // pair: it appears in every IAM listing and audit note. See the paired
  // sample in SECRETS, which is what a leak actually looks like.
  ['bare aws access key id', 'AKIAIOSFODNN7EXAMPLE'],
  // Measured false positives from a 2293-file markdown vault, 2026-09-18.
  ['cloudwatch metric name', 'the alarm watches HTTPCode_ELB_5XX_Count on prod-alb over five minutes'],
  ['prefixed metric name', 'prod-alb-HTTPCode_ELB_500_Count breached at 11:20'],
  ['ssm document name', 'the maintenance window runs AWS-RunPatchBaseline then AWSEC2-ConfigureSTIG'],
  ['managed policy name', 'attach AWSLambda_FullAccess and AmazonEC2ContainerRegistryReadOnly'],
  ['slash-joined acronyms', 'the diagram shows VPC/subnets/NAT/IGW/route wiring'],
  ['security group rule id', 'sgr-0590b743d0db69ea3 allows 443 from the office range'],
  ['tfc run id', 'run-2dpEth3mLTP3g73n finished applying'],
  ['tfc trigger id', 'trig_01564HvjAymVrZkqfnX2bjS7 fired the run'],
  ['session transcript path', '/Users/dev/.claude/projects/-private-tmp/beaf7dc3-6bd2-43e5-933e-50d1dea7b329.jsonl'],
  ['skill path with a cue word', '/Users/dev/Documents/repos/example-skills/plugins/infra/skills/handle-a-found-credential/SKILL.md'],
  ['iam action', 'the role needs secretsmanager:GetSecretValue and secretsmanager:ListSecrets'],
  ['terraform enum', 'metadata_options { http_tokens = "required" }'],
  ['credential id is a uuid', 'CREDENTIAL_ID: 32b00056-5319-4422-a91e-aabd390b60e8'],
  ['env var name only', 'OPSBOT_JWT_PRIVATE_KEY_PEM_BASE64 is unset in this environment'],
  ['aws cli output', '{"UserId": "AIDACKCEVSQ6C2EXAMPLE", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/plee"}'],
  ['ec2 dns name', 'ip-10-42-7-193.ec2.internal'],
  ['long flag line', '--cache-control max-age=31536000,public --content-encoding gzip --metadata-directive REPLACE'],
  ['base64 png header', 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk'],
  ['go module sum', 'github.com/aws/aws-sdk-go-v2/service/s3 v1.48.1'],
  ['jenkins build id', 'service-polling-deploy-qa-build-2481'],
  ['s3 key', 's3://example-prod-artifacts/service-reports/releases/2026-09-18/service-reports-3.14.2.tar.gz'],
  ['terraform state address', "aws_iam_role_policy_attachment.this[\"arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore\"]"],
  // --- measured on this operator's own traffic, 2026-09-18: a 2301-file wiki
  // vault and 8957 shell commands. Every one of these was a false positive of
  // the assignment rule, which lowered the entropy bar without running the
  // structural filters the entropy path runs first.
  ['yaml secrets block', 'secrets: TERRAFORM_TOKEN: required: true'],
  ['markdown secrets label', 'Secrets: encrypted env/*.ejson decrypted locally to .env files (make env).'],
  ['command substitution', 'TOKEN=$(jq -r .credentials.token ~/.terraform.d/credentials.tfrc.json)'],
  ['python fragment', 'SECRET_RE = re.compile(r"[0-9a-f]{12}")'],
  ['elided credential id', 'CREDENTIAL_ID=32b00056-\u2026 was the real BitBucket access key'],
  ['held secret placeholder', 'aws configure set aws_secret_access_key [secret:AWS_PROD]'],
  ['jq path ending in a brace', "aws rds describe-db-clusters --query 'DBClusters[0].{Secret:MasterUserSecret}'"],
  ['ecs task ids', 'aws ecs describe-tasks --cluster employee_tournaments --tasks 0de381fa1b284946a0f3b7c25e4d19cc 9c286fe6b26048ea8c1d7f40a2b5e3d1'],
  ['turnstile site key', 'the widget renders with 0x4AAAAAABc1dEfGhIjKlMnO in the page'],
]

let tp = 0
let fn = 0
const misses: string[] = []
for (const [label, text] of SECRETS) {
  const f = scan(text)
  if (f.length > 0) tp++
  else {
    fn++
    misses.push(`${label}  ratio=${entropyRatioOf(text.split(/[^A-Za-z0-9+/=_-]/).sort((a, b) => b.length - a.length)[0] ?? '').toFixed(3)}`)
  }
}

let tn = 0
let fp = 0
const falsePositives: string[] = []
for (const [label, text] of CLEAN) {
  const f = scan(text)
  if (f.length === 0) tn++
  else {
    fp++
    for (const x of f) falsePositives.push(`${label}  rule=${x.rule} ratio=${x.ratio.toFixed(3)} "${text.slice(x.start, x.end)}"`)
  }
}

console.log(`secrets caught     ${tp}/${SECRETS.length}`)
console.log(`clean passed       ${tn}/${CLEAN.length}`)
if (misses.length > 0) console.log(`\nMISSED (false negatives):\n  ${misses.join('\n  ')}`)
if (falsePositives.length > 0) console.log(`\nFLAGGED WRONGLY (false positives):\n  ${falsePositives.join('\n  ')}`)
process.exitCode = fn + fp > 0 ? 1 : 0
