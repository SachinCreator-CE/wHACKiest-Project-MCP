# SentinelAI

**A security-incident agent on AWS.** SentinelAI joins a (synthetic) GitHub secret-scanning
alert with **real CloudTrail activity** of the leaked key, detects brute-force logins from
CloudWatch Logs and explains each incident in plain language, by text or voice. A
**Bedrock Converse tool-use agent** investigates through **MCP servers**, including the official
**AWS Labs CloudTrail MCP server**. The agent can only *propose* remediations. A human approves
them, and only then does SentinelAI deactivate the leaked IAM access key for real.

AWS is the main path. An offline mode with the same scenarios is the backup, and each
component falls back on its own with the reason shown in the UI.

## Features

- **Live leaked-key incident (INC-001):** a zero-permission demo user's key makes real API calls
  (`ListBuckets`, `CreateAccessKey`, `AttachUserPolicy AdministratorAccess`, ...). All are denied,
  but they show up in CloudTrail Event history (ap-south-1 and us-east-1). SentinelAI finds them
  through the CloudTrail MCP, ranks the privilege-escalation attempts and opens a critical incident.
- **Brute-force detection (INC-002):** 18 failed logins on `priya` followed by an MFA-blocked
  success, read from CloudWatch Logs. Benign `arjun` (one typo from a new laptop) is
  **suppressed with a reason**.
- **Bedrock agent with tool use:** Amazon Nova Lite through the APAC inference profile. Tools:
  incidents, GitHub alerts, CloudTrail lookup, auth events, user profiles, datasets in S3,
  remediation proposals and the audit log. Every tool call appears in a live **tool trace**
  (`CloudTrail MCP → lookup_events → 7 events in 820 ms`, target *aws*).
- **Human-in-the-loop remediation:** "Deactivate leaked access key" runs `iam:UpdateAccessKey`
  only after a human approves **and** `ALLOW_REAL_ACTIONS=true` **and** the user is allow-listed
  **and** the incident is live. Otherwise the action is simulated, and the UI says why.
- **Tamper-evident audit log** (SHA-256 hash chain) and **incident reports** (Markdown + JSON)
  written to S3 `reports/`.
- **Voice:** ElevenLabs speech-to-text and text-to-speech (key from env or Secrets Manager), with
  the browser Web Speech API as fallback.
- **Masking everywhere:** access keys show as `AKIA…WXYZ`, and secrets, emails and tokens are
  redacted before anything reaches Bedrock, the UI, reports or logs. An optional Bedrock
  Guardrail adds a second layer.

## Quickstart

**Offline, in 2 commands** (no AWS account, no network):

```bash
make venv
make offline          # http://127.0.0.1:8000  (SENTINEL_MODE=offline, own store in var/offline)
```

**AWS mode** (full guide in [docs/AWS_SETUP.md](docs/AWS_SETUP.md)):

```bash
brew install awscli uv && make venv && cp .env.example .env
.venv/bin/python scripts/render_iam_policy.py --profile admin   # least-privilege policy
# create IAM users sentinel-app (rendered policy) + sentinel-demo-victim (NO policies), CLI profiles
# then in .env set the victim's key ID, or INC-001 stays synthetic and nothing runs for real (AWS_SETUP step 8):
sed -i.bak "s/^DEMO_LEAKED_ACCESS_KEY_ID=.*/DEMO_LEAKED_ACCESS_KEY_ID=$(aws configure get aws_access_key_id --profile sentinel-victim)/" .env
.venv/bin/python scripts/aws_setup.py          # bucket, data upload, log group, simulated auth traffic, Bedrock test
.venv/bin/python scripts/simulate_leaked_key.py --profile sentinel-victim
.venv/bin/python scripts/aws_check.py          # all green? (CloudTrail needs 5–15 min)
make run                                       # ALLOW_REAL_ACTIONS=true in .env for the live demo's real key deactivation
```

## AWS architecture

```mermaid
flowchart LR
  UI["Browser UI<br/>(text + voice)"] --> API["FastAPI<br/>python -m sentinel"]
  API --> AGENT["Bedrock Converse<br/>tool-use agent<br/>(Nova Lite, apac profile)"]
  API --> RULES["Rule engine<br/>R-LEAKED-KEY, R-BRUTE-FORCE"]
  AGENT --> HUB["MCP clients (hub)"]
  RULES --> HUB
  HUB --> CTMCP["AWS Labs CloudTrail MCP<br/>(uvx awslabs.cloudtrail-mcp-server)"]
  CTMCP --> CT[("CloudTrail Event history<br/>ap-south-1 + us-east-1")]
  HUB --> IDMCP["Identity MCP"] --> CWL[("CloudWatch Logs<br/>/sentinelai/app-auth")]
  HUB --> LOGMCP["Logs MCP"] --> S3RAW[("S3 raw/")]
  HUB --> GHMCP["GitHub MCP (mock)<br/>synthetic alert"]
  API --> APPROVE{"Human approval<br/>+ ALLOW_REAL_ACTIONS<br/>+ allow-list + live"}
  APPROVE -->|"iam:UpdateAccessKey"| IAM[("IAM user<br/>sentinel-demo-victim")]
  API --> REPORTS[("S3 reports/")]
  API --> AUDIT[("Audit hash chain<br/>SQLite")]
  API --> VOICE["ElevenLabs STT/TTS"]
  API -.optional.-> SM[("Secrets Manager<br/>ElevenLabs key")]
  AGENT -.optional.-> GR["Bedrock Guardrail<br/>PII anonymize"]
```

- **Bedrock Converse + tool use:** the agent loop runs up to `BEDROCK_MAX_TURNS` tool rounds.
  Switching models is a one-line change (`BEDROCK_MODEL_ID`).
- **CloudTrail:** the AWS Labs MCP server first, then boto3 `LookupEvents`, then the mock. Results
  are deduplicated across regions, rate-limited to 2 req/s and cached.
- **CloudWatch Logs:** `FilterLogEvents` with JSON filter patterns on `/sentinelai/app-auth`.
- **S3:** `raw/` datasets (Block Public Access on, SSE-S3) and `reports/` incident reports.
- **IAM:** the only write is `UpdateAccessKey` on the single demo victim user.

### IAM policy (least privilege)

[`infra/iam/sentinel-app-policy.json`](infra/iam/sentinel-app-policy.json) is the template;
`scripts/render_iam_policy.py` fills it in.

| Sid | Actions | Resource |
|---|---|---|
| BedrockInvoke | `bedrock:InvokeModel` (Converse) | `foundation-model/amazon.nova-*` (any region), inference profiles `apac.amazon.nova-*`, `us.amazon.nova-*`, plus whatever `BEDROCK_MODEL_ID` needs |
| BedrockDiscovery | `ListFoundationModels`, `ListInferenceProfiles` | `*` |
| CloudTrailLookup | `cloudtrail:LookupEvents` | `*` (the only resource it supports) |
| LogsAppAuth | create/retention/delete group, create stream, put/filter events, describe streams | `log-group:<AUTH_LOG_GROUP>` (default `/sentinelai/app-auth`) and its streams only |
| S3Bucket | create/list/versions, public-access-block, put encryption, delete bucket | `arn:aws:s3:::<bucket>` |
| S3Objects | `GetObject`, `PutObject`, `DeleteObject`, `DeleteObjectVersion` | `arn:aws:s3:::<bucket>/*` |
| IamDemoVictimKeyOnly | `iam:UpdateAccessKey`, `iam:ListAccessKeys` | `user/<DEMO_VICTIM_USER>` (default `sentinel-demo-victim`) only |
| STS | `sts:GetCallerIdentity` | `*` |
| SecretsManagerElevenLabs (optional) | `secretsmanager:GetSecretValue` | `secret:<ELEVENLABS_SECRET_ID>-*` (default `sentinelai/elevenlabs`) |

**Stronger model:** enable Amazon Nova Pro under Bedrock → Model access, then set
`BEDROCK_MODEL_ID=apac.amazon.nova-pro-v1:0` (one line in `.env`) and re-render. For any other
model the renderer adds the `foundation-model/<model>` and matching `inference-profile/<id>` ARNs
automatically (or pass `--model <id>`). Publish the result as a new policy version.

The victim user has **no policies at all** (see
[`infra/iam/sentinel-victim-policy.md`](infra/iam/sentinel-victim-policy.md)).

### Cost

- **Bedrock** is pay-per-use. Nova Lite costs fractions of a cent per demo question (a few
  thousand tokens).
- **CloudTrail Event history** (90 days of management events) is **free**. No trail is needed.
- **S3** (a few KB) and **CloudWatch Logs** (a few hundred events, 7-day retention) stay within
  the free tier.
- A **$5 budget alert** is part of the setup. `scripts/aws_teardown.py` removes the bucket and
  log group afterwards.

## How the live scenario is kept safe

1. **The victim has zero permissions.** The leaked key can only call `GetCallerIdentity`, and
   every other call is denied. That is exactly what creates the CloudTrail evidence.
2. **The key never leaves your laptop.** It lives only in the local `sentinel-victim` CLI
   profile. `.env` holds just its *ID* (`DEMO_LEAKED_ACCESS_KEY_ID`). Nothing is pushed to GitHub,
   and the GitHub side of the story is a **synthetic** alert from a mock MCP server.
3. **The simulation is guarded.** `simulate_leaked_key.py` stops unless the caller is exactly
   `user/sentinel-demo-victim`. If a denied call ever succeeds, it undoes it (deletes the key or
   detaches the policy) and exits non-zero.
4. **Real actions are triple-gated:** human approval, `ALLOW_REAL_ACTIONS=true`, and the target in
   `REAL_ACTION_USER_ALLOWLIST`. They also run only for a **live** incident with AWS connected.
   The LLM can only propose.
5. **Everything is audited.** The audit log is a SHA-256 hash chain (`chain_ok` in the UI) and
   every approval produces an S3 report.
6. **No secrets in the repo.** Only AWS's documented example key `AKIAIOSFODNN7EXAMPLE` appears.
   CI fails on any other `AKIA…` string.

## Offline fallback

`SENTINEL_MODE=offline` never touches AWS or the network, and CI uses it. In `auto` mode each
component falls back independently: CloudTrail (AWS Labs MCP → boto3 → mock), CloudWatch Logs,
S3 datasets, Bedrock (→ deterministic offline agent using the same tools), and ElevenLabs
(→ browser speech). The header then shows an **"Offline fallback"** banner with the reasons. If
the live key has no CloudTrail events yet (Event history lag), INC-001 is shown from synthetic
data and the banner says so.

## Project layout

```
sentinel/            app package
  config.py models.py trace.py masking.py store.py
  aws/               session, bedrock, cloudtrail_direct, cloudwatch, s3, iam_actions
  mcp_servers/       github_mock, cloudtrail_mock, identity, logs (stdio MCP servers)
  mcp_hub.py sources.py normalize.py engine.py pipeline.py actions.py reports.py voice.py api.py
  agent/             tools, prompts, loop (Bedrock), offline agent
web/                 vanilla JS SPA
data/                synthetic datasets (uploaded to s3://<bucket>/raw/)
scripts/             aws_setup, aws_check, simulate_leaked_key, simulate_app_auth,
                     reset_demo_victim, aws_teardown, list_bedrock_models, render_iam_policy
infra/iam/           least-privilege policy template + victim notes
docs/                AWS_SETUP.md, CONTRACT.md
tests/               pytest (offline; AWS via botocore Stubber)
```

## Testing

```bash
make test        # SENTINEL_MODE=offline SENTINEL_NO_DOTENV=1 pytest -q
```

No test touches AWS or the network. AWS code is tested with `botocore.stub.Stubber` and small
fakes. CI (GitHub Actions, Python 3.12) runs the suite and the access-key scan.
`scripts/aws_check.py` is the live end-to-end readiness check.

## Milestones

| | Milestone | Status |
|---|---|---|
| M0 | Contract, config, models, masking, store, trace, AWS session | done |
| M1 | Synthetic datasets + mock/identity/logs MCP servers | done |
| M2 | AWS adapters (CloudTrail direct, CloudWatch Logs, S3) + MCP hub | done |
| M3 | Rule engine + detection pipeline (INC-001, INC-002, arjun suppression) | done |
| M4 | Actions catalog, real-action gate, IAM remediation, S3 reports | done |
| M5 | Bedrock Converse tool-use agent + offline agent | done |
| M6 | FastAPI + SPA (timeline, trace, approvals, audit) | done |
| M7 | ElevenLabs voice + browser fallback | done |
| M8 | Ops: IAM policy, setup/check/simulate/teardown scripts, Docker, CI, docs | done |
| M9 | Live rehearsal on a real AWS account + demo polish | in progress |

"Done" means implemented and unit-tested offline. The live path is verified with
`scripts/aws_check.py` on a configured account.

## Limitations

- The GitHub secret-scanning side is **synthetic** (mock MCP). Only the CloudTrail, CloudWatch,
  S3, Bedrock and IAM parts are live.
- CloudTrail Event history lags **5–15 minutes**, and `LookupEvents` is limited to 2 req/s.
- Remediation is limited to deactivating the demo victim's access key. The other actions
  (block IP, force password reset, ...) are simulated.
- The UI has no authentication. Run it locally, or on EC2 behind a security group restricted to
  your IP or an SSH tunnel.
- Bedrock model availability differs by region and account. Use
  `scripts/list_bedrock_models.py --probe <id>` to check.
