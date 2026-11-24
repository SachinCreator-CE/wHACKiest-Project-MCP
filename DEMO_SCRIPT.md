# SentinelAI demo script (3–4 minutes)

## Before the demo (T-30 to T-5 min)

| When | Do | Expect |
|---|---|---|
| T-30 | Stop the app, then `.venv/bin/python scripts/reset_demo_victim.py` (= `make reset`) | leaked key `Active`, and `var/sentinel.db` moved aside so INC-001 is open again with **Deactivate leaked access key** proposed (a rehearsed approval is remembered there). After an offline-only rehearsal (`make offline` uses its own `var/offline`) nothing is needed. |
| T-15 | `.venv/bin/python scripts/simulate_app_auth.py` (= `make simulate-auth`) | simulated app-auth traffic written; INC-002 only sees the last `CLOUDTRAIL_LOOKBACK_HOURS` (24 h), so traffic from setup day is too old |
| T-15 | `.venv/bin/python scripts/simulate_leaked_key.py --profile sentinel-victim` | table: GetCallerIdentity `OK`, 4 × `AccessDenied`; key `AKIA…XXXX (matches DEMO_LEAKED_ACCESS_KEY_ID ✓)` |
| T-5 | `.venv/bin/python scripts/aws_check.py` | all required rows green; **CloudTrail us-east-1 and ap-south-1 show > 0 events**; CloudWatch Logs shows simulated events in the last 24 h |
| T-5 | `ALLOW_REAL_ACTIONS=true` in `.env`, then `make run` | http://127.0.0.1:8000 |
| T-2 | Terminal tab ready: `aws iam list-access-keys --user-name sentinel-demo-victim --profile sentinel-app` | shows `Active` |

If CloudTrail still shows 0 events at T-5, start the app anyway. INC-001 will appear from
synthetic data with a banner saying so. Click **Run detection** once the events
arrive.

## Live run

**0:00–0:20 · The problem.**
"An AWS key gets pushed to GitHub. Within minutes someone uses it to probe the account and try
to make themselves admin. SentinelAI turns that into an explained, contained incident, with a
human in control."
Point at the header: **AWS: connected (account …1234, ap-south-1)** and the Bedrock model id.

**0:20–1:00 · INC-001, live evidence.**
Open **INC-001 (critical): leaked access key**. Walk through the timeline: the GitHub
secret-scanning alert (synthetic, flagged) followed by **real CloudTrail events tagged
`live AWS`**: `GetCallerIdentity` succeeded, then `ListBuckets`, `ListAttachedUserPolicies`,
`CreateAccessKey`, and `AttachUserPolicy AdministratorAccess` on itself, all **AccessDenied**.
"Those are real events from this AWS account, minutes old. The key ID is masked everywhere:
AKIA…XXXX."

**1:00–1:30 · Tool trace.**
Open the **Tool calls** tab (bottom panel): `CloudTrail MCP → lookup_events` (backend
`awslabs.cloudtrail-mcp-server`, target **aws**, us-east-1 and ap-south-1), `Identity MCP`
(CloudWatch Logs), `Logs MCP` (S3). "The agent uses the official AWS Labs CloudTrail MCP server
over stdio, plus our own MCP servers."

**1:30–2:15 · Voice question.**
Click the mic and ask: **"What happened with the leaked key and what should we do?"**
The answer is spoken (ElevenLabs): the key was used after it was flagged, 4 calls were denied,
2 were privilege-escalation attempts (CreateAccessKey, AttachUserPolicy AdministratorAccess),
and it recommends deactivating the key, resolving the alert and notifying the owner. The trace
shows `Bedrock → converse` (Nova Lite, stop reason + tokens) and the tools it called.
"The model can only *propose*. Nothing runs without a human."

**2:15–3:00 · Human-approved containment.**
In **Actions** ("Agent proposes · human approves"), click **Approve** on **Deactivate leaked
access key** and enter your name, which is recorded in the audit log.
The result is **executed for real**: all gates passed (human approval, ALLOW_REAL_ACTIONS,
allow-listed user, live incident). Switch to the terminal:

```bash
aws iam list-access-keys --user-name sentinel-demo-victim --profile sentinel-app
# "Status": "Inactive"
```

Back in the UI, the incident is **mitigated**. Open the **Audit log** tab, which shows
`action_approved → action_executed → report_written` with **chain verified ✓** (SHA-256 hash chain).
Open the report link: `s3://sentinelai-…/reports/INC-001/<ts>.md`.

**3:00–3:30 · INC-002 + noise suppression.**
Open **INC-002 (high): brute force on priya**: 18 failed logins from 185.220.101.47 in about 4
minutes, then a success **stopped by MFA**. The data comes from CloudWatch Logs
`/sentinelai/app-auth` (simulated traffic, tagged as such). Click **Run detection**: the toast reports
"… 1 suppressed". Ask the agent **"Why was arjun not flagged?"**: one typo from a new laptop,
then MFA success from India during work hours, so no incident and a stated reason. "It explains
what it *didn't* raise, too."

**3:30–3:45 · Close.**
"Bedrock tool-use agent, CloudTrail through MCP, CloudWatch Logs, S3, least-privilege IAM, and
a real, audited, human-approved fix. It also runs fully offline as a fallback."

## After the demo

```bash
# stop the app first
.venv/bin/python scripts/reset_demo_victim.py      # key back to Active + var/sentinel.db moved aside for the next run
```

Set `ALLOW_REAL_ACTIONS=false` again when you aren't presenting.

## Backup plan (offline fallback)

| Problem | Action |
|---|---|
| No network / AWS down / credentials broken | `make offline`. Same incidents from synthetic data (key `AKIA…MPLE`), offline agent, browser speech. Say "this is the offline fallback; the live path is identical but backed by AWS". |
| CloudTrail events not visible yet | Keep going. INC-001 runs on synthetic data with the banner. Show the `simulate_leaked_key.py` output table as proof of the real calls. |
| Bedrock error / throttling | The agent falls back to the deterministic offline agent (banner shows the reason). Answers still cite the same tool results. |
| ElevenLabs fails | Browser speech recognition and TTS take over automatically, or type the question. |
| Approve shows "simulated" | Check `ALLOW_REAL_ACTIONS=true` and restart. The incident must be live (not synthetic). |
| The key was already deactivated / no Approve button on INC-001 | Stop the app, `scripts/reset_demo_victim.py` (reactivates the key and moves `var/sentinel.db` aside), start the app again; detection runs at startup. |

## Judge Q&A cheat sheet

- **Is that a real leaked key?** It's a real key of a dedicated IAM user with **zero
  permissions**. It never left this laptop (local CLI profile only), and the GitHub alert is
  synthetic. Every call except GetCallerIdentity is denied.
- **Which AWS services?** Bedrock (Converse tool use, Nova Lite via the APAC inference profile,
  optional Guardrails), CloudTrail Event history via the AWS Labs CloudTrail MCP server,
  CloudWatch Logs, S3 (raw datasets + reports, Block Public Access + SSE-S3), IAM
  (UpdateAccessKey), STS, optional Secrets Manager. It deploys on EC2 with an instance role.
- **Why MCP?** One tool interface for the agent across the AWS Labs server and our own servers
  (GitHub, Identity, Logs), each swappable between live AWS and offline.
- **How do you stop the LLM doing damage?** It has no execute tool. It can only call
  `propose_remediation`. Execution is a separate human approval endpoint with three gates plus a
  live-only check, and the only IAM write allowed by policy is UpdateAccessKey on one user.
- **What about secrets in prompts?** Masking before anything leaves the process (key IDs as
  AKIA…WXYZ, secrets and emails redacted), and optionally a Bedrock Guardrail with
  AWS_ACCESS_KEY / AWS_SECRET_KEY / EMAIL anonymization.
- **Why no IP reputation for INC-001?** The live calls come from the presenter's laptop, so the
  rule keys on *use after the alert* and *escalation attempts* instead.
- **Cost?** Fractions of a cent per question on Nova Lite. Event history is free, and S3 and
  Logs stay within the free tier. A $5 budget alert is configured.
- **Latency of detection?** CloudTrail Event history typically lags 5–15 minutes. In production
  you would add EventBridge rules on CloudTrail for near-real-time triggers.
- **Is the audit trustworthy?** Each entry hashes the previous one (SHA-256 chain), and the UI
  verifies the chain. Reports are written to S3.
- **What would you add next?** EventBridge triggers, a real GitHub App for secret-scanning
  webhooks, Security Hub findings export, and DynamoDB behind the same store interface.
