# AWS setup for SentinelAI

This guide sets up the live AWS path from scratch, with exact console **and** CLI steps.
It takes about 20 minutes and should cost well under $1. The default region is
**ap-south-1 (Mumbai)**. IAM and STS events are global, so they also land in **us-east-1**
Event history, and SentinelAI queries both regions.

What you will create:

| Resource | Purpose |
|---|---|
| IAM user `sentinel-app` + managed policy `SentinelAIApp` | the app's least-privilege identity (profile `sentinel-app`) |
| IAM user `sentinel-demo-victim`, **no policies**, one access key | the "leaked" key (profile `sentinel-victim`) |
| S3 bucket `sentinelai-<8 hex>` | `raw/` datasets for the Logs MCP and `reports/` for incident reports |
| CloudWatch Logs group `/sentinelai/app-auth` (7-day retention) | simulated app-auth traffic for the Identity MCP |
| Bedrock model access (Amazon Nova Lite) | the Converse tool-use agent |
| $5 budget alert | cost guard rail |

---

## 0. Install the tools (macOS)

```bash
brew install awscli uv        # AWS CLI v2 + uv (uvx runs the AWS Labs CloudTrail MCP server)
aws --version                 # aws-cli/2.x
uvx --version
uvx awslabs.cloudtrail-mcp-server@0.1.2 --help </dev/null >/dev/null 2>&1 || true   # pre-fetch the pinned CloudTrail MCP release before demo day
python3 --version             # 3.12 or newer
```

## 1. Use an admin identity for setup, never root keys

Don't create access keys for the root user. For the one-time setup, use one of these:

- **IAM Identity Center (recommended):** `aws configure sso --profile admin`, then
  `aws sso login --profile admin`.
- **An admin IAM user** with MFA: `aws configure --profile admin`.

Every setup command below uses `--profile admin`. The app itself never uses this profile.

```bash
aws sts get-caller-identity --profile admin      # must NOT show ":root"
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --profile admin)
```

## 2. Create a $5 budget alert

**Console:** Billing and Cost Management → **Budgets** → **Create budget** → *Use a template* →
**Monthly cost budget** → budget name `sentinelai-5usd`, amount **5.00 USD**, your email →
**Create budget**.

**CLI:**

```bash
cat > /tmp/budget.json <<'JSON'
{"BudgetName": "sentinelai-5usd", "BudgetLimit": {"Amount": "5", "Unit": "USD"},
 "TimeUnit": "MONTHLY", "BudgetType": "COST"}
JSON
cat > /tmp/notifications.json <<'JSON'
[
  {"Notification": {"NotificationType": "ACTUAL", "ComparisonOperator": "GREATER_THAN",
                    "Threshold": 80, "ThresholdType": "PERCENTAGE"},
   "Subscribers": [{"SubscriptionType": "EMAIL", "Address": "you@example.com"}]},
  {"Notification": {"NotificationType": "FORECASTED", "ComparisonOperator": "GREATER_THAN",
                    "Threshold": 100, "ThresholdType": "PERCENTAGE"},
   "Subscribers": [{"SubscriptionType": "EMAIL", "Address": "you@example.com"}]}
]
JSON
aws budgets create-budget --account-id "$ACCOUNT_ID" \
  --budget file:///tmp/budget.json \
  --notifications-with-subscribers file:///tmp/notifications.json --profile admin
```

## 3. Enable Bedrock model access

**Console:** switch the region to **Asia Pacific (Mumbai) ap-south-1** → Amazon Bedrock →
**Model access** (bottom of the left nav) → **Modify model access** → tick
**Amazon › Nova Lite** (and **Nova Pro** if you want a stronger model) → **Next** → **Submit**.
Access is usually granted within a minute. Newer accounts may show serverless models as
already enabled; that's fine.

- In ap-south-1, Nova Lite is called through the **APAC cross-region inference profile**
  `apac.amazon.nova-lite-v1:0`. Profiles route requests across APAC regions, which is why the
  IAM policy allows `arn:aws:bedrock:*::foundation-model/amazon.nova-*`.
- If Nova isn't offered in your region, use **us-east-1**: set `BEDROCK_REGION=us-east-1` and
  `BEDROCK_MODEL_ID=us.amazon.nova-lite-v1:0`.
- Some model providers also ask for a one-time **use-case form** on the Model access page
  before access is granted; if Bedrock says so, fill it in and retry.

**CLI (verify):**

```bash
aws bedrock list-foundation-models --region ap-south-1 --by-provider amazon \
  --query "modelSummaries[].{id:modelId,types:join(',',inferenceTypesSupported)}" --output table --profile admin
aws bedrock list-inference-profiles --region ap-south-1 \
  --query "inferenceProfileSummaries[].inferenceProfileId" --output table --profile admin
aws bedrock-runtime converse --region ap-south-1 --model-id apac.amazon.nova-lite-v1:0 \
  --messages '[{"role":"user","content":[{"text":"Say hi"}]}]' --profile admin
```

## 4. Prepare the project

```bash
git clone <this repo> sentinelai && cd sentinelai
make venv                      # .venv with requirements-dev.txt
cp .env.example .env           # never commit .env
```

## 5. Render the least-privilege IAM policy

```bash
.venv/bin/python scripts/render_iam_policy.py --profile admin
# -> infra/iam/sentinel-app-policy.rendered.json (gitignored)
#    also writes S3_BUCKET=sentinelai-<8 hex> into .env if it was empty
```

The renderer fills `<ACCOUNT_ID>`, `<BUCKET_NAME>` and `<REGION>`, plus `<AUTH_LOG_GROUP>`,
`<VICTIM_USER>` and `<ELEVENLABS_SECRET>` from `AUTH_LOG_GROUP`, `DEMO_VICTIM_USER` and
`ELEVENLABS_SECRET_ID` (defaults `/sentinelai/app-auth`, `sentinel-demo-victim`,
`sentinelai/elevenlabs`). It adds inference-profile ARNs for `BEDROCK_REGION` and the
foundation-model / inference-profile ARNs `BEDROCK_MODEL_ID` needs when the template's
`apac.`/`us.` Nova wildcards do not cover it (`--model ID` adds more; ids or full ARNs), and
adds `bedrock:ApplyGuardrail` when `BEDROCK_GUARDRAIL_ID` (id or ARN) is set. It warns about any
`REAL_ACTION_USER_ALLOWLIST` user other than `DEMO_VICTIM_USER`, since the policy grants key
actions on that one user only. Re-render whenever you change any of these settings. Use
`--account-id 123456789012` to skip the STS call.

## 6. Create the app user `sentinel-app`

**Console:** IAM → **Policies** → **Create policy** → **JSON** → paste the rendered file →
name `SentinelAIApp` → **Create policy**. Then IAM → **Users** → **Create user** →
`sentinel-app` (no console access) → **Attach policies directly** → `SentinelAIApp` → **Create user**.
Open the user → **Security credentials** → **Create access key** → *Command Line Interface (CLI)*,
then run `aws configure --profile sentinel-app` and paste the key ID and secret
(region `ap-south-1`, output `json`).

**CLI:** the secret goes straight into the profile and never shows on screen.

```bash
aws iam create-policy --policy-name SentinelAIApp \
  --policy-document file://infra/iam/sentinel-app-policy.rendered.json --profile admin
aws iam create-user --user-name sentinel-app --profile admin
aws iam attach-user-policy --user-name sentinel-app \
  --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/SentinelAIApp" --profile admin
aws iam create-access-key --user-name sentinel-app \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text --profile admin \
  | { read -r id secret; aws configure set aws_access_key_id "$id" --profile sentinel-app;
      aws configure set aws_secret_access_key "$secret" --profile sentinel-app; }
aws configure set region ap-south-1 --profile sentinel-app
aws sts get-caller-identity --profile sentinel-app     # .../user/sentinel-app
```

To change the policy later, re-render it and publish a new default version. IAM keeps at
most 5 versions, so delete old ones when needed.

```bash
aws iam create-policy-version --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/SentinelAIApp" \
  --policy-document file://infra/iam/sentinel-app-policy.rendered.json --set-as-default --profile admin
```

## 7. Create the demo victim `sentinel-demo-victim` (NO policies)

See [`infra/iam/sentinel-victim-policy.md`](../infra/iam/sentinel-victim-policy.md) for why it
has no permissions.

**Console:** IAM → Users → **Create user** → `sentinel-demo-victim`, no console access →
**do not attach any policy** → Create. Then **Security credentials** → **Create access key**
(CLI) → `aws configure --profile sentinel-victim`.

**CLI:**

```bash
aws iam create-user --user-name sentinel-demo-victim --profile admin
aws iam create-access-key --user-name sentinel-demo-victim \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text --profile admin \
  | { read -r id secret; aws configure set aws_access_key_id "$id" --profile sentinel-victim;
      aws configure set aws_secret_access_key "$secret" --profile sentinel-victim; }
aws configure set region ap-south-1 --profile sentinel-victim
aws iam list-attached-user-policies --user-name sentinel-demo-victim --profile admin   # []
```

## 8. Fill in `.env`

```bash
# The victim's access key ID only (AKIA...), never the secret:
aws configure get aws_access_key_id --profile sentinel-victim
```

| Variable | Value |
|---|---|
| `AWS_PROFILE` | `sentinel-app` (on EC2 delete the line to use the instance role; an empty value is ignored) |
| `AWS_REGION` / `BEDROCK_REGION` | `ap-south-1` |
| `BEDROCK_MODEL_ID` | `apac.amazon.nova-lite-v1:0` |
| `S3_BUCKET` | already filled by step 5 |
| `DEMO_LEAKED_ACCESS_KEY_ID` | the victim's key ID from the command above |
| `ALLOW_REAL_ACTIONS` | `true` only for the live demo; `false` otherwise |

## 9. Provision, verify, simulate, run

```bash
.venv/bin/python scripts/aws_setup.py          # bucket (BPA + SSE-S3), raw/ upload, reports/, log group,
                                               # simulated app-auth traffic, Bedrock test call
.venv/bin/python scripts/aws_check.py          # green/red checklist (exit 1 if a required check fails)
.venv/bin/python scripts/simulate_leaked_key.py   # real AccessDenied CloudTrail events
# wait 5–15 minutes for CloudTrail Event history
.venv/bin/python scripts/aws_check.py          # CloudTrail rows should now show events
.venv/bin/python -m sentinel                   # http://127.0.0.1:8000, header shows "AWS: connected"
```

`scripts/aws_setup.py` is idempotent, so you can run it again. Use `--skip-simulation` to avoid
writing a second batch of simulated logins. `scripts/list_bedrock_models.py` lists models and
profiles in a region, and `--probe MODEL_ID` verifies tool use for a model.

## 10. Optional: ElevenLabs key in Secrets Manager

The name must start with `sentinelai/elevenlabs` to match the policy statement
`SecretsManagerElevenLabs`.

```bash
read -rs EL_KEY   # paste the key, it is not echoed
aws secretsmanager create-secret --name sentinelai/elevenlabs --region ap-south-1 --profile admin \
  --secret-string "{\"ELEVENLABS_API_KEY\":\"${EL_KEY}\"}"
unset EL_KEY
```

Then set `ELEVENLABS_SECRET_ID=sentinelai/elevenlabs` and leave `ELEVENLABS_API_KEY` empty.

## 11. Optional: Bedrock Guardrail (second masking layer)

**Console:** Bedrock → **Guardrails** → **Create guardrail** → name `sentinelai-pii` →
*Sensitive information filters* → add PII types **AWS access key**, **AWS secret key** and
**Email**, behavior **Mask** → Create → **Create version**.

**CLI:**

```bash
aws bedrock create-guardrail --name sentinelai-pii --region ap-south-1 --profile admin \
  --blocked-input-messaging "Blocked by the SentinelAI guardrail." \
  --blocked-outputs-messaging "Blocked by the SentinelAI guardrail." \
  --sensitive-information-policy-config '{"piiEntitiesConfig":[
      {"type":"AWS_ACCESS_KEY","action":"ANONYMIZE"},
      {"type":"AWS_SECRET_KEY","action":"ANONYMIZE"},
      {"type":"EMAIL","action":"ANONYMIZE"}]}'
aws bedrock create-guardrail-version --guardrail-identifier <guardrailId> --region ap-south-1 --profile admin
```

Set `BEDROCK_GUARDRAIL_ID` to the `guardrailId` that `create-guardrail` printed (lowercase
letters and digits, or the guardrail ARN; not the name `sentinelai-pii`) and
`BEDROCK_GUARDRAIL_VERSION` to the version number (or `DRAFT`) in `.env`. Then re-render the
policy, which adds `bedrock:ApplyGuardrail`, and publish it as a new policy version (step 6).
`scripts/aws_check.py` fails on a malformed id or version, and its Bedrock probe sends the
copilot's real system prompt, guardrail and a `toolResult` turn, so a missing
`bedrock:ApplyGuardrail` grant shows up there instead of as an offline chat.

## 12. Optional: run on EC2 (t4g.small)

Attach an instance role with the rendered policy, set the IMDSv2 hop limit to 2 so
containers can reach instance metadata, and run `docker compose up -d --build`. See the
comments in `docker-compose.yml`. No keys are needed on the instance.

## 13. After the demo / teardown

```bash
.venv/bin/python scripts/reset_demo_victim.py      # stop the app first: reactivates the leaked key and moves var/sentinel.db aside
.venv/bin/python scripts/aws_teardown.py           # empties + deletes the bucket (all versions) and the log group
```

The teardown script never touches IAM and prints the manual IAM cleanup commands.
Also delete the budget, the guardrail and the secret if you created them:

```bash
aws secretsmanager delete-secret --secret-id sentinelai/elevenlabs --recovery-window-in-days 7 --region ap-south-1 --profile admin
aws bedrock delete-guardrail --guardrail-identifier <guardrailId> --region ap-south-1 --profile admin
aws budgets delete-budget --account-id "$ACCOUNT_ID" --budget-name sentinelai-5usd --profile admin
```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `AccessDeniedException` calling the model | Model access not granted in this region, the wrong profile/model id, or the IAM policy is missing that model. Check Model access, run `scripts/list_bedrock_models.py --probe <id>`, re-render the policy with `--model <id>`. |
| `ValidationException: Invocation of model ID ... with on-demand throughput isn't supported` | Use the **inference profile** id (`apac.amazon.nova-lite-v1:0` / `us.amazon.nova-lite-v1:0`), not the bare model id. |
| Live INC-001 shows "synthetic" / no CloudTrail events | Event history lags **5–15 min** after `simulate_leaked_key.py`. Wait, then `scripts/aws_check.py`. Check `DEMO_LEAKED_ACCESS_KEY_ID` matches the victim profile. |
| `ThrottlingException` on LookupEvents | CloudTrail LookupEvents allows **2 requests/second** per account and region. The app rate-limits and backs off; don't run several checks in parallel. |
| `The config profile (sentinel-app) could not be found` | Run step 6. To use the default chain instead (EC2 instance role): for the scripts pass `--profile ''`; for the app (`make run` / `python -m sentinel`, which has no `--profile` flag) delete the `AWS_PROFILE` line from `.env` or leave it empty. |
| `InvalidClientTokenId` / `UnrecognizedClientException` | The profile's key was deleted or deactivated. For the victim, run `scripts/reset_demo_victim.py`. |
| CloudTrail MCP row red in `aws_check.py` | Install uv (`brew install uv`). The first `uvx` run downloads the server, so rerun if it timed out. The app falls back to boto3 LookupEvents either way. |
| `simulate_leaked_key.py` says "refusing to continue" | The `sentinel-victim` profile isn't `user/sentinel-demo-victim`. Fix the profile, and never point it at a real user. |
