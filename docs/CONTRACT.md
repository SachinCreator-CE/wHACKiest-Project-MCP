# SentinelAI internal contract (for implementers)

SentinelAI is a security-incident agent built for an AWS sponsor prize, so **AWS is the
main path**. The offline demo mode is a backup only: when AWS credentials are missing or a call
fails, that component falls back to offline data and the UI shows an "Offline fallback" banner
with the reason.

Stack: Python 3.12+ (the dev Mac runs 3.15), FastAPI, boto3, `mcp` SDK 2.3 (`mcp.server.mcpserver.MCPServer`,
`mcp.client.stdio.stdio_client`, `mcp.ClientSession`), httpx, a vanilla JS SPA in `web/`, SQLite.
Run everything from the repo root the repository root with `.venv/bin/python`.
Tests: `SENTINEL_NO_DOTENV=1 SENTINEL_MODE=offline .venv/bin/python -m pytest -q`.

## Already written (do NOT rewrite; extend only if a bug blocks you, and say so)
- `sentinel/config.py`: `Settings`, `load_settings(**overrides)`. Read it.
  Env values are validated, never fatal: an empty `AWS_PROFILE` (or `AWS_DEFAULT_PROFILE`) is removed from the environment; integers that are
  blank/unparsable/below range use the default (above range: clamped, lookback max 2160 h); `CLOUDTRAIL_REGIONS` splits on
  `,`/`;`/space, is lowercased, de-duplicated and drops non-region names; `SENTINEL_MODE` maps off/false/demo -> offline,
  live/true -> aws, anything unknown -> offline (fail safe); `DEMO_LEAK_FLAGGED_AT` is normalised to UTC ISO (naive = UTC,
  warned; relative "2 hours ago" allowed) or blanked. `leak_flagged_at(settings, now)` is the one flagged-at rule for the GitHub MCP
  and its local fallback; a flag more than 5 min in the future is ignored (warned) and the lookback start is used instead.
  A lookback under 3 h warns once (the offline scenario spans ~3 h). All warnings go to the `sentinel.config` logger.
- `sentinel/models.py`: `Event`, `SecretAlert`, `Incident`, `Action`, `AuditEntry`, `TraceEntry`, `iso()`, `parse_ts()`, `utcnow()`.
- `sentinel/trace.py`: `collect()`, `span(server, tool, target, backend, region)`, `recent()`, `fmt()`.
- `sentinel/masking.py`: `mask_text`, `mask_obj`, `mask_access_key`. Access key IDs become `AKIA…WXYZ`, also when
  glued to other text (`creds_AKIA…`, `%3DAKIA…`). A 40-char secret is redacted after any assignment (`secret=`, `password=`,
  `token:`, `aws_secret_access_key=`, `AWS_SECRET_KEY = "`, `--aws-secret-access-key `, `aws secret access key: `) and when
  bare (any 40-char base64-alphabet token with upper and lower case and a digit, `/` or `+`; lower-case hex SHAs never match).
- `sentinel/store.py`: `SQLiteStore` (incidents, actions, hash-chained audit, cache).
  Writes run in `BEGIN IMMEDIATE` transactions with a 10 s busy timeout, so the audit chain head read + append,
  action numbering and `upsert_incident` (returns True only for the writer that created the row, which alone
  audits `incident_opened`) stay atomic across connections and processes. `python -m sentinel` also holds an
  exclusive `flock` on `<SENTINEL_VAR_DIR>/sentinel.lock`; a second server on the same var dir exits before startup.
- `sentinel/aws/session.py`: `AwsSessionFactory(settings)` with `.client(service, region=None)`,
  `.status(refresh=False) -> AwsStatus` (`.connected`, `.account_suffix`, `.label`, `.to_dict()`), `.mark_failure(exc)`,
  plus `safe_reason(exc)` and `is_credentials_error(exc)`.
  The STS probe behind `status()` is bounded (`client_config("sts")`: 2 s connect, 4 s read, 2 attempts) so a network that
  silently drops packets reaches the offline fallback in ~5 s instead of holding startup ~25 s. It is single-flight: while
  one thread probes, other callers get the previous (stale) status; only a caller with no status yet waits. A credentials
  failure (`is_credentials_error`, incl. NoCredentials/ProfileNotFound) in `status()` or `mark_failure()` drops the cached
  session and clients, so credentials or a profile added after an offline start are seen on the next refresh.

## Hard rules
1. Never print, log or return AWS credentials. Only the account's last 4 digits are shown. Use the boto3 default chain
   (`AWS_PROFILE=sentinel-app`) and never pass keys explicitly.
2. Everything that leaves the process (Bedrock prompts, API responses, reports, audit) goes through `mask_obj`.
3. A real key ID never goes in the repo, `.env.example`, tests or data files. The offline synthetic leaked key is
   AWS's documented example `AKIAIOSFODNN7EXAMPLE`. The live key ID is read at runtime from `DEMO_LEAKED_ACCESS_KEY_ID`.
4. The agent (LLM) can only PROPOSE actions. Execution happens only via the human approve endpoint.
5. A real AWS write (iam:UpdateAccessKey) happens only when ALL hold: a human approved it, `settings.allow_real_actions`,
   the target user is in `settings.real_action_user_allowlist`, the incident `data_mode` is `"live"`, and AWS is connected.
   Otherwise the action is simulated, and the result says why.
6. Every external call is wrapped in `trace.span(...)` with `target="aws"` for real AWS or `"offline"` for fallback/mock.
7. Each component falls back independently and records the reason (see `DataSources.fallbacks`).
8. Offline mode (`SENTINEL_MODE=offline`) must never touch AWS or the network, because CI runs this way.

## Synthetic data: `sentinel/datasets.py` + `data/` (owner: DATA)
```
OFFLINE_LEAKED_KEY = "AKIAIOSFODNN7EXAMPLE"
ANCHOR = "2026-11-20T12:00:00Z"   # authored timestamps are relative to this
def data_path(rel: str, settings=None) -> Path
def load_records(rel: str, settings=None) -> list[dict]        # .json (list) or .jsonl
def shift_records(records, now=None, anchor=ANCHOR, lead_minutes=30, fields=("ts","eventTime","created_at","EventTime")) -> list[dict]
    # deep-copies records, shifting every listed ISO field by (now - lead_minutes - anchor)
def synthetic_alerts(now=None, live_key: str | None = None, flagged_at: str | None = None) -> list[dict]
    # GitHub alerts. The INC-001 alert's access_key_id is the placeholder "{{DEMO_LEAKED_ACCESS_KEY_ID}}" in the file,
    # replaced by live_key or OFFLINE_LEAKED_KEY. flagged_at overrides that alert's created_at.
def synthetic_cloudtrail_records(now=None) -> list[dict]      # CloudTrail record JSON (the inner "CloudTrailEvent" detail)
def synthetic_auth_records(now=None) -> list[dict]            # app auth log records (schema below)
def app_auth_simulation_records(now) -> list[dict]            # INC-002 + arjun records for simulate_app_auth.py, simulated=True
def list_dataset_names(settings=None) -> list[str]            # relative paths under data/, e.g. "cloudtrail/events.json"
```
Files: `data/github/secret_scanning_alerts.json`, `data/cloudtrail/events.json`, `data/auth/app_auth.jsonl`,
`data/identity/users.json`, plus a little realistic background noise (benign CloudTrail and app-auth events, and a second
already-resolved GitHub alert for a different example key with no usage).

App auth record schema (one JSON object per CloudWatch log event):
`{"ts","event": "login_failed"|"login_success"|"mfa_challenge"|"mfa_success"|"mfa_failed"|"logout","user","ip","geo","user_agent","app":"sentinel-demo-app","reason","simulated":true,"scenario":"INC-002"|"benign-arjun"|"background","source":"simulated-app-traffic"}`

Scenarios:
- **INC-001 (critical)**: a GitHub secret-scanning alert flags key K in repo `acme-payments/billing-service`, file `config/settings.py`.
  The CloudTrail uses of K come from user `sentinel-demo-victim` at a foreign IP (synthetic only):
  GetCallerIdentity (success), ListBuckets, iam:ListAttachedUserPolicies, iam:CreateAccessKey, and
  iam:AttachUserPolicy with AdministratorAccess on itself (all `errorCode` AccessDenied). The IAM and STS records have
  `awsRegion` us-east-1 and the S3 record ap-south-1.
- **INC-002 (high)**: a brute force on app user `priya`. 18 `login_failed` events from 185.220.101.47 within about 4 minutes,
  then a `login_success`, then `mfa_challenge` and `mfa_failed` (MFA blocked the takeover).
- **benign-arjun**: arjun logs in from a new laptop. One `login_failed` (typo), then `login_success` and `mfa_success`
  from an Indian IP during work hours. No incident: it is suppressed with a reason.

## MCP servers: `sentinel/mcp_servers/*.py` (owner: DATA)
Each runs with `python -m sentinel.mcp_servers.<module>` over stdio, uses `MCPServer("<name>")` and `@mcp.tool()`,
returns JSON dicts, and gets its backend from env `SENTINEL_BACKEND` (`aws`|`offline`, default `offline`) plus `load_settings()`.
Servers must never write to stdout except through MCP (logging goes to stderr).
- `github_mock` ("GitHub MCP (mock)"): `list_secret_scanning_alerts(state: str = "open", offline: bool | None = None) -> {"alerts": [...], "backend": "mock", "key_source": "env"|"offline"}`.
  "Live" means `offline` is false and `SENTINEL_MODE` is not offline; when `offline` is omitted (None) it means the backend is aws
  (the hub fixes `SENTINEL_BACKEND` at startup, so `DataSources` always passes `offline` explicitly and a hub built while AWS was
  down still follows AWS once it connects). When live and `DEMO_LEAKED_ACCESS_KEY_ID` is set, use the live key with
  flagged_at = `DEMO_LEAK_FLAGGED_AT` or (now - `CLOUDTRAIL_LOOKBACK_HOURS`). Otherwise use the offline key with shifted synthetic times.
- `cloudtrail_mock` ("CloudTrail MCP (mock)"): `lookup_events(start_time=None, end_time=None, attribute_key=None, attribute_value=None, max_results=None, next_token=None, region="us-east-1")`.
  It has the SAME signature and result shape as the AWS Labs `awslabs.cloudtrail-mcp-server` tool:
  `{"events": [{"EventId","EventName","ReadOnly","AccessKeyId","EventTime": ISO str,"EventSource","Username","Resources": [],"CloudTrailEvent": "<json string>"}], "next_token": None, "query_params": {...}}`.
  It filters by region (record `awsRegion`), time window (accepts ISO or "N hours/days ago"), and attribute.
- `identity` ("Identity MCP"): `filter_auth_events(user=None, start_time=None, end_time=None, outcome=None, limit=500)`
  returns `{"events": [auth records], "backend": "cloudwatch-logs"|"offline", "live": bool, "log_group": str, "fallback_reason": str|None}`.
  With the aws backend it uses CloudWatch Logs `FilterLogEvents` on `settings.auth_log_group` (paginated). A JSON filter pattern
  such as `{ $.user = "priya" || $.user = "Priya" }` is used when user is given (the user match is case-insensitive on every
  path: the pattern ORs the given, lower-case and capitalised spellings, and records are re-checked client-side with
  `.lower()`). On failure it returns offline records with fallback_reason.
  Also `get_user(username) -> {"user": {...}|None}` and `list_users() -> {"users": [...]}` from `data/identity/users.json`.
- `logs` ("Logs MCP"): `list_datasets()` and `read_dataset(name, limit=200, contains=None)` return
  `{"records"|"datasets": ..., "backend": "s3"|"offline", "live": bool, "fallback_reason": ...}`. With the aws backend
  they read `s3://{S3_BUCKET}/raw/<name>` and otherwise `data/<name>`. Reject `..` and absolute paths.
  An unknown (well-formed) dataset name is not an error: `read_dataset` returns `records: []`, `total: 0` and
  `"error": "unknown dataset ...; call list_datasets"` (live/backend "s3" when S3 answered NoSuchKey), never a local path.
  `DataSources.read_dataset` turns that into a `ValueError` for the agent without noting a "logs" fallback.

## AWS adapters: `sentinel/aws/*.py` (owner: SOURCES, except bedrock.py=AGENT and iam_actions.py=ACTIONS)
- `cloudtrail_direct.py`: `lookup_events_direct(aws, region, attribute_key, attribute_value, start, end, max_events=200) -> list[dict]`
  returns AWS Labs-shaped raw events through boto3 pagination. It is used when the AWS Labs MCP server can't start.
- `cloudwatch.py`: `filter_auth_events(aws, log_group, start_ms, end_ms, user=None, limit=500) -> list[dict]` (the newest `limit`, sorted),
  `ensure_log_group(aws, log_group, retention_days=7)`, and `put_auth_events(aws, log_group, stream, records) -> int`
  (sorted, batched at 1 MB / 10k, creates the stream).
- `s3.py`: `put_text(aws, bucket, key, body, content_type="text/plain") -> str` (s3 uri, SSE-S3),
  `get_text(aws, bucket, key) -> str`, `list_keys(aws, bucket, prefix) -> list[dict]` (key, size, last_modified).

## MCP hub: `sentinel/mcp_hub.py` (owner: SOURCES)
```
class MCPError(Exception)
class MCPHub:
    def __init__(self, settings, base_env: dict | None = None)
    def register(self, name: str, command: list[str], *, label: str, env: dict | None = None) -> None
    def is_registered(self, name) -> bool
    async def call(self, name: str, tool: str, args: dict, timeout: float = 45) -> dict   # parsed JSON of content[0].text; raises MCPError on is_error/timeout/spawn failure
    async def list_tools(self, name: str) -> list[dict]
    def info(self) -> list[dict]   # [{name,label,command,running,last_error}]
    async def close(self) -> None
def build_hub(settings, aws_live: bool) -> MCPHub
```
Each server gets one long-lived worker task that holds `stdio_client` and `ClientSession` open and serves requests from an
`asyncio.Queue`. This keeps anyio context enter and exit in the same task. Servers start lazily on first call, and the hub
restarts a server once after it crashes. `build_hub` registers `github`, `cloudtrail_mock`, `identity` and `logs` (all
`[sys.executable, "-m", "sentinel.mcp_servers.X"]` with `SENTINEL_BACKEND` set to `aws` if aws_live else `offline`, and
`PYTHONPATH` set to the repo root). When aws_live is true and the first token of `settings.cloudtrail_mcp_command` is on PATH
(also check `.venv/bin`), it also registers `cloudtrail`, the AWS Labs server (`shlex.split(command)`, env passes `AWS_REGION`
`FASTMCP_LOG_LEVEL=ERROR` and `LOGURU_LEVEL=ERROR`; its loguru logger otherwise prints every lookup's params, including the
full leaked key ID, to the shared stderr at INFO). `hub.aws_live` records the backend it was wired for; when AWS connects
(or drops) after startup, `rewire_hub(hub, live)` (called by `DataSources._is_live()` and `/api/status`) re-registers the
local servers with the new `SENTINEL_BACKEND`, stops the running children (they restart lazily with the new env) and
registers/unregisters the AWS Labs server. SentinelAI's own servers inherit os.environ; the AWS Labs server is third-party code and gets
only `third_party_env()` (AWS_*, UV_*, XDG_*, LC_*, PATH/HOME/USER/TMPDIR/LANG, TLS and proxy vars) plus its own env, never
ELEVENLABS_API_KEY, DEMO_* or PYTHONPATH; credentials are never injected. The default command pins the tested release
(`uvx awslabs.cloudtrail-mcp-server@0.1.2`, `config.DEFAULT_CLOUDTRAIL_MCP_COMMAND`), never `@latest`.

## Data sources facade: `sentinel/sources.py` + `sentinel/normalize.py` (owner: SOURCES)
```
def normalize_cloudtrail(raw: dict, region: str, live: bool) -> Event
    # parses CloudTrailEvent JSON. outcome "denied" for AccessDenied*/UnauthorizedOperation/*Unauthorized*, "failure" for any other errorCode, else "success".
    # id = EventId, kind = EventName, actor = userIdentity.userName or Username, ip = sourceIPAddress,
    # access_key_id = AccessKeyId or userIdentity.accessKeyId, region = awsRegion or region, error_code,
    # summary like "iam:AttachUserPolicy (AdministratorAccess) → AccessDenied", raw = parsed detail (keep it small).
def normalize_auth(rec: dict, live: bool) -> Event   # id = sha1 of the record; outcome failure for login_failed/mfa_failed, success otherwise
def normalize_alert(d: dict) -> SecretAlert

class DataSources:
    def __init__(self, settings, hub: MCPHub, aws: AwsSessionFactory, store: SQLiteStore)
    @property
    def live(self) -> bool                      # aws.status().connected and not settings.offline_only
    fallbacks: dict[str, dict]                  # component -> {"component","reason","ts"}; cleared per component on success
    def note_fallback(self, component: str, reason: str) -> None
    async def github_alerts(self, state="open", force_offline=False) -> list[SecretAlert]
    async def cloudtrail_lookup(self, attribute_key: str, attribute_value: str, hours_back: int | None = None,
                                regions: list[str] | None = None, max_events: int = 200, force_offline=False) -> tuple[list[Event], dict]
        # meta = {"live": bool, "backend": "awslabs.cloudtrail-mcp-server"|"boto3"|"mock", "regions": [...], "fallback_reason": str|None,
        #         "partial": {region: note}, "count": int}
        # live path per region: AWS Labs MCP (paginate via next_token and query_params, 50 per page) -> boto3 direct -> mock.
        # Dedupe by EventId across regions, then sort by ts. Rate limit: one async token bucket per region (the AWS quota is
        # per account and region) at 2 req/s with capacity 1 (strict 0.5 s spacing; the AWS Labs server is started before a
        # token is taken). On ThrottlingException, back off exponentially (3 tries); the cloudtrail boto3 client has botocore
        # retries off (total_max_attempts=1) so every attempt goes through the bucket. MCPHub appends the server's error-level
        # log notifications (masked, account ids dropped) to a failed tool call's MCPError, because FastMCP replies only
        # "Error executing tool X" and the AWS Labs server reports the real error via ctx.error().
        # Pagination stops when the token runs out, max_events are collected, the server repeats a token, or after
        # ceil(max_events/50)+16 pages. A page failure after >=1 good page keeps those live pages (no restart on the next
        # backend, no mock data); any early stop is reported in meta["partial"][region] and the result is not cached.
        # Complete results are cached in store.cache for settings.cloudtrail_cache_ttl_s, keyed by (attr, value, region, hours_back, max_events).
    async def auth_events(self, user=None, hours_back=None, outcome=None, force_offline=False) -> tuple[list[Event], dict]
    async def get_user(self, username: str) -> dict | None
    async def list_datasets(self) -> tuple[list[str], dict]
    async def read_dataset(self, name: str, limit=200, contains=None) -> tuple[list[dict], dict]
```
Trace labels: "GitHub MCP", "CloudTrail MCP", "Identity MCP", "Logs MCP". `target` is "aws" when the data really came from
AWS, otherwise "offline". `summary` reads like "7 events" or "3 alerts".

## Rule engine + pipeline: `sentinel/engine.py`, `sentinel/pipeline.py` (owner: ENGINE)
```
ESCALATION_EVENTS = {"CreateAccessKey","AttachUserPolicy","PutUserPolicy","CreateUser","AttachRolePolicy","PutRolePolicy",
                     "CreateLoginProfile","UpdateLoginProfile","AddUserToGroup","AttachGroupPolicy","CreatePolicyVersion","UpdateAssumeRolePolicy","PassRole"}
RECON_EVENTS = {"GetCallerIdentity","ListBuckets","ListAttachedUserPolicies","ListUserPolicies","GetUser","ListUsers","ListRoles","ListAccessKeys","GetAccountAuthorizationDetails","DescribeInstances"}
@dataclass class DetectionResult: incidents: list[Incident]; suppressed: list[dict]   # {"rule","entity","reason"}
def detect_leaked_key(alert: SecretAlert, events: list[Event], *, flagged_at: datetime, data_mode: str, now: datetime) -> Incident | None
def detect_bruteforce(auth_events: list[Event], *, threshold: int = 10, window_minutes: int = 10, now: datetime) -> tuple[list[Incident], list[dict]]
def detect(alerts, events_by_key: dict[str, list[Event]], auth_events, *, now, data_modes: dict[str,str] | None = None) -> DetectionResult
async def run_detection(sources, store, settings, *, now=None) -> dict
    # -> {"incidents": [Incident dicts], "suppressed": [...], "fallbacks": [...], "trace": [TraceEntry dicts], "mode": "aws"|"offline"}
```
Engine rules:
- R-LEAKED-KEY: join the alert to CloudTrail events on the access key ID. Every use AFTER flagged_at is suspicious. Count
  denied escalation attempts, especially an AdministratorAccess attach. Critical if any post-flag use. Do NOT use IP
  reputation, because the live calls come from the user's laptop. With no usage at all it is suppressed ("alert open, key unused in window").
- R-BRUTE-FORCE: ≥ threshold `login_failed` for one user in any sliding window. Critical if a success from an attacking IP
  was not stopped by MFA, high otherwise. Below threshold it is suppressed with a reason (this is how arjun is suppressed).
  When several windows tie for the most failures, the latest wins (after a rehearsal, the burst just run on stage is reported).
  Users are grouped case- and whitespace-insensitively (`strip().casefold()`), so "Alice"/"alice " cannot split one attack;
  `app_user` is the most common stripped spelling (ties: sorted first), and the id-stability key is casefolded too.
- Incident IDs are deterministic: leaked-key incidents first (INC-001, ...) in alert order, then brute force (sorted by user).
  `detect` numbers by position; `run_detection` then keeps ids stable per (rule, entity) — entity is `alert_number` for leaked
  key (so the live INC-001 and its synthetic twin share an id) and `app_user` for brute force. A stored incident's id is reused for
  the same entity, and an incident is never upserted onto an id that belongs to a different entity (it gets the next free number).
  `entities` must include `access_key_id` (full; masking happens at the edge), `iam_user`, `repository`, `alert_number` for
  leaked key and `app_user`, `attacker_ips` for brute force. `recommended_actions` use action type ids from the ACTIONS catalog.
  `counts` holds e.g. {"post_flag_uses":5,"denied":4,"escalation_attempts":2}. Evidence strings are short human sentences.
- `run_detection`: get alerts and look up CloudTrail by `AccessKeyId` for each open alert (regions = settings.cloudtrail_regions).
  If the alert carries the live demo key (`sources.live` is snapshotted before the first lookup, because a failed live call such as
  an expired session token flips it mid-run) and it has zero live events, rerun INC-001 with `force_offline=True` (offline alert
  plus mock CloudTrail), set data_mode "synthetic", and `note_fallback("cloudtrail", ...)`: when AWS answered with no events
  (meta live) the reason is "No live CloudTrail events for AKIA…XXXX in the last N h yet; Event history can lag ~15 min. Showing
  synthetic INC-001."; when the live lookup failed it is "Live CloudTrail lookup failed (<meta fallback_reason>). Showing
  synthetic INC-001." (masked). Then fetch auth events, run `detect`, upsert incidents
  into the store, call `actions.ensure_recommended(store, incident)`, and add an audit entry `incident_opened` the first time an
  incident id appears. data_mode is "live" when the CloudTrail events came from AWS (the GitHub side is always synthetic, so
  INC-001 live is effectively "mixed"; use "live" for gating purposes and say "GitHub alert synthetic" in evidence).

## Actions, IAM, reports: `sentinel/actions.py`, `sentinel/aws/iam_actions.py`, `sentinel/reports.py` (owner: ACTIONS)
```
ACTION_CATALOG = {
  "deactivate_access_key": {"title": "Deactivate leaked access key", "real_capable": True, ...},
  "resolve_github_alert": {...False}, "notify_owner": {...False},
  "force_password_reset": {...False}, "block_ip": {...False}, "revoke_sessions": {...False},
}
def propose(store, incident, action_type, *, proposed_by="rules", reason="", target=None) -> Action   # idempotent per (incident, type): returns the proposed one, or the latest one that already took effect (simulated / executed+verified; a real-capable action simulated on a live incident did NOT take effect); a failed, unverified, live-but-simulated or rejected one may be proposed again; raises ValueError when action_type is not in incident.recommended_actions or the incident lacks the action's entities (an action that does not fit never marks the incident mitigated)
def ensure_recommended(store, incident) -> list[Action]   # never resurrects proposed/settled/rejected types; re-proposes a failed or unverified real execution, or a real-capable action that was only simulated on a live incident, so it can be retried
def incident_subject(incident) -> str   # non-secret 16-hex fingerprint of (rule, access_key_id, iam_user, app_user casefolded, data_mode=="live"); stored on every new Action as `subject` ("" on legacy rows = matches any)
# One incident id can change subject between runs (the synthetic INC-001 twin with the EXAMPLE key becomes the live INC-001 with
# the real key). propose/ensure_recommended only count actions of the current subject; ensure_recommended first marks proposed
# actions of an older subject "superseded" (audit `action_superseded`; never approvable: approve -> ValueError/409, and
# real_action_gate refuses a subject mismatch), then sets the incident status to "mitigated" iff a mitigating, recommended action
# already took effect for the current subject, else "open" (audit `incident_reopened` / `incident_mitigated` on a change).
def is_human_approver(approver) -> bool   # normalised (lowercase alnum); refuses agent/bedrock/system/rules/sentinel* and other model/system names
def approver_problem(approver) -> str | None   # used by the API: empty or non-human approver -> HTTP 400
def real_action_gate(action, incident, settings, aws_connected: bool, approver: str) -> tuple[bool, list[str]]   # (run_real, reasons_if_not)
async def approve(action_id, approver, *, store, settings, aws, reports) -> Action
def reject(action_id, approver, *, store, reason="") -> Action
# iam_actions.py
def set_access_key_status(aws, user_name, access_key_id, status: str) -> dict   # UpdateAccessKey then ListAccessKeys verify (up to 3 reads, 1 s apart; IAM is eventually consistent) -> {"status","verified","checks"}
def list_access_keys(aws, user_name) -> list[dict]
# reports.py
class ReportWriter:
    def __init__(self, settings, aws)
    def write(self, incident, actions, audit, *, trigger: str, live: bool) -> dict   # {"uri","markdown_key","json_key","live"}; masked; S3 reports/<INC>/<ts>.md|.json, else var/reports/
    def list(self, live: bool) -> list[dict]
```
`write` sorts the incident's audit entries by `seq` itself (callers may pass `store.list_audit()` newest first) and keeps
the newest 25, oldest first. If the `.md` upload succeeds and the `.json` upload fails, both files are written locally
(`fallback_reason` "S3 upload failed: ..."); no delete is attempted (the IAM policy grants no `s3:DeleteObject`), and
`list` returns each key once, preferring the S3 entry.
On approve: an `action_approved` audit entry, then execution (real or simulated) with a span "IAM"/"update_access_key"
target aws, then an `action_executed`/`action_simulated`/`action_failed` audit entry with mode and reasons. Then write the
report (trigger="action_approved", in a worker thread so an S3 upload never blocks the event loop), audit `report_written`,
and set the incident status to "mitigated" when the action succeeded. A real-capable action (deactivate_access_key) that the gate
simulated on a live incident (`data_mode == "live"`) did not succeed: the real key is unchanged, so the result carries
`live_change_pending: true`, the summary says the incident stays open, and the incident is not marked mitigated. The approver name is cleaned (control/bidi characters
removed, at most 64 characters) and masked before it is stored in `decided_by` or the audit `actor`; the API answers 400
for an empty or non-human (agent/system) approver.

## Agent: `sentinel/agent/{tools.py,prompts.py,loop.py,offline.py}`, `sentinel/aws/bedrock.py` (owner: AGENT)
```
@dataclass class AgentContext: settings; store; sources; aws
TOOL_SPECS: list[dict]   # Bedrock Converse toolSpec dicts
async def run_tool(name: str, args: dict, ctx: AgentContext) -> dict    # masked, size-capped (~8 KB JSON)
class SentinelAgent:
    def __init__(self, ctx: AgentContext)
    async def ask(self, question: str, incident_id: str | None = None, history: list[dict] | None = None, voice: bool = False) -> dict
    # -> {"answer","mode":"bedrock"|"offline","model_id","fallback_reason","trace":[TraceEntry dicts],"proposed_actions":[action ids]}
# aws/bedrock.py
def converse(aws, settings, messages, system, tool_config) -> dict    # sync; adds guardrailConfig if configured
```
Tools: `list_incidents`, `get_incident`, `get_github_secret_alerts`, `lookup_cloudtrail_events(attribute_key, attribute_value, hours_back)`,
`get_auth_events(user, hours_back, outcome)`, `get_user_profile(username)`, `read_dataset(name, contains, limit)`,
`propose_remediation(incident_id, action_type, reason)` (creates a proposed action and never executes it; only the incident's recommended_actions are accepted), and `get_audit_log(limit)`.
Event lists in tool results keep the newest 30 events (with `count`, `first_seen`, `last_seen` over all of them).
Bedrock calls go through `asyncio.to_thread`, with up to `settings.bedrock_max_turns` tool rounds and a "Bedrock"/"converse" span per call
(summary: stop reason + token usage). Any Bedrock failure (no creds, AccessDenied, model not enabled, validation, throttling)
falls back to the deterministic offline agent, which calls the same `run_tool` functions so the trace stays honest.
Robustness: the bedrock-runtime client uses connect 3 s / read 25 s timeouts and at most 2 attempts, and one question
has a wall-clock budget of `settings.bedrock_deadline_s` (`BEDROCK_DEADLINE_S`, default 45, 5-300) after which the
offline answer is used. `malformed_tool_use`, `malformed_model_output` and `ModelErrorException` retry the same request
once (the garbled reply is never appended). Text is returned for end_turn/stop_sequence/guardrail_intervened/content_filtered,
with " …" for max_tokens/model_context_window_exceeded, and for a final-round `tool_use` that also carries text.
`toolResult.status` is sent only for `amazon.nova` model ids (it is optional, so other models omit it).
`BEDROCK_GUARDRAIL_ID` must be an id or ARN and `BEDROCK_GUARDRAIL_VERSION` DRAFT or a number ('draft'/'v3' are
normalised; anything else is warned at startup and fails `aws_check`). `build_system_prompt` only embeds ids matching `INC-\d{1,6}`.
Prompt-injection guards: `ask()` only puts an `incident_id` into the system prompt when it names a stored incident (canonical id);
a Bedrock answer in which the copilot claims to have approved/executed/deactivated/blocked something gets a fixed
"nothing was executed" note appended. Normalisers (`sentinel/normalize.py`) collapse control characters (newlines) in
attacker-controlled fields (alert path/repository, auth user/geo/reason/user_agent, CloudTrail userAgent...) and cap their length;
reports escape `<`/`>` and keep each data item on one line.

## Voice: `sentinel/voice.py` (owner: VOICE)
```
class VoiceUnavailable(Exception)
class VoiceService:
    def __init__(self, settings, aws)
    def status(self) -> dict      # {"provider": "elevenlabs"|"browser", "reason", "voice_id", "key_source": "env"|"secrets-manager"|None}
    async def transcribe(self, audio: bytes, filename: str, content_type: str) -> dict   # {"text","provider","ms"}
    async def speak(self, text: str) -> tuple[bytes, str]                                   # (audio, mime)
```
ElevenLabs REST via httpx: STT `POST https://api.elevenlabs.io/v1/speech-to-text` (multipart `file`, `model_id`), TTS
`POST https://api.elevenlabs.io/v1/text-to-speech/{voice_id}?output_format=mp3_44100_128` (json `text`, `model_id`), header `xi-api-key`.
The key comes from env, or from Secrets Manager when `ELEVENLABS_SECRET_ID` is set and AWS is connected. The SecretString is
either the raw key or JSON `{"ELEVENLABS_API_KEY": ...}`. The key is cached in memory and never logged. Spans: "ElevenLabs"
"speech_to_text"/"text_to_speech". Without a key, raise VoiceUnavailable so the UI falls back to the browser Web Speech API.
After ElevenLabs rejects the key (401/403) or the quota is used up (`quota_exceeded`) voice pauses for 5 minutes; after a
rate limit (429), timeout or network error for 1 minute. While paused `status()` reports `provider: "browser"` with the
reason and `last_error`, and transcribe/speak raise VoiceUnavailable without calling ElevenLabs; a 401/403 also drops a cached
Secrets Manager key so it is re-read afterwards. Error reasons echo `detail.status` only when it matches `[a-z_]{1,40}`; a TTS
response that is not `audio/*` is a failure. The UI switches to browser speech only on a 503 `{"fallback": "browser"}` (other
transcribe errors keep ElevenLabs), asks for a tap instead of starting recognition outside a gesture, and cancels in-flight
TTS (request token + AbortController) when the mic is tapped or a newer answer is spoken.

## API + UI: `sentinel/api.py`, `sentinel/__main__.py`, `web/` (owner: API)
Times are stored and sent as UTC ISO; the incident timeline renders them in UTC (header "Time (UTC)", date shown when not today)
to match the evidence, agent and voice; audit/action/report times are browser-local with the zone name.
`create_app(settings=None) -> FastAPI` wires AwsSessionFactory, SQLiteStore(settings.db_path), build_hub, DataSources,
SentinelAgent, VoiceService and ReportWriter onto `app.state`, and runs detection once in the background at startup.
`python -m sentinel` serves on 127.0.0.1:8000. Every JSON response goes through `mask_obj`.
Routes: `GET /api/status`, `POST /api/detect`, `GET /api/incidents`, `GET /api/incidents/{id}` (incident + actions),
`POST /api/chat {message, incident_id?, voice?}`, `GET /api/actions`, `POST /api/actions/{id}/approve {approver}`,
`POST /api/actions/{id}/reject {approver, reason}`, `GET /api/audit` (entries + chain_ok), `POST /api/reports/{incident_id}`,
`GET /api/reports`, `POST /api/voice/transcribe` (multipart file), `POST /api/voice/speak {text}` (audio/mpeg, or 503
`{"fallback": "browser"}`), `GET /api/voice/status`, `GET /api/trace/recent`, and static `/` → web/index.html.
`/api/status` returns `{"aws": {...AwsStatus, "label"}, "mode": "aws"|"offline", "aws_required": bool, "banner": str|None, "fallbacks": [...],
"settings": public_dict, "mcp": hub.info(), "voice": voice.status(), "bedrock": {"model_id","last_mode","last_error"}}`.
The banner is "Offline fallback" plus the reasons whenever mode is offline or any fallback is active. When offline,
fallbacks whose reason is just "AWS not connected: …" are not repeated: their components are named once after the AWS
reason ("Offline fallback — <reason> (cloudtrail, auth using offline data); other: reason").
`aws_required` is true when `SENTINEL_MODE=aws`; then a missing/broken AWS connection is an error, not a quiet fallback: the
banner reason reads "AWS required (SENTINEL_MODE=aws) but not connected: …" and the UI shows the AWS pill and banner in red.
Request bodies are capped before they are buffered (`BodyLimitMiddleware`): `POST /api/voice/transcribe` at 10 MiB of
audio plus 64 KiB multipart overhead, every other `/api/*` body at 1 MiB; a larger declared Content-Length, or a streamed
body that passes the cap, gets 413 without the rest being read, and the route never reads more than 10 MiB + 1 byte of audio.
Free-text fields are bounded too (422 above the limit): chat `message` 4000 chars (400), `history` at most 50 items (only
the last 12 are used; malformed items are skipped, never raised), approver 200 raw / 64 cleaned, reject `reason` 1000,
report `requested_by` 100 (whitespace-collapsed and masked; it becomes the audit actor). Blocking AWS work never runs on
the event loop: `aws.status()`, `voice.status()` (STS + Secrets Manager), report writes and IAM calls go through
`asyncio.to_thread`.

## Scripts, infra, docs (owner: OPS)
See the task brief: `scripts/*.py`, `infra/iam/*.json`, `docs/AWS_SETUP.md`, `README.md`, `DEMO_SCRIPT.md`, `.env.example`,
`requirements.txt`, `pyproject.toml`, `Dockerfile`, `docker-compose.yml`, `.github/workflows/ci.yml`, `Makefile`.
