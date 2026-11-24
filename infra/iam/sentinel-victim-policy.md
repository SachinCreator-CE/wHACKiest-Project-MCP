# `sentinel-demo-victim`: no policies, on purpose

The demo victim is an IAM user with **no permissions at all**:

- no inline policies
- no attached managed policies
- no group memberships
- no console password (no login profile)
- exactly **one** access key, stored only in the local `sentinel-victim` AWS CLI profile

That key is the "leaked" key for INC-001. `scripts/simulate_leaked_key.py` uses it to make
real API calls. Every call except `sts:GetCallerIdentity` is denied, because
GetCallerIdentity needs no permission. The denied calls still create real CloudTrail
events (`errorCode: AccessDenied`), and SentinelAI investigates those events.

There is no JSON policy file for this user because the safe policy is no policy. Adding any
permission, even a read-only one, would make the demo key a real risk.

## Verify it (as an admin)

```bash
aws iam list-attached-user-policies --user-name sentinel-demo-victim   # -> "AttachedPolicies": []
aws iam list-user-policies          --user-name sentinel-demo-victim   # -> "PolicyNames": []
aws iam list-groups-for-user        --user-name sentinel-demo-victim   # -> "Groups": []
aws iam list-access-keys            --user-name sentinel-demo-victim   # -> exactly one key
```

## Built-in safety nets

- `simulate_leaked_key.py` stops before any other call unless the caller ARN is exactly
  `user/sentinel-demo-victim`, so it can't run with the wrong profile.
- If `CreateAccessKey` or `AttachUserPolicy` ever **succeeds**, the script deletes the new
  key or detaches the policy straight away, prints a loud warning and exits non-zero.
- The only principal that can change this user is `sentinel-app`, and its policy only allows
  `iam:UpdateAccessKey` and `iam:ListAccessKeys` on this one user ARN (statement
  `IamDemoVictimKeyOnly`). That is just enough to deactivate the leaked key after a human
  approves it, and to reactivate it with `scripts/reset_demo_victim.py`.
