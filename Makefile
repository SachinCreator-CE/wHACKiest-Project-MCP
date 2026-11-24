# SentinelAI developer shortcuts. AWS targets use AWS_PROFILE (default sentinel-app).
PY ?= .venv/bin/python
OFFLINE_ENV = SENTINEL_MODE=offline SENTINEL_NO_DOTENV=1

.PHONY: venv run offline test policy models aws-setup aws-check simulate simulate-auth reset reset-local teardown

venv: ## create .venv and install dependencies
	python3 -m venv .venv
	.venv/bin/pip install -r requirements-dev.txt

run: ## start the app (AWS when credentials work, offline fallback otherwise)
	$(PY) -m sentinel

offline: ## start the app fully offline (no AWS, no network); own store in var/offline so rehearsals never touch the live demo's
	$(OFFLINE_ENV) SENTINEL_VAR_DIR=var/offline $(PY) -m sentinel

test: ## run the test suite offline
	$(OFFLINE_ENV) $(PY) -m pytest -q

policy: ## render the least-privilege IAM policy
	$(PY) scripts/render_iam_policy.py

models: ## list Bedrock models / inference profiles and the recommended BEDROCK_MODEL_ID
	$(PY) scripts/list_bedrock_models.py

aws-setup: ## create bucket, upload data, log group, simulated auth traffic, Bedrock test
	$(PY) scripts/aws_setup.py

aws-check: ## green/red readiness checklist
	$(PY) scripts/aws_check.py

simulate: ## real denied CloudTrail events with the leaked demo key (run ~15 min before the demo)
	$(PY) scripts/simulate_leaked_key.py

simulate-auth: ## write simulated app-auth traffic to CloudWatch Logs
	$(PY) scripts/simulate_app_auth.py

reset: ## reactivate the demo victim's key and move var/sentinel.db aside (stop the app first)
	$(PY) scripts/reset_demo_victim.py

reset-local: ## only move the local store aside (var/sentinel.db and var/offline/sentinel.db); no AWS
	$(PY) scripts/reset_demo_victim.py --local-only
	SENTINEL_VAR_DIR=var/offline $(PY) scripts/reset_demo_victim.py --local-only

teardown: ## delete the bucket and log group (asks for confirmation)
	$(PY) scripts/aws_teardown.py
