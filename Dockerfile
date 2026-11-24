# SentinelAI container. Credentials come from the EC2 instance role (or any boto3
# default-chain source); no keys are ever baked into the image.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SENTINEL_NO_DOTENV=1 \
    HOME=/home/sentinel \
    UV_CACHE_DIR=/home/sentinel/.cache/uv

WORKDIR /app

# uv provides `uvx`, which launches the AWS Labs CloudTrail MCP server on demand.
COPY requirements.txt .
RUN pip install -r requirements.txt "uv>=0.5,<1"

RUN useradd --create-home --home-dir /home/sentinel --uid 10001 sentinel
COPY --chown=sentinel:sentinel . .
RUN mkdir -p /app/var && chown sentinel:sentinel /app/var

USER sentinel
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/status', timeout=4)"

CMD ["python", "-m", "sentinel", "--host", "0.0.0.0", "--port", "8000"]
