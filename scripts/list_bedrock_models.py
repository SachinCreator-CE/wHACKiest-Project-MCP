#!/usr/bin/env python3
"""List Bedrock text models and inference profiles in a region and recommend BEDROCK_MODEL_ID.

Models are marked ``tool-use`` when their family is known to support Converse
tool use (the agent needs it). ``--probe MODEL_ID`` makes one tiny Converse call
with a dummy tool to prove it end to end.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts._common import (  # noqa: E402
    AWS_ERRORS,
    Out,
    app_profile,
    bedrock_probe,
    describe_error,
    init_settings,
    table,
    use_profile,
)
from sentinel.aws.session import AwsSessionFactory  # noqa: E402

TOOL_USE_FAMILIES = [
    re.compile(p)
    for p in (
        r"amazon\.nova-",
        r"meta\.llama3-[1-9]-",  # Llama 3.1+
        r"meta\.llama[4-9]",
        r"mistral\.mistral-large",
        r"cohere\.command-r",
    )
]
_GEO_PREFIX = re.compile(r"^(?:us|us-gov|eu|apac|jp|au|ca|global)\.")
USABLE_INFERENCE_TYPES = {"ON_DEMAND", "INFERENCE_PROFILE"}


def base_model_id(model_id: str) -> str:
    """``apac.amazon.nova-lite-v1:0`` -> ``amazon.nova-lite-v1:0``."""
    return _GEO_PREFIX.sub("", model_id)


def supports_tool_use(model_id: str) -> bool:
    base = base_model_id(model_id)
    return any(p.match(base) for p in TOOL_USE_FAMILIES)


def tool_use_mark(model_id: str) -> str:
    return "tool-use" if supports_tool_use(model_id) else ""


def geo_prefix(region: str) -> str:
    for prefix, geo in (("ap-", "apac."), ("us-", "us."), ("eu-", "eu.")):
        if region.startswith(prefix):
            return geo
    return ""


def recommended_model(region: str, available: set[str] | None = None) -> str:
    """Nova Lite through the region's cross-region inference profile (cheap, fast, tool use)."""
    candidate = f"{geo_prefix(region)}amazon.nova-lite-v1:0"
    if not available or candidate in available:
        return candidate
    fallback = sorted(m for m in available if "nova-lite" in m) or sorted(m for m in available if supports_tool_use(m))
    return fallback[0] if fallback else candidate


def stronger_model(region: str, available: set[str] | None = None) -> str:
    """A stronger demo model: Amazon Nova Pro through the regional inference profile."""
    return f"{geo_prefix(region)}amazon.nova-pro-v1:0"


def list_models(bedrock: Any) -> list[dict[str, Any]]:
    """ACTIVE text models invokable on demand or through an inference profile."""
    models = bedrock.list_foundation_models(byOutputModality="TEXT").get("modelSummaries", [])
    return sorted(
        (
            m
            for m in models
            if m.get("modelLifecycle", {}).get("status", "ACTIVE") == "ACTIVE"
            and USABLE_INFERENCE_TYPES & set(m.get("inferenceTypesSupported", []))
        ),
        key=lambda m: m["modelId"],
    )


def list_profiles(bedrock: Any) -> list[dict[str, Any]]:
    profiles: list[dict[str, Any]] = []
    kwargs: dict[str, Any] = {}
    while True:
        resp = bedrock.list_inference_profiles(**kwargs)
        profiles += resp.get("inferenceProfileSummaries", [])
        if not resp.get("nextToken"):
            return sorted(profiles, key=lambda p: p["inferenceProfileId"])
        kwargs["nextToken"] = resp["nextToken"]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--profile", default=None, help="app AWS CLI profile (default: AWS_PROFILE or sentinel-app; '' = default chain)")
    p.add_argument("--region", default=None, help="Bedrock region (default: BEDROCK_REGION or AWS_REGION)")
    p.add_argument("--probe", metavar="MODEL_ID", default=None, help="Converse with a dummy tool against MODEL_ID")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    settings = init_settings()
    use_profile(app_profile(args.profile))
    region = args.region or settings.bedrock_region
    aws = AwsSessionFactory(settings)
    out = Out()

    if args.probe:
        out.step(f"Probing {args.probe} in {region}")
        try:
            probe = bedrock_probe(aws.client("bedrock-runtime", region), args.probe, with_tool=True)
        except AWS_ERRORS as exc:
            out.fail(describe_error(exc))
            return 1
        (out.ok if probe.tool_used else out.warn)(
            f"stopReason={probe.stop_reason}, tool use={'yes' if probe.tool_used else 'no'}, {probe.ms} ms"
        )
        return 0 if probe.tool_used else 1

    try:
        bedrock = aws.client("bedrock", region)
        models, profiles = list_models(bedrock), list_profiles(bedrock)
    except AWS_ERRORS as exc:
        out.fail(describe_error(exc))
        return 1

    out.step(f"Foundation models in {region} (ACTIVE, ON_DEMAND or INFERENCE_PROFILE)")
    out.line(table(
        ["modelId", "provider", "inference", "converse"],
        [(m["modelId"], m.get("providerName", ""), ",".join(m.get("inferenceTypesSupported", [])), tool_use_mark(m["modelId"])) for m in models],
    ))
    out.step(f"Inference profiles in {region}")
    out.line(table(
        ["inferenceProfileId", "status", "converse"],
        [(p["inferenceProfileId"], p.get("status", ""), tool_use_mark(p["inferenceProfileId"])) for p in profiles],
    ))

    available = {p["inferenceProfileId"] for p in profiles} | {
        m["modelId"] for m in models if "ON_DEMAND" in m.get("inferenceTypesSupported", [])
    }
    out.step("Recommendation")
    out.ok(f"BEDROCK_MODEL_ID={recommended_model(region, available)}   (current: {settings.bedrock_model_id})")
    out.info(
        f"Stronger demo model in one line: BEDROCK_MODEL_ID={stronger_model(region, available)} "
        "(enable it under Bedrock → Model access; re-render the IAM policy for the new model id)"
    )
    out.info(f"Verify with: python scripts/list_bedrock_models.py --probe {recommended_model(region, available)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
