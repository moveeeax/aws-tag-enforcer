"""Flag a non-compliant resource to SNS and/or Slack."""
from __future__ import annotations

import json
from typing import Dict, List, Optional

from .events import ResourceRef
from .policy import Policy


def format_alert(
    ref: ResourceRef,
    missing: List[str],
    applied: Dict[str, str],
    mode: str,
    invalid: Optional[Dict[str, str]] = None,
) -> str:
    lines = [
        "Non-compliant AWS resource: %s (%s/%s)"
        % (ref.resource_id, ref.service, ref.resource_type),
        "Region: %s  Account: %s" % (ref.region, ref.account_id),
    ]
    if ref.principal and ref.principal.arn:
        lines.append("Created by: %s" % ref.principal.arn)
    if missing:
        lines.append("Missing required tags: %s" % ", ".join(missing))
    if invalid:
        lines.append(
            "Invalid tag values: %s"
            % ", ".join("%s=%s" % kv for kv in sorted(invalid.items()))
        )
    lines.append("Mode: %s" % mode)
    if applied:
        lines.append(
            "Auto-applied tags: %s"
            % ", ".join("%s=%s" % kv for kv in sorted(applied.items()))
        )
    return "\n".join(lines)


def notify(
    policy: Policy,
    ref: ResourceRef,
    missing: List[str],
    applied: Dict[str, str],
    session=None,
    invalid: Optional[Dict[str, str]] = None,
) -> List[str]:
    """Send an alert to every configured channel; return the channels used."""
    message = format_alert(ref, missing, applied, policy.mode, invalid=invalid)
    sent: List[str] = []

    if policy.sns_topic_arn:
        sess = session
        if sess is None:
            import boto3  # lazy

            sess = boto3.Session()
        sess.client("sns", region_name=ref.region or None).publish(
            TopicArn=policy.sns_topic_arn,
            Subject="aws-tag-enforcer: %s" % ref.resource_id,
            Message=message,
        )
        sent.append("sns")

    if policy.slack_webhook_url:
        _post_slack(policy.slack_webhook_url, message)
        sent.append("slack")

    return sent


def _post_slack(webhook_url: str, message: str) -> None:
    import urllib.request  # stdlib -- no extra dependency

    payload = json.dumps({"text": message}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=payload, headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req, timeout=5).close()
