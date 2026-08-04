"""Normalize AWS resource-creation events into a :class:`ResourceRef`.

Real create events reach EventBridge as CloudTrail ``AWS API Call`` records.
The shape of the interesting fields differs per service, so each supported
service gets a small extractor. Anything we do not understand returns ``None``
and the handler skips it -- better to ignore an event than to guess wrong.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

# EventBridge ``source`` -> short service name we use everywhere else.
_SOURCE_SERVICE = {
    "aws.ec2": "ec2",
    "aws.s3": "s3",
    "aws.rds": "rds",
}


@dataclass
class ResourceRef:
    service: str
    region: str
    account_id: str
    resource_id: str
    resource_type: str
    arn: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)


def _tags_from_list(items) -> Dict[str, str]:
    """CloudTrail encodes tags as ``[{"key": .., "value": ..}, ...]``."""
    out: Dict[str, str] = {}
    for item in items or []:
        key = item.get("key") or item.get("Key")
        if key is not None:
            out[key] = item.get("value") or item.get("Value") or ""
    return out


def _from_run_instances(detail, region, account) -> Optional[ResourceRef]:
    resp = detail.get("responseElements") or {}
    items = (resp.get("instancesSet") or {}).get("items") or []
    if not items:
        return None
    instance_id = items[0].get("instanceId")
    if not instance_id:
        return None
    tags: Dict[str, str] = {}
    for spec in (detail.get("requestParameters") or {}).get(
        "tagSpecificationSet", {}
    ).get("items", []):
        tags.update(_tags_from_list(spec.get("tags")))
    return ResourceRef(
        service="ec2",
        region=region,
        account_id=account,
        resource_id=instance_id,
        resource_type="instance",
        arn="arn:aws:ec2:%s:%s:instance/%s" % (region, account, instance_id),
        tags=tags,
    )


def _from_create_bucket(detail, region, account) -> Optional[ResourceRef]:
    name = (detail.get("requestParameters") or {}).get("bucketName")
    if not name:
        return None
    return ResourceRef(
        service="s3",
        region=region,
        account_id=account,
        resource_id=name,
        resource_type="bucket",
        arn="arn:aws:s3:::%s" % name,
        tags={},  # CreateBucket never carries tags inline.
    )


def _from_create_db_instance(detail, region, account) -> Optional[ResourceRef]:
    resp = detail.get("responseElements") or {}
    arn = resp.get("dBInstanceArn")
    db_id = resp.get("dBInstanceIdentifier") or (
        detail.get("requestParameters") or {}
    ).get("dBInstanceIdentifier")
    if not db_id:
        return None
    tags = _tags_from_list((detail.get("requestParameters") or {}).get("tags"))
    return ResourceRef(
        service="rds",
        region=region,
        account_id=account,
        resource_id=db_id,
        resource_type="db",
        arn=arn or "arn:aws:rds:%s:%s:db:%s" % (region, account, db_id),
        tags=tags,
    )


# eventName -> extractor.
_EXTRACTORS: Dict[str, Callable] = {
    "RunInstances": _from_run_instances,
    "CreateBucket": _from_create_bucket,
    "CreateDBInstance": _from_create_db_instance,
}


def parse_event(event: Dict) -> Optional[ResourceRef]:
    """Turn a raw EventBridge event into a :class:`ResourceRef`, or ``None``."""
    if not isinstance(event, dict):
        return None
    detail = event.get("detail") or {}
    event_name = detail.get("eventName")
    extractor = _EXTRACTORS.get(event_name)
    if extractor is None:
        return None
    region = event.get("region") or detail.get("awsRegion") or ""
    account = event.get("account") or detail.get("recipientAccountId") or ""
    return extractor(detail, region, account)


def supported_events() -> Dict[str, str]:
    """Map of supported eventName -> service (handy for docs/tests)."""
    return {"RunInstances": "ec2", "CreateBucket": "s3", "CreateDBInstance": "rds"}
