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
class Principal:
    """Who made the API call, taken from CloudTrail ``userIdentity``."""

    type: str = ""
    arn: str = ""
    account_id: str = ""
    #: a human-meaningful name: the IAM user name, the session name of an
    #: assumed role (for IAM Identity Center users that is the user name,
    #: usually the email), the federated user name, or ``root``.
    user: str = ""

    @classmethod
    def from_identity(cls, identity) -> Optional["Principal"]:
        if not isinstance(identity, dict) or not identity:
            return None
        ptype = identity.get("type") or ""
        arn = identity.get("arn") or ""
        if ptype == "Root":
            user = "root"
        elif ptype == "IAMUser":
            user = identity.get("userName") or _arn_tail(arn)
        elif ptype in ("AssumedRole", "FederatedUser"):
            # arn:aws:sts::<acct>:assumed-role/<role>/<session> -- the session
            # name is the last segment; principalId is "<id>:<session>".
            principal_id = identity.get("principalId") or ""
            user = _arn_tail(arn) or principal_id.rpartition(":")[2]
        elif ptype == "AWSService":
            # A service acting on its own: no person to put in Owner.
            user = ""
        else:
            user = identity.get("userName") or ""
        return cls(
            type=ptype,
            arn=arn,
            account_id=identity.get("accountId") or "",
            user=user,
        )

    @classmethod
    def from_arn(cls, arn: str) -> "Principal":
        """Build a principal from an IAM/STS ARN (for offline ``check``)."""
        parts = (arn or "").split(":", 5)
        if len(parts) != 6 or parts[0] != "arn":
            raise ValueError("bad principal ARN %r" % arn)
        service, account, resource = parts[2], parts[4], parts[5]
        if service == "iam" and resource == "root":
            return cls(type="Root", arn=arn, account_id=account, user="root")
        if service == "iam" and resource.startswith("user/"):
            ptype = "IAMUser"
        elif service == "sts" and resource.startswith("assumed-role/"):
            ptype = "AssumedRole"
        elif service == "sts" and resource.startswith("federated-user/"):
            ptype = "FederatedUser"
        else:
            raise ValueError(
                "unsupported principal ARN %r (want an IAM user, root, "
                "assumed-role or federated-user ARN)" % arn
            )
        return cls(type=ptype, arn=arn, account_id=account, user=_arn_tail(arn))

    def values(self) -> Dict[str, str]:
        """This principal as ``principal.*`` derived sources (non-empty only)."""
        raw = {
            "principal.user": self.user,
            "principal.arn": self.arn,
            "principal.account": self.account_id,
            "principal.type": self.type,
        }
        return {k: v for k, v in raw.items() if v}


def _arn_tail(arn: str) -> str:
    """Last path segment of an ARN's resource part ("" if there is none)."""
    resource = (arn or "").split(":", 5)[-1]
    return resource.rsplit("/", 1)[1] if "/" in resource else ""


@dataclass
class ResourceRef:
    service: str
    region: str
    account_id: str
    resource_id: str
    resource_type: str
    arn: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    principal: Optional[Principal] = None
    #: CloudTrail ``eventTime`` (ISO 8601, UTC), e.g. ``2026-11-05T09:30:00Z``.
    event_time: Optional[str] = None

    def derive_values(self) -> Dict[str, str]:
        """Values for the policy's ``derived`` sources, keyed by source name."""
        out = self.principal.values() if self.principal else {}
        if self.event_time:
            out["event.time"] = self.event_time
        return out


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
    ref = extractor(detail, region, account)
    if ref is not None:
        ref.principal = Principal.from_identity(detail.get("userIdentity"))
        ref.event_time = detail.get("eventTime") or event.get("time") or None
    return ref


def supported_events() -> Dict[str, str]:
    """Map of supported eventName -> service (handy for docs/tests)."""
    return {"RunInstances": "ec2", "CreateBucket": "s3", "CreateDBInstance": "rds"}
