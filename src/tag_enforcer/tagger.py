"""Apply tags to a live AWS resource.

boto3 is imported lazily inside the call so that importing this module -- and
the whole policy engine -- never requires boto3 to be installed. The Lambda
runtime ships boto3; local unit tests inject a fake session instead.
"""
from __future__ import annotations

from typing import Dict, Optional

from .events import ResourceRef


def _session(session):
    if session is not None:
        return session
    import boto3  # lazy: only needed when we actually talk to AWS

    return boto3.Session()


def apply_tags(ref: ResourceRef, tags: Dict[str, str], session=None) -> None:
    """Add ``tags`` to the resource described by ``ref``.

    EC2 and S3 have bespoke tagging APIs; everything else goes through the
    Resource Groups Tagging API by ARN, which covers most taggable services.
    """
    if not tags:
        return
    sess = _session(session)
    if ref.service == "ec2":
        client = sess.client("ec2", region_name=ref.region)
        client.create_tags(
            Resources=[ref.resource_id],
            Tags=[{"Key": k, "Value": v} for k, v in tags.items()],
        )
    elif ref.service == "s3":
        client = sess.client("s3")
        merged = dict(ref.tags)
        merged.update(tags)
        client.put_bucket_tagging(
            Bucket=ref.resource_id,
            Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in merged.items()]},
        )
    else:
        if not ref.arn:
            raise ValueError("cannot tag %s without an ARN" % ref.resource_id)
        client = sess.client("resourcegroupstaggingapi", region_name=ref.region)
        client.tag_resources(ResourceARNList=[ref.arn], Tags=dict(tags))
