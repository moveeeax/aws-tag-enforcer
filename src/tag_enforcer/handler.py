"""The Lambda entry point: evaluate one create event and act on it."""
from __future__ import annotations

import os
from typing import Dict, Optional

from .events import parse_event
from .notify import notify
from .policy import Policy
from .tagger import apply_tags

_POLICY_CACHE: Dict[str, Policy] = {}


def _load_policy(policy: Optional[Policy]) -> Policy:
    if policy is not None:
        return policy
    path = os.environ.get("POLICY_PATH", "policy.yaml")
    if path not in _POLICY_CACHE:
        _POLICY_CACHE[path] = Policy.load(path)
    return _POLICY_CACHE[path]


def lambda_handler(event, context=None, policy: Optional[Policy] = None, session=None):
    """Handle one EventBridge resource-creation event.

    Returns a small dict describing what happened, which is easy to assert on
    in tests and shows up nicely in CloudWatch logs.
    """
    pol = _load_policy(policy)
    ref = parse_event(event)
    if ref is None:
        return {"status": "skipped", "reason": "unsupported-event"}

    if pol.services and ref.service not in pol.services:
        return {"status": "skipped", "reason": "service-not-in-scope",
                "resource": ref.resource_id}

    ev = pol.evaluate(ref.tags)
    if ev.compliant:
        return {"status": "compliant", "resource": ref.resource_id}

    applied: Dict[str, str] = {}
    if pol.mode == "enforce" and ev.to_apply:
        apply_tags(ref, ev.to_apply, session=session)
        applied = dict(ev.to_apply)

    # What is still non-compliant after we acted? In enforce mode we fixed the
    # defaultable tags, so only the unresolved ones remain. In report mode we
    # changed nothing, so the defaultable tags are still missing too.
    if pol.mode == "enforce":
        still_missing = list(ev.unresolved)
    else:
        still_missing = sorted(list(ev.to_apply.keys()) + list(ev.unresolved))

    result: Dict = {
        "status": "enforced" if applied else "flagged",
        "resource": ref.resource_id,
        "service": ref.service,
        "missing": still_missing,
        "applied": applied,
        "notified": [],
    }

    if still_missing:
        result["notified"] = notify(pol, ref, still_missing, applied, session=session)

    return result
