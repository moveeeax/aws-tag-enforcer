"""Command-line interface for local, offline policy checks.

Neither subcommand touches AWS -- they run the same pure evaluation the Lambda
uses, so you can validate a policy against a tag set or a captured event in CI
or a pre-commit hook.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, List, Optional

from .events import Principal, parse_event
from .policy import Evaluation, Policy


def _parse_tags(pairs: Optional[str]) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    for pair in (pairs or "").split(","):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            raise ValueError("bad tag %r, expected KEY=VALUE" % pair)
        key, value = pair.split("=", 1)
        tags[key.strip()] = value.strip()
    return tags


def _report(ev: Evaluation) -> Dict:
    return {
        "compliant": ev.compliant,
        "unresolved": ev.unresolved,
        "to_apply": ev.to_apply,
        "invalid": ev.invalid,
        "to_fix": ev.to_fix,
        "extra_tags": ev.extra_tags,
    }


def _cmd_check(args) -> int:
    policy = Policy.load(args.policy)
    context: Dict[str, str] = {}
    if args.principal:
        context.update(Principal.from_arn(args.principal).values())
    if args.event_time:
        context["event.time"] = args.event_time
    ev = policy.evaluate(_parse_tags(args.tags), context)
    report = _report(ev)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if ev.compliant else 1


def _cmd_eval_event(args) -> int:
    policy = Policy.load(args.policy)
    with open(args.event, "r", encoding="utf-8") as fh:
        event = json.load(fh)
    ref = parse_event(event)
    if ref is None:
        print(json.dumps({"status": "skipped", "reason": "unsupported-event"}))
        return 0
    ev = policy.evaluate(ref.tags, ref.derive_values())
    report = _report(ev)
    report.update({"resource": ref.resource_id, "service": ref.service})
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if ev.compliant else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tag-enforcer",
        description="Check AWS tags against a required-tag policy (offline).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="check a KEY=VALUE tag set")
    p_check.add_argument("--policy", required=True, help="path to policy.yaml")
    p_check.add_argument("--tags", default="", help="comma-separated KEY=VALUE tags")
    p_check.add_argument(
        "--principal",
        help="creator IAM/STS ARN, feeds principal.* derived tags",
    )
    p_check.add_argument(
        "--event-time",
        help="creation time (ISO 8601), feeds event.time derived tags",
    )
    p_check.set_defaults(func=_cmd_check)

    p_event = sub.add_parser("eval-event", help="evaluate a captured EventBridge event")
    p_event.add_argument("--policy", required=True, help="path to policy.yaml")
    p_event.add_argument("--event", required=True, help="path to an event JSON file")
    p_event.set_defaults(func=_cmd_eval_event)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
