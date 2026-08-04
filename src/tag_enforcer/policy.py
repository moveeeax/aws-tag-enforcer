"""The required-tag policy engine.

A :class:`Policy` is loaded from YAML/JSON and evaluates a resource's existing
tags against a list of mandatory tags. The evaluation is a pure function -- no
AWS calls -- which is what makes the whole thing easy to unit test.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import yaml

VALID_MODES = ("report", "enforce")


@dataclass
class Evaluation:
    """The result of checking one resource's tags against a policy."""

    compliant: bool
    #: required tags that are missing and have no default we can fill in.
    unresolved: List[str]
    #: required tags we can satisfy by applying a policy default.
    to_apply: Dict[str, str]
    #: the tags the resource already carries.
    present: Dict[str, str]

    @property
    def flagged(self) -> bool:
        """True when the resource cannot be made compliant automatically."""
        return bool(self.unresolved)


@dataclass
class Policy:
    required_tags: List[str]
    defaults: Dict[str, str] = field(default_factory=dict)
    mode: str = "report"
    services: List[str] = field(default_factory=list)
    sns_topic_arn: Optional[str] = None
    slack_webhook_url: Optional[str] = None

    def __post_init__(self) -> None:
        if self.mode not in VALID_MODES:
            raise ValueError(
                "mode must be one of %s, got %r" % (VALID_MODES, self.mode)
            )
        if not self.required_tags:
            raise ValueError("required_tags must not be empty")

    # -- loading ---------------------------------------------------------
    @classmethod
    def from_dict(cls, data: Dict) -> "Policy":
        notify = data.get("notify", {}) or {}
        return cls(
            required_tags=list(data["required_tags"]),
            defaults=dict(data.get("defaults", {}) or {}),
            mode=str(data.get("mode", "report")),
            services=list(data.get("services", []) or []),
            sns_topic_arn=notify.get("sns_topic_arn"),
            slack_webhook_url=notify.get("slack_webhook_url"),
        )

    @classmethod
    def load(cls, path: str) -> "Policy":
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        # yaml.safe_load parses JSON too, but be explicit for .json files.
        data = json.loads(text) if path.endswith(".json") else yaml.safe_load(text)
        if not isinstance(data, dict):
            raise ValueError("policy file must contain a mapping at the top level")
        return cls.from_dict(data)

    # -- evaluation ------------------------------------------------------
    def evaluate(self, tags: Optional[Dict[str, str]]) -> Evaluation:
        """Check ``tags`` against the policy.

        A tag counts as present only when it is set to a non-empty value, so an
        ``Owner=""`` tag is treated the same as a missing one.
        """
        present = {k: v for k, v in (tags or {}).items() if str(v).strip()}
        to_apply: Dict[str, str] = {}
        unresolved: List[str] = []
        for tag in self.required_tags:
            if tag in present:
                continue
            if tag in self.defaults:
                to_apply[tag] = self.defaults[tag]
            else:
                unresolved.append(tag)
        compliant = not to_apply and not unresolved
        return Evaluation(
            compliant=compliant,
            unresolved=unresolved,
            to_apply=to_apply,
            present=present,
        )
