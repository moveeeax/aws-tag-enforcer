"""The required-tag policy engine.

A :class:`Policy` is loaded from YAML/JSON and evaluates a resource's existing
tags against a list of mandatory tags, optional value rules, and values derived
from the creating event. The evaluation is a pure function -- no AWS calls --
which is what makes the whole thing easy to unit test.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import yaml

VALID_MODES = ("report", "enforce")

#: Sources a ``derived`` tag can take its value from. The event layer fills
#: them in from the CloudTrail record (see ``ResourceRef.derive_values``).
DERIVED_SOURCES = (
    "principal.user",
    "principal.arn",
    "principal.account",
    "principal.type",
    "event.time",
)

#: AWS rejects tag values longer than 256 characters on every tagging API.
MAX_TAG_VALUE_LEN = 256

_CASES = {"lower": str.lower, "upper": str.upper}
_RULE_KEYS = ("allowed", "pattern", "case")


@dataclass
class Rule:
    """Constraints on one tag's value.

    ``allowed`` is an exact list, ``pattern`` a regex the whole value must
    match, and ``case`` (``lower``/``upper``) the required letter case. A value
    that only differs from a valid one by case is fixable when ``case`` is set;
    anything else that fails the rule is invalid and never rewritten.
    """

    allowed: Optional[List[str]] = None
    pattern: Optional[str] = None
    case: Optional[str] = None

    def __post_init__(self) -> None:
        if self.allowed is None and self.pattern is None and self.case is None:
            raise ValueError("a rule needs at least one of %s" % (_RULE_KEYS,))
        if self.case is not None and self.case not in _CASES:
            raise ValueError(
                "case must be one of %s, got %r" % (tuple(_CASES), self.case)
            )
        if self.allowed is not None:
            if isinstance(self.allowed, str) or not self.allowed:
                raise ValueError("allowed must be a non-empty list of values")
            self.allowed = [str(v) for v in self.allowed]
            if self.case is not None:
                bad = [v for v in self.allowed if _CASES[self.case](v) != v]
                if bad:
                    raise ValueError(
                        "allowed values %s are not %s case" % (bad, self.case)
                    )
        self._regex = None
        if self.pattern is not None:
            try:
                self._regex = re.compile(str(self.pattern))
            except re.error as exc:
                raise ValueError("bad pattern %r: %s" % (self.pattern, exc))

    @classmethod
    def from_dict(cls, data: Dict) -> "Rule":
        if not isinstance(data, dict):
            raise ValueError("a rule must be a mapping, got %r" % (data,))
        unknown = sorted(set(data) - set(_RULE_KEYS))
        if unknown:
            raise ValueError("unknown rule keys %s" % unknown)
        return cls(
            allowed=data.get("allowed"),
            pattern=data.get("pattern"),
            case=data.get("case"),
        )

    def _accepts(self, value: str) -> bool:
        if self.allowed is not None and value not in self.allowed:
            return False
        if self._regex is not None and not self._regex.fullmatch(value):
            return False
        return True

    def check(self, value: str) -> Tuple[str, str]:
        """Return ``("ok", value)``, ``("fix", fixed)`` or ``("invalid", value)``.

        ``fix`` only happens for a pure case variant: lowering (or uppering)
        the value is the one change that makes it valid.
        """
        target = _CASES[self.case](value) if self.case else value
        if target == value:
            return ("ok", value) if self._accepts(value) else ("invalid", value)
        if self._accepts(target):
            return ("fix", target)
        return ("invalid", value)


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
    #: present tags whose value breaks a rule; flagged, never auto-fixed.
    invalid: Dict[str, str] = field(default_factory=dict)
    #: present tags whose value is a case variant of a valid one -> fixed value.
    to_fix: Dict[str, str] = field(default_factory=dict)
    #: derived tags that are not required but missing; enforce mode adds them
    #: without them counting against compliance.
    extra_tags: Dict[str, str] = field(default_factory=dict)

    @property
    def flagged(self) -> bool:
        """True when the resource cannot be made compliant automatically."""
        return bool(self.unresolved or self.invalid)

    @property
    def writes(self) -> Dict[str, str]:
        """Every tag enforce mode would write: derived/defaults, fixes, extras."""
        out = dict(self.extra_tags)
        out.update(self.to_apply)
        out.update(self.to_fix)
        return out


@dataclass
class Policy:
    required_tags: List[str]
    defaults: Dict[str, str] = field(default_factory=dict)
    #: tag -> source in DERIVED_SOURCES, e.g. ``{"Owner": "principal.user"}``.
    derived: Dict[str, str] = field(default_factory=dict)
    #: tag -> :class:`Rule` (or a plain mapping, converted on init).
    rules: Dict[str, Rule] = field(default_factory=dict)
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
        for tag, source in self.derived.items():
            if source not in DERIVED_SOURCES:
                raise ValueError(
                    "derived %s: source must be one of %s, got %r"
                    % (tag, DERIVED_SOURCES, source)
                )
        self.rules = {
            tag: rule if isinstance(rule, Rule) else Rule.from_dict(rule)
            for tag, rule in self.rules.items()
        }
        # A default that breaks its own rule would be written and then flagged
        # on the next event; refuse the policy instead.
        for tag, value in self.defaults.items():
            rule = self.rules.get(tag)
            if rule is not None and rule.check(str(value))[0] != "ok":
                raise ValueError(
                    "default %s=%r does not satisfy its rule" % (tag, value)
                )

    # -- loading ---------------------------------------------------------
    @classmethod
    def from_dict(cls, data: Dict) -> "Policy":
        notify = data.get("notify", {}) or {}
        return cls(
            required_tags=list(data["required_tags"]),
            defaults=dict(data.get("defaults", {}) or {}),
            derived=dict(data.get("derived", {}) or {}),
            rules=dict(data.get("rules", {}) or {}),
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
    def _derived_value(self, tag: str, context: Dict[str, str]) -> Optional[str]:
        """The derived value for ``tag``, or ``None`` if there is no usable one.

        A value that is empty, too long for AWS, or breaks the tag's rule is
        dropped so the tag falls through to ``defaults``.
        """
        source = self.derived.get(tag)
        value = str(context.get(source) or "").strip() if source else ""
        if not value or len(value) > MAX_TAG_VALUE_LEN:
            return None
        rule = self.rules.get(tag)
        if rule is not None:
            status, value = rule.check(value)
            if status == "invalid":
                return None
        return value

    def evaluate(
        self,
        tags: Optional[Dict[str, str]],
        context: Optional[Dict[str, str]] = None,
    ) -> Evaluation:
        """Check ``tags`` against the policy.

        A tag counts as present only when it is set to a non-empty value, so an
        ``Owner=""`` tag is treated the same as a missing one. ``context`` maps
        derived sources (``principal.user`` ...) to values from the event; a
        missing required tag is filled from it first, then from ``defaults``.
        """
        context = context or {}
        present = {k: v for k, v in (tags or {}).items() if str(v).strip()}
        to_apply: Dict[str, str] = {}
        unresolved: List[str] = []
        invalid: Dict[str, str] = {}
        to_fix: Dict[str, str] = {}
        extra_tags: Dict[str, str] = {}

        for tag, value in present.items():
            rule = self.rules.get(tag)
            if rule is None:
                continue
            status, fixed = rule.check(str(value))
            if status == "fix":
                to_fix[tag] = fixed
            elif status == "invalid":
                invalid[tag] = value

        for tag in self.required_tags:
            if tag in present:
                continue
            derived = self._derived_value(tag, context)
            if derived is not None:
                to_apply[tag] = derived
            elif tag in self.defaults:
                to_apply[tag] = self.defaults[tag]
            else:
                unresolved.append(tag)

        for tag in self.derived:
            if tag in present or tag in self.required_tags:
                continue
            derived = self._derived_value(tag, context)
            if derived is not None:
                extra_tags[tag] = derived

        compliant = not to_apply and not unresolved and not invalid and not to_fix
        return Evaluation(
            compliant=compliant,
            unresolved=unresolved,
            to_apply=to_apply,
            present=present,
            invalid=invalid,
            to_fix=to_fix,
            extra_tags=extra_tags,
        )
