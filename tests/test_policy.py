import json

import pytest

from tag_enforcer.policy import Policy


def make_policy(**kw):
    base = dict(required_tags=["Owner", "Environment", "CostCenter"])
    base.update(kw)
    return Policy(**base)


def test_fully_compliant_resource():
    pol = make_policy()
    ev = pol.evaluate({"Owner": "mt", "Environment": "prod", "CostCenter": "eng"})
    assert ev.compliant is True
    assert ev.unresolved == []
    assert ev.to_apply == {}
    assert ev.flagged is False


def test_missing_tag_with_default_is_auto_appliable():
    pol = make_policy(defaults={"Environment": "dev"})
    ev = pol.evaluate({"Owner": "mt", "CostCenter": "eng"})
    assert ev.compliant is False
    assert ev.to_apply == {"Environment": "dev"}
    assert ev.unresolved == []
    assert ev.flagged is False


def test_missing_tag_without_default_is_unresolved():
    pol = make_policy(defaults={"Environment": "dev"})
    ev = pol.evaluate({"Environment": "dev"})
    assert ev.compliant is False
    assert set(ev.unresolved) == {"Owner", "CostCenter"}
    assert ev.flagged is True


def test_empty_string_tag_counts_as_missing():
    pol = make_policy()
    ev = pol.evaluate({"Owner": "  ", "Environment": "prod", "CostCenter": "eng"})
    assert "Owner" in ev.unresolved
    assert ev.compliant is False


def test_none_tags_flags_everything():
    pol = make_policy()
    ev = pol.evaluate(None)
    assert set(ev.unresolved) == {"Owner", "Environment", "CostCenter"}


def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        make_policy(mode="delete-everything")


def test_empty_required_tags_rejected():
    with pytest.raises(ValueError):
        Policy(required_tags=[])


def test_from_dict_reads_notify_block():
    pol = Policy.from_dict(
        {
            "required_tags": ["Owner"],
            "mode": "enforce",
            "notify": {"sns_topic_arn": "arn:aws:sns:x", "slack_webhook_url": "https://h"},
        }
    )
    assert pol.mode == "enforce"
    assert pol.sns_topic_arn == "arn:aws:sns:x"
    assert pol.slack_webhook_url == "https://h"


def test_load_yaml_and_json_roundtrip(tmp_path):
    data = {"required_tags": ["Owner"], "defaults": {"Owner": "team"}}
    y = tmp_path / "p.yaml"
    y.write_text("required_tags: [Owner]\ndefaults: {Owner: team}\n")
    j = tmp_path / "p.json"
    j.write_text(json.dumps(data))
    assert Policy.load(str(y)).defaults == {"Owner": "team"}
    assert Policy.load(str(j)).defaults == {"Owner": "team"}


# -- derived tags ------------------------------------------------------------

CTX = {
    "principal.user": "alice@example.com",
    "principal.arn": "arn:aws:sts::111122223333:assumed-role/R/alice@example.com",
    "event.time": "2026-11-05T09:30:00Z",
}


def test_derived_value_fills_missing_required_tag_before_default():
    pol = make_policy(
        derived={"Owner": "principal.user"}, defaults={"Owner": "platform"}
    )
    ev = pol.evaluate({"Environment": "prod", "CostCenter": "eng"}, CTX)
    assert ev.to_apply == {"Owner": "alice@example.com"}
    assert ev.unresolved == []


def test_derived_falls_back_to_default_without_context():
    pol = make_policy(
        derived={"Owner": "principal.user"}, defaults={"Owner": "platform"}
    )
    ev = pol.evaluate({"Environment": "prod", "CostCenter": "eng"})
    assert ev.to_apply == {"Owner": "platform"}


def test_derived_never_overrides_present_tag():
    pol = make_policy(derived={"Owner": "principal.user"})
    ev = pol.evaluate({"Owner": "bob", "Environment": "prod", "CostCenter": "eng"}, CTX)
    assert ev.compliant is True
    assert ev.to_apply == {}


def test_derived_non_required_tags_are_extras_not_compliance():
    pol = make_policy(
        derived={"CreatedBy": "principal.arn", "CreatedAt": "event.time"}
    )
    ev = pol.evaluate({"Owner": "mt", "Environment": "prod", "CostCenter": "eng"}, CTX)
    assert ev.compliant is True
    assert ev.extra_tags == {
        "CreatedBy": CTX["principal.arn"],
        "CreatedAt": "2026-11-05T09:30:00Z",
    }
    assert ev.writes == ev.extra_tags


def test_derived_value_too_long_for_aws_is_dropped():
    pol = make_policy(derived={"Owner": "principal.arn"})
    ev = pol.evaluate({}, {"principal.arn": "x" * 257})
    assert "Owner" in ev.unresolved


def test_unknown_derived_source_rejected():
    with pytest.raises(ValueError):
        make_policy(derived={"Owner": "principal.email"})


def test_from_dict_reads_derived_and_rules():
    pol = Policy.from_dict(
        {
            "required_tags": ["Owner"],
            "derived": {"Owner": "principal.user"},
            "rules": {"Owner": {"pattern": "[a-z.@]+"}},
        }
    )
    assert pol.derived == {"Owner": "principal.user"}
    assert pol.rules["Owner"].pattern == "[a-z.@]+"


# -- value rules -------------------------------------------------------------

ENV_RULE = {"Environment": {"allowed": ["dev", "staging", "prod"], "case": "lower"}}


def test_allowed_value_passes():
    pol = make_policy(rules=ENV_RULE)
    ev = pol.evaluate({"Owner": "mt", "Environment": "prod", "CostCenter": "eng"})
    assert ev.compliant is True
    assert ev.invalid == {} and ev.to_fix == {}


def test_value_outside_allowed_list_is_invalid():
    pol = make_policy(rules=ENV_RULE)
    ev = pol.evaluate({"Owner": "mt", "Environment": "production", "CostCenter": "eng"})
    assert ev.compliant is False
    assert ev.invalid == {"Environment": "production"}
    assert ev.to_fix == {}
    assert ev.flagged is True
    # Never auto-fixed.
    assert "Environment" not in ev.writes


def test_case_variant_is_fixable_with_case_rule():
    pol = make_policy(rules=ENV_RULE)
    ev = pol.evaluate({"Owner": "mt", "Environment": "Prod", "CostCenter": "eng"})
    assert ev.compliant is False
    assert ev.to_fix == {"Environment": "prod"}
    assert ev.invalid == {}
    assert ev.flagged is False
    assert ev.writes == {"Environment": "prod"}


def test_case_variant_is_invalid_without_case_rule():
    pol = make_policy(rules={"Environment": {"allowed": ["dev", "prod"]}})
    ev = pol.evaluate({"Owner": "mt", "Environment": "Prod", "CostCenter": "eng"})
    assert ev.invalid == {"Environment": "Prod"}
    assert ev.to_fix == {}


def test_pattern_must_match_whole_value():
    pol = make_policy(rules={"CostCenter": {"pattern": "CC-[0-9]{4}"}})
    ok = pol.evaluate({"Owner": "mt", "Environment": "dev", "CostCenter": "CC-1234"})
    bad = pol.evaluate({"Owner": "mt", "Environment": "dev", "CostCenter": "CC-12345"})
    assert ok.compliant is True
    assert bad.invalid == {"CostCenter": "CC-12345"}


def test_rule_applies_to_present_optional_tag():
    pol = make_policy(rules={"Team": {"allowed": ["iam", "data"]}})
    ev = pol.evaluate(
        {"Owner": "mt", "Environment": "dev", "CostCenter": "x", "Team": "ops"}
    )
    assert ev.invalid == {"Team": "ops"}


def test_blank_value_with_rule_counts_as_missing_not_invalid():
    pol = make_policy(rules=ENV_RULE, defaults={"Environment": "dev"})
    ev = pol.evaluate({"Owner": "mt", "Environment": " ", "CostCenter": "eng"})
    assert ev.invalid == {}
    assert ev.to_apply == {"Environment": "dev"}


def test_derived_value_is_case_normalized_and_validated():
    pol = make_policy(
        derived={"Owner": "principal.user"},
        rules={"Owner": {"pattern": "[a-z]+@example\\.com", "case": "lower"}},
        defaults={"Owner": "platform@example.com"},
    )
    tags = {"Environment": "dev", "CostCenter": "x"}
    upper = pol.evaluate(tags, {"principal.user": "Alice@Example.com"})
    assert upper.to_apply == {"Owner": "alice@example.com"}
    other = pol.evaluate(tags, {"principal.user": "AutoScaling"})
    # Breaks the rule, so it falls through to the default.
    assert other.to_apply == {"Owner": "platform@example.com"}


@pytest.mark.parametrize(
    "rule",
    [
        {},
        {"allowed": []},
        {"allowed": "prod"},
        {"case": "title"},
        {"pattern": "("},
        {"allowed": ["Prod"], "case": "lower"},
        {"alowed": ["prod"]},
    ],
)
def test_bad_rules_rejected(rule):
    with pytest.raises(ValueError):
        make_policy(rules={"Environment": rule})


def test_default_breaking_its_rule_rejected():
    with pytest.raises(ValueError):
        make_policy(rules=ENV_RULE, defaults={"Environment": "Dev"})
