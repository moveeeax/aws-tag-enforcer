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
