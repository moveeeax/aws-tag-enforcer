import json

from tag_enforcer.cli import main

POLICY = "required_tags: [Owner, Environment]\ndefaults: {Environment: dev}\n"


def write_policy(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(POLICY)
    return str(p)


def test_check_compliant_exits_zero(tmp_path, capsys):
    policy = write_policy(tmp_path)
    rc = main(["check", "--policy", policy, "--tags", "Owner=mt,Environment=prod"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["compliant"] is True


def test_check_noncompliant_exits_one(tmp_path, capsys):
    policy = write_policy(tmp_path)
    rc = main(["check", "--policy", policy, "--tags", "Owner=mt"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert out["compliant"] is False
    assert out["to_apply"] == {"Environment": "dev"}


def test_check_bad_tag_string_errors(tmp_path):
    policy = write_policy(tmp_path)
    rc = main(["check", "--policy", policy, "--tags", "brokentag"])
    assert rc == 2


def test_eval_event_from_file(tmp_path, capsys):
    policy = write_policy(tmp_path)
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps(
            {
                "region": "eu-central-1",
                "account": "111122223333",
                "detail": {
                    "eventName": "CreateBucket",
                    "requestParameters": {"bucketName": "b1"},
                },
            }
        )
    )
    rc = main(["eval-event", "--policy", policy, "--event", str(event)])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert out["resource"] == "b1"
    assert out["service"] == "s3"
