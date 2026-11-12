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


RULES_POLICY = """
required_tags: [Owner, Environment, CostCenter]
derived: {Owner: principal.user, CreatedBy: principal.arn, CreatedAt: event.time}
rules:
  Environment: {allowed: [dev, prod], case: lower}
  CostCenter: {pattern: "CC-[0-9]{4}"}
"""


def write_rules_policy(tmp_path):
    p = tmp_path / "rules.yaml"
    p.write_text(RULES_POLICY)
    return str(p)


def test_check_principal_fills_owner(tmp_path, capsys):
    policy = write_rules_policy(tmp_path)
    arn = "arn:aws:sts::111122223333:assumed-role/R/alice@example.com"
    rc = main(
        [
            "check", "--policy", policy,
            "--tags", "Environment=dev,CostCenter=CC-0001",
            "--principal", arn,
            "--event-time", "2026-11-05T09:30:00Z",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert rc == 1  # Owner still has to be written
    assert out["to_apply"] == {"Owner": "alice@example.com"}
    assert out["extra_tags"] == {
        "CreatedBy": arn,
        "CreatedAt": "2026-11-05T09:30:00Z",
    }
    assert out["unresolved"] == []


def test_check_extras_alone_stay_compliant(tmp_path, capsys):
    policy = write_rules_policy(tmp_path)
    rc = main(
        [
            "check", "--policy", policy,
            "--tags", "Owner=mt,Environment=dev,CostCenter=CC-0001",
            "--principal", "arn:aws:iam::111122223333:user/mt",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["compliant"] is True
    assert out["extra_tags"] == {"CreatedBy": "arn:aws:iam::111122223333:user/mt"}


def test_check_reports_invalid_and_fixable_values(tmp_path, capsys):
    policy = write_rules_policy(tmp_path)
    rc = main(
        [
            "check", "--policy", policy,
            "--tags", "Owner=mt,Environment=Prod,CostCenter=eng",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert out["invalid"] == {"CostCenter": "eng"}
    assert out["to_fix"] == {"Environment": "prod"}


def test_check_bad_principal_errors(tmp_path):
    policy = write_rules_policy(tmp_path)
    rc = main(["check", "--policy", policy, "--principal", "not-an-arn"])
    assert rc == 2


def test_bad_rule_in_policy_file_errors(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("required_tags: [Owner]\nrules: {Owner: {case: title}}\n")
    assert main(["check", "--policy", str(p), "--tags", "Owner=mt"]) == 2


def test_eval_event_example_derives_from_identity(capsys):
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent / "examples"
    rc = main(
        [
            "eval-event",
            "--policy", str(root / "policy.yaml"),
            "--event", str(root / "event-run-instances.json"),
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert out["unresolved"] == ["CostCenter"]
    assert out["extra_tags"]["CreatedAt"] == "2026-11-05T09:30:00Z"
    assert out["extra_tags"]["CreatedBy"].endswith("/mtarassov@example.com")
