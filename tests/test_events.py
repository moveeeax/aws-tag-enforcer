import pytest

from tag_enforcer.events import parse_event


def test_run_instances_extracts_id_and_tags():
    event = {
        "region": "eu-central-1",
        "account": "111122223333",
        "detail": {
            "eventName": "RunInstances",
            "requestParameters": {
                "tagSpecificationSet": {
                    "items": [
                        {"tags": [{"key": "Owner", "value": "mt"}]},
                    ]
                }
            },
            "responseElements": {
                "instancesSet": {"items": [{"instanceId": "i-0abc"}]}
            },
        },
    }
    ref = parse_event(event)
    assert ref.service == "ec2"
    assert ref.resource_id == "i-0abc"
    assert ref.tags == {"Owner": "mt"}
    assert ref.arn == "arn:aws:ec2:eu-central-1:111122223333:instance/i-0abc"


def test_create_bucket_has_no_inline_tags():
    event = {
        "region": "us-east-1",
        "account": "111122223333",
        "detail": {
            "eventName": "CreateBucket",
            "requestParameters": {"bucketName": "my-bucket"},
        },
    }
    ref = parse_event(event)
    assert ref.service == "s3"
    assert ref.resource_id == "my-bucket"
    assert ref.arn == "arn:aws:s3:::my-bucket"
    assert ref.tags == {}


def test_create_db_instance_uses_response_arn():
    event = {
        "region": "eu-west-1",
        "account": "111122223333",
        "detail": {
            "eventName": "CreateDBInstance",
            "requestParameters": {
                "dBInstanceIdentifier": "db1",
                "tags": [{"key": "Environment", "value": "prod"}],
            },
            "responseElements": {
                "dBInstanceIdentifier": "db1",
                "dBInstanceArn": "arn:aws:rds:eu-west-1:111122223333:db:db1",
            },
        },
    }
    ref = parse_event(event)
    assert ref.service == "rds"
    assert ref.tags == {"Environment": "prod"}
    assert ref.arn.endswith(":db:db1")


def test_unsupported_event_returns_none():
    assert parse_event({"detail": {"eventName": "DeleteBucket"}}) is None
    assert parse_event({}) is None
    assert parse_event("not-a-dict") is None


def test_run_instances_without_instance_returns_none():
    event = {"detail": {"eventName": "RunInstances", "responseElements": {}}}
    assert parse_event(event) is None


def _with_identity(identity, **detail_extra):
    detail = {
        "eventName": "CreateBucket",
        "requestParameters": {"bucketName": "b1"},
        "userIdentity": identity,
    }
    detail.update(detail_extra)
    return {"region": "us-east-1", "account": "111122223333", "detail": detail}


def test_assumed_role_principal_uses_session_name():
    arn = "arn:aws:sts::111122223333:assumed-role/SSO_Admin/alice@example.com"
    ref = parse_event(
        _with_identity(
            {
                "type": "AssumedRole",
                "principalId": "AROAEXAMPLE:alice@example.com",
                "arn": arn,
                "accountId": "111122223333",
            },
            eventTime="2026-11-05T09:30:00Z",
        )
    )
    assert ref.principal.user == "alice@example.com"
    assert ref.principal.type == "AssumedRole"
    assert ref.derive_values() == {
        "principal.user": "alice@example.com",
        "principal.arn": arn,
        "principal.account": "111122223333",
        "principal.type": "AssumedRole",
        "event.time": "2026-11-05T09:30:00Z",
    }


def test_iam_user_principal_uses_user_name():
    ref = parse_event(
        _with_identity(
            {
                "type": "IAMUser",
                "arn": "arn:aws:iam::111122223333:user/ops/bob",
                "userName": "bob",
            }
        )
    )
    assert ref.principal.user == "bob"


def test_root_and_service_principals():
    root = parse_event(_with_identity({"type": "Root", "arn": "arn:aws:iam::1:root"}))
    assert root.principal.user == "root"
    svc = parse_event(
        _with_identity({"type": "AWSService", "invokedBy": "ec2.amazonaws.com"})
    )
    assert svc.principal.user == ""
    assert "principal.user" not in svc.derive_values()


def test_event_time_falls_back_to_envelope_time():
    event = _with_identity({})
    event["time"] = "2026-11-05T10:00:00Z"
    ref = parse_event(event)
    assert ref.principal is None
    assert ref.derive_values() == {"event.time": "2026-11-05T10:00:00Z"}


def test_derived_source_names_match_policy():
    from tag_enforcer.events import Principal
    from tag_enforcer.policy import DERIVED_SOURCES

    full = Principal(type="IAMUser", arn="a", account_id="1", user="u").values()
    assert set(full) | {"event.time"} == set(DERIVED_SOURCES)


@pytest.mark.parametrize(
    "arn,ptype,user",
    [
        ("arn:aws:iam::111122223333:user/ops/bob", "IAMUser", "bob"),
        ("arn:aws:iam::111122223333:root", "Root", "root"),
        (
            "arn:aws:sts::111122223333:assumed-role/R/alice@example.com",
            "AssumedRole",
            "alice@example.com",
        ),
        ("arn:aws:sts::111122223333:federated-user/carol", "FederatedUser", "carol"),
    ],
)
def test_principal_from_arn(arn, ptype, user):
    from tag_enforcer.events import Principal

    p = Principal.from_arn(arn)
    assert (p.type, p.user, p.account_id) == (ptype, user, "111122223333")


@pytest.mark.parametrize(
    "arn", ["bob", "arn:aws:iam::111122223333:role/R", "arn:aws:s3:::bucket"]
)
def test_principal_from_bad_arn(arn):
    from tag_enforcer.events import Principal

    with pytest.raises(ValueError):
        Principal.from_arn(arn)
