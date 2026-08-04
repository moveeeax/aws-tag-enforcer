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
