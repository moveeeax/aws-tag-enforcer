"""Handler tests use a fake boto3 Session that records calls -- no AWS, no boto3."""
from tag_enforcer.handler import lambda_handler
from tag_enforcer.policy import Policy


class FakeClient:
    def __init__(self, name, calls):
        self.name = name
        self.calls = calls

    def create_tags(self, **kw):
        self.calls.append((self.name, "create_tags", kw))

    def put_bucket_tagging(self, **kw):
        self.calls.append((self.name, "put_bucket_tagging", kw))

    def tag_resources(self, **kw):
        self.calls.append((self.name, "tag_resources", kw))

    def publish(self, **kw):
        self.calls.append((self.name, "publish", kw))


class FakeSession:
    def __init__(self):
        self.calls = []

    def client(self, name, **kw):
        return FakeClient(name, self.calls)


EC2_EVENT = {
    "region": "eu-central-1",
    "account": "111122223333",
    "detail": {
        "eventName": "RunInstances",
        "requestParameters": {
            "tagSpecificationSet": {"items": [{"tags": [{"key": "Owner", "value": "mt"}]}]}
        },
        "responseElements": {"instancesSet": {"items": [{"instanceId": "i-0abc"}]}},
    },
}


def test_compliant_resource_does_nothing():
    pol = Policy(required_tags=["Owner"])
    sess = FakeSession()
    res = lambda_handler(EC2_EVENT, policy=pol, session=sess)
    assert res["status"] == "compliant"
    assert sess.calls == []


def test_enforce_applies_default_tags():
    pol = Policy(
        required_tags=["Owner", "Environment"],
        defaults={"Environment": "dev"},
        mode="enforce",
    )
    sess = FakeSession()
    res = lambda_handler(EC2_EVENT, policy=pol, session=sess)
    assert res["status"] == "enforced"
    assert res["applied"] == {"Environment": "dev"}
    assert sess.calls[0][:2] == ("ec2", "create_tags")
    assert sess.calls[0][2]["Resources"] == ["i-0abc"]


def test_report_mode_never_applies_tags():
    pol = Policy(
        required_tags=["Owner", "Environment"],
        defaults={"Environment": "dev"},
        mode="report",
        sns_topic_arn="arn:aws:sns:eu-central-1:111122223333:tags",
    )
    sess = FakeSession()
    res = lambda_handler(EC2_EVENT, policy=pol, session=sess)
    # Environment has a default, but report mode applies nothing -- so the
    # resource stays non-compliant and gets flagged (never tagged).
    assert res["status"] == "flagged"
    assert res["applied"] == {}
    assert res["missing"] == ["Environment"]
    assert res["notified"] == ["sns"]
    assert all(c[1] != "create_tags" for c in sess.calls)


def test_unresolved_tag_is_flagged_to_sns():
    pol = Policy(
        required_tags=["Owner", "CostCenter"],
        mode="enforce",
        sns_topic_arn="arn:aws:sns:eu-central-1:111122223333:tags",
    )
    sess = FakeSession()
    res = lambda_handler(EC2_EVENT, policy=pol, session=sess)
    assert res["missing"] == ["CostCenter"]
    assert res["notified"] == ["sns"]
    published = [c for c in sess.calls if c[1] == "publish"]
    assert published and "CostCenter" in published[0][2]["Message"]


def test_out_of_scope_service_is_skipped():
    pol = Policy(required_tags=["Owner"], services=["s3"])
    res = lambda_handler(EC2_EVENT, policy=pol, session=FakeSession())
    assert res["status"] == "skipped"
    assert res["reason"] == "service-not-in-scope"


def test_unsupported_event_is_skipped():
    pol = Policy(required_tags=["Owner"])
    res = lambda_handler({"detail": {"eventName": "Nope"}}, policy=pol)
    assert res["status"] == "skipped"


SSO_ARN = "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Dev/alice@example.com"


def _bucket_event(**detail_extra):
    detail = {
        "eventName": "CreateBucket",
        "eventTime": "2026-11-05T09:30:00Z",
        "requestParameters": {"bucketName": "b1"},
        "userIdentity": {"type": "AssumedRole", "arn": SSO_ARN},
    }
    detail.update(detail_extra)
    return {"region": "eu-central-1", "account": "111122223333", "detail": detail}


def test_enforce_fills_owner_from_principal_and_adds_extras():
    pol = Policy(
        required_tags=["Owner"],
        derived={
            "Owner": "principal.user",
            "CreatedBy": "principal.arn",
            "CreatedAt": "event.time",
        },
        mode="enforce",
    )
    sess = FakeSession()
    res = lambda_handler(_bucket_event(), policy=pol, session=sess)
    assert res["status"] == "enforced"
    assert res["missing"] == [] and res["notified"] == []
    assert res["applied"] == {
        "Owner": "alice@example.com",
        "CreatedBy": SSO_ARN,
        "CreatedAt": "2026-11-05T09:30:00Z",
    }
    tagging = sess.calls[0][2]["Tagging"]["TagSet"]
    assert {"Key": "Owner", "Value": "alice@example.com"} in tagging


def _ec2_by_sso():
    identity = {"type": "AssumedRole", "arn": SSO_ARN}
    return dict(EC2_EVENT, detail=dict(EC2_EVENT["detail"], userIdentity=identity))


def test_enforce_adds_extras_to_otherwise_compliant_resource():
    pol = Policy(
        required_tags=["Owner"], derived={"CreatedBy": "principal.arn"}, mode="enforce"
    )
    ev = _ec2_by_sso()
    sess = FakeSession()
    res = lambda_handler(ev, policy=pol, session=sess)
    assert res["status"] == "enforced"
    assert res["applied"] == {"CreatedBy": SSO_ARN}


def test_report_mode_does_not_add_extras():
    pol = Policy(required_tags=["Owner"], derived={"CreatedBy": "principal.arn"})
    ev = _ec2_by_sso()
    sess = FakeSession()
    res = lambda_handler(ev, policy=pol, session=sess)
    assert res["status"] == "compliant"
    assert sess.calls == []


def _ec2_with_tags(tags):
    detail = dict(EC2_EVENT["detail"])
    detail["requestParameters"] = {
        "tagSpecificationSet": {
            "items": [{"tags": [{"key": k, "value": v} for k, v in tags.items()]}]
        }
    }
    return dict(EC2_EVENT, detail=detail)


RULES = {
    "Environment": {"allowed": ["dev", "prod"], "case": "lower"},
    "CostCenter": {"pattern": "CC-[0-9]{4}"},
}


def test_enforce_rewrites_case_variant_and_flags_invalid():
    pol = Policy(
        required_tags=["Owner", "Environment", "CostCenter"],
        rules=RULES,
        mode="enforce",
        sns_topic_arn="arn:aws:sns:eu-central-1:111122223333:tags",
    )
    sess = FakeSession()
    event = _ec2_with_tags({"Owner": "mt", "Environment": "Prod", "CostCenter": "eng"})
    res = lambda_handler(event, policy=pol, session=sess)
    assert res["status"] == "enforced"
    assert res["applied"] == {"Environment": "prod"}
    assert res["invalid"] == {"CostCenter": "eng"}
    assert res["missing"] == []
    assert res["notified"] == ["sns"]
    create = [c for c in sess.calls if c[1] == "create_tags"][0][2]
    assert create["Tags"] == [{"Key": "Environment", "Value": "prod"}]
    msg = [c for c in sess.calls if c[1] == "publish"][0][2]["Message"]
    assert "Invalid tag values: CostCenter=eng" in msg
    assert "Missing required tags" not in msg


def test_report_mode_flags_case_variant_without_rewriting():
    pol = Policy(
        required_tags=["Owner", "Environment"],
        rules=RULES,
        sns_topic_arn="arn:aws:sns:eu-central-1:111122223333:tags",
    )
    sess = FakeSession()
    event = _ec2_with_tags({"Owner": "mt", "Environment": "Prod"})
    res = lambda_handler(event, policy=pol, session=sess)
    assert res["status"] == "flagged"
    assert res["invalid"] == {"Environment": "Prod"}
    assert res["applied"] == {}
    assert all(c[1] != "create_tags" for c in sess.calls)
