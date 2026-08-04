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
