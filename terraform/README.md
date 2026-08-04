# Deploying aws-tag-enforcer

This module deploys the enforcer as a Lambda wired to an EventBridge rule, with
an SNS topic for alerts and an SQS dead-letter queue for failed invocations.

## Build the Lambda package

The Lambda expects the package code plus `policy.yaml` and vendored `PyYAML` in
a `build/lambda/` directory:

```bash
mkdir -p build/lambda
cp -r src/tag_enforcer build/lambda/
cp examples/policy.yaml build/lambda/policy.yaml
pip install --target build/lambda PyYAML   # boto3 is provided by the runtime
```

## Apply

```bash
cd terraform
terraform init
terraform apply -var="region=eu-central-1"
```

Subscribe your email or Slack integration to the `sns_topic_arn` output, or set
`notify.slack_webhook_url` in `policy.yaml` and redeploy.

> Resource-creation events require an active CloudTrail (a multi-region trail is
> enough) so the API calls reach EventBridge.
