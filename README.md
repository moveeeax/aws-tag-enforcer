# aws-tag-enforcer

[![ci](https://github.com/moveeeax/aws-tag-enforcer/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-tag-enforcer/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Keep your AWS tagging policy honest, automatically. `aws-tag-enforcer` reacts to
resource-creation events on EventBridge, checks the new resource against a
config-driven required-tag policy, **applies** the defaults it can, and
**flags** whatever it cannot fix to SNS or Slack.

## What it does

- Watches CloudTrail resource-creation events (EC2 `RunInstances`, S3
  `CreateBucket`, RDS `CreateDBInstance`) via an EventBridge rule.
- Evaluates the resource's tags against a YAML/JSON policy of required tags.
- **enforce mode:** auto-applies default values for missing required tags, then
  flags anything with no default.
- **report mode:** changes nothing, just flags non-compliant resources.
- Ships as a Lambda with a Terraform module, an SNS alert topic, and an SQS
  dead-letter queue for failed invocations.

## How it works

The policy engine (`src/tag_enforcer/policy.py`) is a pure function: given a tag
map it returns which required tags are missing, which can be satisfied from
`defaults`, and which are unresolved. No AWS calls, so it is trivially testable.

The event layer (`src/tag_enforcer/events.py`) normalizes each CloudTrail event
shape into a single `ResourceRef`. Unsupported events return `None` and are
skipped — better to ignore an event than to guess a resource wrong.

`boto3` is imported lazily inside the tagging and notification calls, so the
engine, the CLI, and the whole test suite run without `boto3` installed.

```
EventBridge -> Lambda(handler) -> policy.evaluate() -> tagger.apply_tags()  (enforce)
                                                    \-> notify() -> SNS / Slack
```

## Install

Requires Python 3.11+. The package is not published on PyPI; install it
straight from GitHub:

```bash
pip install git+https://github.com/moveeeax/aws-tag-enforcer
# or pin a release tag
pip install git+https://github.com/moveeeax/aws-tag-enforcer@v0.1.0
```

That installs the `tag-enforcer` CLI. Add the `aws` extra
(`pip install "aws-tag-enforcer[aws] @ git+https://github.com/moveeeax/aws-tag-enforcer"`)
if you want to apply tags or send notifications outside Lambda; the Lambda
runtime already ships `boto3`.

To deploy as a Lambda you need Terraform 1.3+ with the `hashicorp/aws` 6.x and
`hashicorp/archive` 2.x providers (declared in `terraform/main.tf`).

## Usage

Check a tag set offline:

```console
$ tag-enforcer check --policy examples/policy.yaml --tags Owner=mt
{
  "compliant": false,
  "to_apply": {
    "Environment": "dev"
  },
  "unresolved": [
    "CostCenter"
  ]
}
$ echo $?
1
```

Replay a captured EventBridge event:

```console
$ tag-enforcer eval-event --policy examples/policy.yaml \
    --event examples/event-run-instances.json
{
  "compliant": false,
  "resource": "i-0123456789abcdef0",
  "service": "ec2",
  "to_apply": { "Environment": "dev" },
  "unresolved": ["CostCenter"]
}
```

Deploy the Lambda + EventBridge rule with Terraform — see
[`terraform/README.md`](terraform/README.md).

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## One note

A required tag set to an empty string (`Owner=""`) is treated exactly like a
missing tag. AWS lets you create a resource with a blank tag value, which sails
past a naive "is the key present?" check — the policy engine strips and rejects
it so a blank tag never counts as compliant.

## License

MIT — see [LICENSE](LICENSE).
