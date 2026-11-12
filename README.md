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
- Evaluates the resource's tags against a YAML/JSON policy of required tags and
  optional value rules (allowed lists, regex, letter case).
- **enforce mode:** fills missing required tags from the creating identity
  (`derived`, e.g. `Owner` from the CloudTrail `userIdentity`) or from
  `defaults`, rewrites pure case variants (`Prod` -> `prod`) when a rule asks
  for it, then flags anything it could not fix.
- **report mode:** changes nothing, just flags non-compliant resources.
- Ships as a Lambda with a Terraform module, an SNS alert topic, and an SQS
  dead-letter queue for failed invocations.

## How it works

The policy engine (`src/tag_enforcer/policy.py`) is a pure function: given a tag
map and the values derived from the event, it returns which required tags are
missing, which can be filled from `derived` or `defaults`, which are
unresolved, and which present values break a rule. No AWS calls, so it is
trivially testable.

The event layer (`src/tag_enforcer/events.py`) normalizes each CloudTrail event
shape into a single `ResourceRef`, including who made the call
(`userIdentity`) and when (`eventTime`). Unsupported events return `None` and are
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
  "extra_tags": {},
  "invalid": {},
  "to_apply": {
    "Environment": "dev"
  },
  "to_fix": {},
  "unresolved": [
    "CostCenter"
  ]
}
$ echo $?
1
```

Pass `--principal <IAM/STS ARN>` (and optionally `--event-time`) to see what
the `derived` tags would get:

```console
$ tag-enforcer check --policy examples/policy.yaml \
    --tags Environment=Prod,CostCenter=eng \
    --principal arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_PowerUser_0123456789abcdef/mtarassov@example.com
{
  "compliant": false,
  "extra_tags": {
    "CreatedBy": "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_PowerUser_0123456789abcdef/mtarassov@example.com"
  },
  "invalid": {
    "CostCenter": "eng"
  },
  "to_apply": {
    "Owner": "mtarassov@example.com"
  },
  "to_fix": {
    "Environment": "prod"
  },
  "unresolved": []
}
```

Replay a captured EventBridge event:

```console
$ tag-enforcer eval-event --policy examples/policy.yaml \
    --event examples/event-run-instances.json
{
  "compliant": false,
  "extra_tags": {
    "CreatedAt": "2026-11-05T09:30:00Z",
    "CreatedBy": "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_PowerUser_0123456789abcdef/mtarassov@example.com"
  },
  "invalid": {},
  "resource": "i-0123456789abcdef0",
  "service": "ec2",
  "to_apply": { "Environment": "dev" },
  "to_fix": {},
  "unresolved": ["CostCenter"]
}
```

The report fields:

| Field | Meaning | Affects exit code |
|---|---|---|
| `to_apply` | missing required tags enforce mode fills (from `derived`, then `defaults`) | yes |
| `unresolved` | missing required tags with no derived value and no default | yes |
| `invalid` | present tags whose value breaks a rule; flagged, never rewritten | yes |
| `to_fix` | present tags that are a pure case variant of a valid value -> the value enforce mode writes | yes |
| `extra_tags` | derived tags that are not required and are missing (enforce mode adds them) | no |

Both commands exit `0` when compliant, `1` when not, `2` on a bad policy,
event or argument.

Deploy the Lambda + EventBridge rule with Terraform — see
[`terraform/README.md`](terraform/README.md).

## Policy

See [`examples/policy.yaml`](examples/policy.yaml) for a complete file.

### Derived tags

`derived` maps a tag to a value taken from the creating CloudTrail event:

```yaml
derived:
  Owner: principal.user
  CreatedBy: principal.arn
  CreatedAt: event.time
```

| Source | Value |
|---|---|
| `principal.user` | IAM user: the user name. Assumed role: the session name (for IAM Identity Center users that is their Identity Center user name, usually the email). Federated user: its name. Root: `root`. AWS service principals give nothing. |
| `principal.arn` | `userIdentity.arn` |
| `principal.account` | `userIdentity.accountId` |
| `principal.type` | `userIdentity.type` (`IAMUser`, `AssumedRole`, `Root`, ...) |
| `event.time` | CloudTrail `eventTime` (ISO 8601 UTC), else the EventBridge `time` |

A missing required tag is filled from `derived` first, then from `defaults`. A
derived value is skipped (so the default applies) when it is empty, longer than
AWS's 256-character tag value limit, or breaks the tag's rule. Derived tags
that are not in `required_tags` are added in enforce mode when missing but do
not make a resource non-compliant. Present tags are never overwritten.

For an instance launched by an Auto Scaling group or a role used by a pipeline,
`principal.user` is the session name that service or pipeline chose, not a
person. Put a `rules` entry on `Owner` (for example an email `pattern`) if
those should fall back to a default instead.

### Value rules

```yaml
rules:
  Environment:
    allowed: [dev, staging, prod]
    case: lower
  CostCenter:
    pattern: "CC-[0-9]{4}"
```

- `allowed`: exact list of values.
- `pattern`: Python regex the whole value must match (`re.fullmatch`), so
  `prod|dev` does not accept `nonprod`.
- `case`: `lower` or `upper`. A value whose only problem is letter case
  (`Prod`) is reported in `to_fix`, and enforce mode rewrites it. Without
  `case`, matching is case-sensitive and `Prod` is `invalid`.

Rules apply to every present tag that has one, required or not. A value that
breaks a rule in any other way (`production`) goes to `invalid`: it is flagged
and never rewritten, since only a person knows the right value. The policy
fails to load when a rule has unknown keys or a bad regex, when an `allowed`
value contradicts `case`, or when a `defaults` value breaks its own rule.

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
