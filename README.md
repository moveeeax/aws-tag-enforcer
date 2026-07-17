# aws-tag-enforcer

> Keep your tagging policy honest, automatically.

**Status:** 🚧 In development

## Overview

Auto-tag or flag AWS resources missing mandatory tags, driven by EventBridge.

## Features

- EventBridge rule on resource-creation events
- Applies default tags (owner, env, cost-center) when derivable
- Flags non-compliant resources to SNS/Slack
- Config-driven required-tag policy
- Report mode + enforce mode

## Stack

Python + boto3, packaged as Lambda; Terraform to deploy.

## Usage

```bash
# deploy via terraform/
terraform apply
```

## License

MIT
