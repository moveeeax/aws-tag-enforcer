terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# ---------------------------------------------------------------------------
# Package the Lambda from the src/ tree. boto3 is provided by the Lambda
# runtime, and PyYAML is vendored alongside the code (see the build note in
# terraform/README.md).
# ---------------------------------------------------------------------------
data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../build/lambda"
  output_path = "${path.module}/../build/aws-tag-enforcer.zip"
}

resource "aws_sns_topic" "alerts" {
  name = "${var.name}-alerts"
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name}-dlq"
  message_retention_seconds = 1209600 # 14 days
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${var.name}-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "perms" {
  statement {
    sid = "Logs"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }
  statement {
    sid = "Tagging"
    actions = [
      "ec2:CreateTags",
      "s3:PutBucketTagging",
      "s3:GetBucketTagging",
      "rds:AddTagsToResource",
      "tag:TagResources",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
  statement {
    sid       = "Dlq"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }
}

resource "aws_iam_role_policy" "perms" {
  name   = "${var.name}-perms"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.perms.json
}

resource "aws_lambda_function" "enforcer" {
  function_name    = var.name
  role             = aws_iam_role.lambda.arn
  handler          = "tag_enforcer.handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      POLICY_PATH = "policy.yaml"
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }
}

# React to resource-creation API calls captured by CloudTrail.
resource "aws_cloudwatch_event_rule" "creates" {
  name        = "${var.name}-creates"
  description = "Resource-creation events for tag enforcement"
  event_pattern = jsonencode({
    "detail-type" : ["AWS API Call via CloudTrail"],
    "detail" : {
      "eventName" : ["RunInstances", "CreateBucket", "CreateDBInstance"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.creates.name
  arn  = aws_lambda_function.enforcer.arn

  retry_policy {
    maximum_retry_attempts       = 2
    maximum_event_age_in_seconds = 3600
  }
  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.enforcer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.creates.arn
}
