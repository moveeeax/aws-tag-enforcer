output "lambda_function_arn" {
  description = "ARN of the tag-enforcer Lambda."
  value       = aws_lambda_function.enforcer.arn
}

output "sns_topic_arn" {
  description = "SNS topic that receives non-compliance alerts."
  value       = aws_sns_topic.alerts.arn
}

output "dlq_url" {
  description = "Dead-letter queue for failed invocations."
  value       = aws_sqs_queue.dlq.id
}

output "event_rule_name" {
  description = "EventBridge rule matching resource-creation events."
  value       = aws_cloudwatch_event_rule.creates.name
}
