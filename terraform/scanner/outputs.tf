output "scanner_account_id" {
  description = "Set as the SCANNER_ACCOUNT_ID GitHub variable."
  value       = local.account_id
}

output "reports_bucket" {
  description = "Set as the REPORTS_BUCKET GitHub variable."
  value       = aws_s3_bucket.reports.bucket
}

output "runner_role_arn" {
  value = aws_iam_role.runner.arn
}

output "notify_topic_arn" {
  description = "Set as the NOTIFY_TOPIC_ARN GitHub variable to enable email summaries."
  value       = local.email_enabled ? aws_sns_topic.scan_summary[0].arn : null
}
