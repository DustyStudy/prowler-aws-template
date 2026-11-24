output "scanner_account_id" {
  description = "Set as the SCANNER_ACCOUNT_ID GitHub variable."
  value       = local.account_id
}

output "reports_bucket" {
  description = "Set as the REPORTS_BUCKET GitHub variable."
  value       = aws_s3_bucket.reports.bucket
}

output "report_from_email" {
  description = "Set as the REPORT_FROM_EMAIL GitHub variable."
  value       = var.report_email == null ? null : local.report_from
}

output "runner_role_arn" {
  value = aws_iam_role.runner.arn
}

output "kms_key_arn" {
  description = "Reports bucket KMS key; grant kms:Decrypt on it to whoever reads reports. Null unless create_kms_key = true."
  value       = one(aws_kms_key.reports[*].arn)
}

output "access_logs_bucket" {
  description = "Bucket holding the reports bucket's access logs. Null unless enable_access_logging = true."
  value       = one(aws_s3_bucket.access_logs[*].bucket)
}
