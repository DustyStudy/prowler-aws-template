output "management_account_id" {
  description = "Set as the MANAGEMENT_ACCOUNT_ID GitHub variable."
  value       = data.aws_organizations_organization.this.master_account_id
}

output "stack_set_name" {
  value = aws_cloudformation_stack_set.scan_role.name
}
