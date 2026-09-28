# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/DustyStudy/prowler-aws-template/security/advisories/new).
Do not open a public issue.

Include the affected file, the impact, and steps to reproduce. You can expect an
acknowledgement within 7 days.

## Scope

In scope: the Terraform stacks, the CloudFormation role template, and the GitHub Actions
workflows in this repository. Examples include IAM trust or permission policies that are
broader than documented, and workflow injection.

Out of scope: vulnerabilities in [Prowler](https://github.com/prowler-cloud/prowler) itself.
Report those to the Prowler project.

## Deployments

This repo is a template. Each copy is deployed and operated by its owner. Keep your copy
private, protect its `main` branch, and restrict who can push to it: anyone who can change
the workflow on `main` can use the scanner role.
