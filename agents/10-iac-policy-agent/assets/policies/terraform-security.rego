# ============================================================
# Terraform Security Policy
# Package: terraform.security
# Applies to: Terraform HCL files (parsed as text content)
# Author: GRIMSEC IaC Policy Agent
# ============================================================
#
# NOTE: Terraform HCL is not natively parseable by OPA.
# This policy operates on the file content passed as a string.
# For full AST-based checks, prefer Checkov (run-checkov.py).
# These OPA rules provide additional organization-specific checks.
#
# Input schema:
# {
#   "file": "path/to/main.tf",
#   "content": "<raw file contents as string>"
# }
#
# For richer checks, pass a Terraform plan JSON:
# terraform show -json tfplan.binary > tfplan.json
# opa eval --data terraform-security.rego --input tfplan.json \
#          "data.terraform.security.violations"
#
# When using plan JSON, the input will be:
# {
#   "planned_values": { "root_module": { "resources": [...] } },
#   "resource_changes": [...],
#   "configuration": { ... }
# }
# ============================================================

package terraform.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default violations := set()
default warnings := set()

# ========================
# CONTENT-BASED CHECKS
# (Operate on raw file content)
# ========================

# Rule: S3 buckets must have public access blocked
violations contains msg if {
	resource_block_present("aws_s3_bucket")
	not content_contains("aws_s3_bucket_public_access_block")
	msg := sprintf("[%v] S3 bucket found but no aws_s3_bucket_public_access_block resource — all S3 buckets must have public access blocked", [input.file])
}

# Rule: S3 buckets must have server-side encryption
violations contains msg if {
	resource_block_present("aws_s3_bucket")
	not content_contains("aws_s3_bucket_server_side_encryption_configuration")
	msg := sprintf("[%v] S3 bucket found but no aws_s3_bucket_server_side_encryption_configuration — enable SSE-S3 or SSE-KMS", [input.file])
}

# Rule: S3 buckets must have versioning enabled
violations contains msg if {
	resource_block_present("aws_s3_bucket")
	not content_contains("aws_s3_bucket_versioning")
	msg := sprintf("[%v] S3 bucket found but no aws_s3_bucket_versioning resource — enable versioning for data protection", [input.file])
}

# Rule: RDS instances must not be publicly accessible
violations contains msg if {
	resource_block_present("aws_db_instance")
	content_contains("publicly_accessible")
	content_contains("true")
	msg := sprintf("[%v] RDS instance may have publicly_accessible = true — databases must not be publicly accessible", [input.file])
}

# Rule: RDS instances must have encryption at rest
violations contains msg if {
	resource_block_present("aws_db_instance")
	not content_contains("storage_encrypted")
	msg := sprintf("[%v] RDS instance found without storage_encrypted — add storage_encrypted = true", [input.file])
}

# Rule: Security groups must not allow 0.0.0.0/0 on sensitive ports
violations contains msg if {
	resource_block_present("aws_security_group")
	content_contains("0.0.0.0/0")
	cidr_on_ssh_port
	msg := sprintf("[%v] Security group may allow unrestricted SSH access (0.0.0.0/0 on port 22) — restrict to known IP ranges", [input.file])
}

violations contains msg if {
	resource_block_present("aws_security_group")
	content_contains("0.0.0.0/0")
	cidr_on_rdp_port
	msg := sprintf("[%v] Security group may allow unrestricted RDP access (0.0.0.0/0 on port 3389) — restrict to known IP ranges", [input.file])
}

# Rule: CloudTrail should be enabled
violations contains msg if {
	not resource_block_present("aws_cloudtrail")
	content_contains("aws_")
	msg := sprintf("[%v] No aws_cloudtrail resource found — enable CloudTrail for audit logging", [input.file])
}

# Rule: All resources must be tagged with required tags
violations contains msg if {
	resource_block_present("aws_")
	not content_contains("Environment")
	msg := sprintf("[%v] Resources found without 'Environment' tag — all resources require Name, Environment, and Owner tags", [input.file])
}

violations contains msg if {
	resource_block_present("aws_")
	not content_contains("Owner")
	msg := sprintf("[%v] Resources found without 'Owner' tag — all resources require Name, Environment, and Owner tags", [input.file])
}

# Rule: EBS volumes must be encrypted
violations contains msg if {
	resource_block_present("aws_ebs_volume")
	not content_contains("encrypted")
	msg := sprintf("[%v] EBS volume found without encryption — add encrypted = true", [input.file])
}

# Rule: KMS key rotation must be enabled
violations contains msg if {
	resource_block_present("aws_kms_key")
	not content_contains("enable_key_rotation")
	msg := sprintf("[%v] KMS key found without enable_key_rotation = true — enable automatic key rotation", [input.file])
}

# Rule: Secrets Manager or SSM should be used (not hardcoded values)
violations contains msg if {
	content_contains("password")
	not content_contains("aws_secretsmanager")
	not content_contains("aws_ssm_parameter")
	not content_contains("var.")
	not content_contains("data.")
	msg := sprintf("[%v] Hardcoded 'password' string detected — use AWS Secrets Manager or SSM Parameter Store", [input.file])
}

# ========================
# TERRAFORM PLAN CHECKS
# (Operate on `terraform show -json` output)
# ========================

# Check planned resource changes for security issues
violations contains msg if {
	change := input.resource_changes[_]
	change.type == "aws_s3_bucket"
	after := object.get(change, ["change", "after"], {})
	object.get(after, "bucket", "") != ""
	msg := sprintf("[%v] Planned S3 bucket '%v' — verify public access block and encryption are applied",
		[input.file, object.get(after, "bucket", "unknown")])
}

# ========================
# WARNINGS (NON-BLOCKING)
# ========================

# Warning: RDS multi-AZ recommended
warnings contains msg if {
	resource_block_present("aws_db_instance")
	not content_contains("multi_az")
	msg := sprintf("[%v] RDS instance without multi_az — consider multi_az = true for production workloads", [input.file])
}

# Warning: RDS deletion protection recommended
warnings contains msg if {
	resource_block_present("aws_db_instance")
	not content_contains("deletion_protection")
	msg := sprintf("[%v] RDS instance without deletion_protection = true — add to prevent accidental deletion", [input.file])
}

# Warning: S3 access logging recommended
warnings contains msg if {
	resource_block_present("aws_s3_bucket")
	not content_contains("aws_s3_bucket_logging")
	msg := sprintf("[%v] S3 bucket without access logging — consider adding aws_s3_bucket_logging", [input.file])
}

# Warning: Terraform backend state encryption
warnings contains msg if {
	content_contains("terraform {")
	content_contains("backend")
	content_contains("s3")
	not content_contains("encrypt")
	msg := sprintf("[%v] Terraform S3 backend found without encrypt = true — encrypt remote state", [input.file])
}

# Warning: Variables without validation
warnings contains msg if {
	content_contains("variable")
	not content_contains("validation")
	msg := sprintf("[%v] Terraform variables found without validation blocks — add validation to prevent misconfigurations", [input.file])
}

# ========================
# HELPER RULES
# ========================

# Check if file content contains a string (case-insensitive)
content_contains(s) if {
	contains(lower(input.content), lower(s))
}

# Check if a Terraform resource block of a given type is present
resource_block_present(resource_type) if {
	pattern := sprintf("resource \"%v", [resource_type])
	content_contains(pattern)
}

# SSH port pattern detection
cidr_on_ssh_port if {
	content_contains("from_port")
	content_contains("22")
}

# RDP port pattern detection
cidr_on_rdp_port if {
	content_contains("from_port")
	content_contains("3389")
}
