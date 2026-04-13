# Checkov Frameworks and Policy Reference

## Overview

Checkov is a static analysis tool for Infrastructure-as-Code (IaC) that ships with 750+ built-in policies. This reference covers supported frameworks, key policy IDs, severity levels, and CLI usage.

**Install:** `pip install checkov`  
**Version:** 3.x (current)  
**Docs:** https://www.checkov.io/

---

## Supported Frameworks

| Framework | `--framework` value | File Types |
|---|---|---|
| Terraform | `terraform` | `.tf`, `.tfvars` |
| CloudFormation | `cloudformation` | `*.yaml`, `*.json`, `*.template` |
| Kubernetes | `kubernetes` | `*.yaml`, `*.yml` |
| Dockerfile | `dockerfile` | `Dockerfile*` |
| Docker Compose | `docker_compose` | `docker-compose*.yml` |
| GitHub Actions | `github_actions` | `.github/workflows/*.yml` |
| Ansible | `ansible` | playbook `*.yml` |
| Azure ARM | `arm` | `azuredeploy.json`, `*.arm.json` |
| Bicep | `bicep` | `*.bicep` |
| Helm | `helm` | `Chart.yaml`, `templates/*.yaml` |
| Kustomize | `kustomize` | `kustomization.yaml` |
| Serverless | `serverless` | `serverless.yml` |
| OpenAPI | `openapi` | `openapi.yaml`, `swagger.yaml` |
| Secrets | `secrets` | any (entropy-based) |
| SCA | `sca_package` | `package.json`, `requirements.txt`, etc. |

---

## Key CLI Flags

```bash
# Scan a directory (auto-detect frameworks)
checkov -d /path/to/repo

# Scan with specific framework
checkov -d /path/to/repo --framework terraform

# Multiple frameworks
checkov -d /path/to/repo --framework terraform kubernetes dockerfile

# Output formats
checkov -d /path/to/repo --output json
checkov -d /path/to/repo --output sarif
checkov -d /path/to/repo --output github_failed_only  # for GitHub PR annotations

# Write output to file
checkov -d /path/to/repo --output json --output-file-path ./iac-policy/

# Run specific checks only
checkov -d /path/to/repo --check CKV_AWS_19,CKV_AWS_20

# Skip checks
checkov -d /path/to/repo --skip-check CKV_AWS_123,CKV2_AWS_1

# Compact output (failures only)
checkov -d /path/to/repo --compact

# Use external custom checks
checkov -d /path/to/repo --external-checks-dir ./my-checks/

# Soft fail (exit 0 even on violations — for CI pipelines in audit mode)
checkov -d /path/to/repo --soft-fail

# Scan a single file
checkov -f /path/to/main.tf

# Scan a Terraform plan JSON
checkov --file /path/to/tfplan.json --framework terraform_plan

# Show check IDs in output
checkov -d /path/to/repo --show-skipped

# Download and show all check IDs for a framework
checkov --list --framework kubernetes
```

---

## Critical AWS Policy IDs

### S3

| Check ID | Policy | Severity |
|---|---|---|
| CKV_AWS_19 | S3 bucket has server-side encryption enabled | HIGH |
| CKV_AWS_20 | S3 bucket has public access via ACL | HIGH |
| CKV_AWS_21 | S3 bucket has versioning enabled | MEDIUM |
| CKV_AWS_52 | S3 bucket has MFA delete enabled | MEDIUM |
| CKV_AWS_70 | S3 bucket does not allow public access via bucket policy | HIGH |
| CKV2_AWS_6 | S3 bucket should have public access blocked | HIGH |
| CKV2_AWS_62 | S3 bucket should have Object Lock enabled | LOW |

### IAM

| Check ID | Policy | Severity |
|---|---|---|
| CKV_AWS_1 | IAM policies should not have full "*:*" administrative privileges | CRITICAL |
| CKV_AWS_2 | IAM users should not have console access | MEDIUM |
| CKV_AWS_9 | IAM root account should have MFA enabled | CRITICAL |
| CKV_AWS_40 | IAM policies should not be attached directly to users | MEDIUM |
| CKV_AWS_107 | IAM policies should not have root access | CRITICAL |

### EC2 / Security Groups

| Check ID | Policy | Severity |
|---|---|---|
| CKV_AWS_24 | Security group allows unrestricted access to SSH (port 22) | HIGH |
| CKV_AWS_25 | Security group allows unrestricted access to RDP (port 3389) | HIGH |
| CKV_AWS_26 | Security group allows unrestricted outbound access | MEDIUM |
| CKV_AWS_87 | EC2 instance has termination protection disabled | LOW |
| CKV_AWS_88 | EC2 instance has public IP | MEDIUM |

### RDS

| Check ID | Policy | Severity |
|---|---|---|
| CKV_AWS_16 | RDS database is not encrypted at rest | HIGH |
| CKV_AWS_17 | RDS database should not be publicly accessible | HIGH |
| CKV_AWS_77 | RDS cluster should have log exports enabled | MEDIUM |
| CKV_AWS_133 | RDS should have auto minor version upgrade enabled | LOW |
| CKV_AWS_157 | RDS cluster should have multi-AZ enabled | MEDIUM |

### Encryption / KMS

| Check ID | Policy | Severity |
|---|---|---|
| CKV_AWS_7 | KMS keys should have rotation enabled | MEDIUM |
| CKV_AWS_18 | S3 access logging should be enabled | MEDIUM |
| CKV_AWS_119 | DynamoDB should have point-in-time recovery enabled | MEDIUM |

### CloudTrail / Logging

| Check ID | Policy | Severity |
|---|---|---|
| CKV_AWS_35 | CloudTrail should have log file validation enabled | MEDIUM |
| CKV_AWS_36 | CloudTrail should have encryption enabled | HIGH |
| CKV_AWS_67 | CloudTrail should be enabled in all regions | HIGH |

### VPC / Networking

| Check ID | Policy | Severity |
|---|---|---|
| CKV_AWS_130 | VPC should not have default security group open to all | HIGH |
| CKV2_AWS_12 | VPC flow logs should be enabled | MEDIUM |

---

## Critical Kubernetes Policy IDs

| Check ID | Policy | Severity |
|---|---|---|
| CKV_K8S_1 | Container should not run as root | HIGH |
| CKV_K8S_6 | Container should not allow privilege escalation | HIGH |
| CKV_K8S_8 | Liveness probe should be configured | MEDIUM |
| CKV_K8S_9 | Readiness probe should be configured | MEDIUM |
| CKV_K8S_10 | CPU limits should be set | MEDIUM |
| CKV_K8S_11 | CPU requests should be set | MEDIUM |
| CKV_K8S_12 | Memory limits should be set | MEDIUM |
| CKV_K8S_13 | Memory requests should be set | MEDIUM |
| CKV_K8S_14 | Image should use a digest | HIGH |
| CKV_K8S_16 | Container security context should not have allowPrivilegeEscalation set to true | HIGH |
| CKV_K8S_17 | Containers should not run as root | HIGH |
| CKV_K8S_20 | Containers should not share host process ID namespace | HIGH |
| CKV_K8S_21 | Containers should not share host IPC namespace | HIGH |
| CKV_K8S_25 | Containers should not bind to privileged host ports | MEDIUM |
| CKV_K8S_28 | Containers should not share host network namespace | HIGH |
| CKV_K8S_30 | Container should use read-only root filesystem | HIGH |
| CKV_K8S_32 | Containers should not run with default capabilities | MEDIUM |
| CKV_K8S_35 | Secrets should not be hardcoded in environment variables | HIGH |
| CKV_K8S_36 | Capabilities should be restricted | MEDIUM |
| CKV_K8S_37 | Minimize capabilities added above default set | MEDIUM |
| CKV_K8S_43 | Image should not use the :latest tag | MEDIUM |

---

## Critical Dockerfile Policy IDs

| Check ID | Policy | Severity |
|---|---|---|
| CKV_DOCKER_1 | Ensure port 22 is not exposed | HIGH |
| CKV_DOCKER_2 | Ensure that HEALTHCHECK instructions have been added | MEDIUM |
| CKV_DOCKER_3 | Ensure that a user for the container has been created | HIGH |
| CKV_DOCKER_4 | Ensure that COPY is used instead of ADD for non-URL files | LOW |
| CKV_DOCKER_5 | Ensure multi-stage builds are used | MEDIUM |
| CKV_DOCKER_6 | Ensure root filesystem is mounted as read-only | HIGH |
| CKV_DOCKER_7 | Ensure that the base image uses a non latest version tag | MEDIUM |
| CKV_DOCKER_8 | Ensure the last USER is not root | HIGH |

---

## Critical GitHub Actions Policy IDs

| Check ID | Policy | Severity |
|---|---|---|
| CKV_GHA_1 | Ensure ACTIONS_ALLOW_UNSECURE_COMMANDS is not set to true | HIGH |
| CKV_GHA_2 | Ensure top-level permissions are not set to write-all | HIGH |
| CKV_GHA_3 | Ensure GitHub Actions are pinned to a full length commit SHA | HIGH |
| CKV_GHA_4 | Ensure GitHub Actions are not allowed to approve pull requests | HIGH |
| CKV_GHA_5 | Found artifact build without evidence of cosign sign during release | MEDIUM |
| CKV_GHA_6 | Ensure untrusted code is not checked out by trigger | CRITICAL |
| CKV_GHA_7 | Ensure that the latest tag is not used | MEDIUM |

---

## Azure Policy IDs

| Check ID | Policy | Severity |
|---|---|---|
| CKV_AZURE_1 | App Service Authentication is not configured | MEDIUM |
| CKV_AZURE_3 | Storage account has secure transfer required disabled | HIGH |
| CKV_AZURE_13 | Web app should use HTTPS only | HIGH |
| CKV_AZURE_22 | Web app should have monitoring enabled | MEDIUM |
| CKV_AZURE_28 | SQL server database should have BYOK transparent data encryption | HIGH |
| CKV_AZURE_33 | Storage account should use Azure Key Vault managed key | MEDIUM |
| CKV_AZURE_36 | Network security group allows unrestricted SSH access | HIGH |
| CKV_AZURE_37 | Network security group allows unrestricted RDP access | HIGH |

---

## GCP Policy IDs

| Check ID | Policy | Severity |
|---|---|---|
| CKV_GCP_4 | Storage bucket is not publicly accessible | HIGH |
| CKV_GCP_5 | Cloud Storage bucket has uniform bucket-level access disabled | MEDIUM |
| CKV_GCP_26 | KMS encryption key rotation period exceeds 90 days | MEDIUM |
| CKV_GCP_29 | Cloud SQL database should have deletion protection enabled | MEDIUM |
| CKV_GCP_40 | Project should not use legacy authorization | HIGH |
| CKV_GCP_62 | Cloud Storage bucket should log access | MEDIUM |
| CKV_GCP_87 | GKE control plane should not be public | HIGH |

---

## Compliance Framework Mapping

Checkov checks are mapped to compliance controls in `references/compliance-mappings.md`.

Key compliance flags available via `--bc-api-key` (Bridgecrew platform):
- `--check-type` can filter by `CIS`, `NIST`, `SOC2`, `PCI`, `HIPAA`

Without the Bridgecrew API key, use the manual mappings in `references/compliance-mappings.md`.

---

## Custom Checks

Checkov supports custom Python checks. Create a directory with custom check `.py` files:

```python
# my-checks/check_s3_tags.py
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

class S3RequiredTags(BaseResourceCheck):
    def __init__(self):
        name = "Ensure S3 bucket has required tags"
        id = "CKV_CUSTOM_1"
        supported_resources = ["aws_s3_bucket"]
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        tags = conf.get("tags", [{}])
        required = {"Environment", "Owner", "Name"}
        if isinstance(tags, list) and tags:
            tags = tags[0]
        if isinstance(tags, dict):
            if required.issubset(tags.keys()):
                return CheckResult.PASSED
        return CheckResult.FAILED

check = S3RequiredTags()
```

Run with:
```bash
checkov -d /path/to/repo --external-checks-dir ./my-checks/
```

---

## Output Format Reference

### JSON output structure:
```json
{
  "check_type": "terraform",
  "results": {
    "passed_checks": [
      {
        "check_id": "CKV_AWS_19",
        "check_name": "Ensure all data stored in the S3 bucket is securely encrypted at rest",
        "check_result": {"result": "passed"},
        "resource": "aws_s3_bucket.example",
        "file_path": "/main.tf",
        "file_line_range": [1, 10],
        "guideline": "https://docs.bridgecrew.io/docs/s3_14-data-encrypted-at-rest"
      }
    ],
    "failed_checks": [...],
    "skipped_checks": [...]
  },
  "summary": {
    "passed": 42,
    "failed": 8,
    "skipped": 2,
    "parsing_error": 0,
    "checkov_version": "3.x.x"
  }
}
```

---

## Performance Tips

- Use `--framework` to limit scanning to relevant frameworks (significantly faster)
- Use `--compact` in CI to reduce output volume
- Use `--check` to run only high-priority checks in pre-commit hooks
- Use `--skip-check` to suppress known false positives
- For large repos, scan sub-directories separately to parallelize
- Cache Checkov's `~/.bridgecrew` directory in CI for faster startup
