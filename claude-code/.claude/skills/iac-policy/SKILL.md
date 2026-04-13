# IaC Policy Agent

Comprehensive Infrastructure-as-Code security scanning using Checkov (750+ built-in policies) and OPA (custom Rego policies). Maps to CIS, NIST 800-53, SOC 2, HIPAA, PCI-DSS.

Invoke with `/iac-policy` or phrases like "scan IaC", "Checkov scan", "Terraform security", "K8s security policies".

## When to Use

- Repository contains IaC files needing security scanning
- Compliance posture assessment against CIS, SOC 2, NIST, HIPAA, or PCI-DSS
- SBOM generation from containers or filesystems
- GitHub Actions workflows need security policy review

## Setup

```bash
pip install checkov
brew install opa  # macOS, or download from https://openpolicyagent.org/
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

## Phase 1: IaC Discovery

| Framework | File Patterns |
|---|---|
| Terraform | `*.tf`, `*.tfvars` |
| CloudFormation | `template.yaml`, `*-stack.yaml` |
| Kubernetes | `*deployment*.yaml`, Helm `Chart.yaml` |
| Docker | `Dockerfile*`, `docker-compose*.yml` |
| Ansible | `playbook*.yml`, `roles/*/tasks/main.yml` |
| GitHub Actions | `.github/workflows/*.yml` |

## Phase 2: Checkov Scan

```bash
# Scan entire repository
checkov -d <repo_path> --output json --output-file-path iac-policy/

# Framework-specific
checkov -d <dir> --framework terraform --output json
checkov -d <dir> --framework kubernetes --output json
checkov -d <dir> --framework dockerfile --output json
checkov -d <dir> --framework github_actions --output json
```

**Critical checks to flag immediately:**
- `CKV_AWS_19` — S3 bucket not encrypted → CRITICAL
- `CKV_AWS_20` / `CKV_AWS_70` — S3 publicly accessible → CRITICAL
- `CKV_AWS_9` — No MFA on root → CRITICAL
- `CKV_AWS_24` / `CKV_AWS_25` — Unrestricted security groups → CRITICAL
- `CKV_AWS_17` — Publicly accessible databases → CRITICAL

## Phase 3: OPA Custom Policies

**Docker rules:** `deny_root_user`, `deny_unpinned_base`, `deny_secrets_in_env`

**Kubernetes rules:** `deny_root_container`, `deny_writable_root_fs`, `deny_privilege_escalation`, `deny_all_capabilities`, `deny_no_limits`, `deny_host_network`

**Terraform rules:** `deny_public_s3`, `deny_public_rds`, `deny_unencrypted_rds`, `deny_open_sg` (0.0.0.0/0 on non-80/443 ports)

**GitHub Actions rules:** `deny_unpinned_action`, `deny_missing_permissions`, `deny_expression_injection`

```bash
python scripts/run-opa.py \
  --policy assets/policies/docker-security.rego \
  --input <dockerfile_parsed_json> \
  --output iac-policy/opa-results.json
```

## Phase 4: SBOM Generation

```bash
syft dir:<repo_path> -o spdx-json > iac-policy/sbom/filesystem-sbom.spdx.json
syft dir:<repo_path> -o cyclonedx-json > iac-policy/sbom/filesystem-sbom.cdx.json
syft <image:tag> -o spdx-json > iac-policy/sbom/<image-name>-sbom.spdx.json
```

## Phase 5: Compliance Mapping

Map failed Checkov checks to compliance controls. Calculate pass rate per framework:
```
pass_rate = (PASS controls) / (PASS + FAIL + PARTIAL controls) × 100
```

## Phase 6: Report

Console summary format:
```
IaC Policy Agent — Scan Complete
Frameworks scanned: Terraform, Kubernetes, Docker, GitHub Actions
Checkov checks run: 847  |  Passed: 623  |  Failed: 224
OPA violations: 37  |  Warnings: 12
SBOM packages: 1,842
Compliance: CIS AWS 74% | SOC2 68% | NIST 71%
Critical findings: 8 — see iac-policy/iac-report.md
```

## Output Files

| File | Description |
|---|---|
| `iac-policy/checkov-results.json` | Raw Checkov output |
| `iac-policy/opa-results.json` | OPA evaluation results |
| `iac-policy/sbom/` | SPDX and CycloneDX SBOMs |
| `iac-policy/compliance-map.json` | Control-by-control compliance status |
| `iac-policy/iac-report.md` | Full security report |
