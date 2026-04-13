---
name: iac-policy-agent
description: "GRIMSEC Agent 10 — Infrastructure-as-Code security scanning and policy enforcement. Use when asked to scan IaC files, run Checkov, evaluate OPA/Rego policies, generate SBOMs, map compliance controls, or audit Terraform, Kubernetes, Docker, CloudFormation, Ansible, or GitHub Actions configurations. Trigger phrases include: scan infrastructure code, check IaC security, run Checkov, evaluate Rego policies, CIS benchmark compliance, SOC2 IaC controls, NIST 800-53 infrastructure, policy enforcement, SBOM generation, Dockerfile security, K8s security policies, Terraform security review."
license: MIT
metadata:
  author: GRIMSEC
  version: '1.0'
  suite: GRIMSEC DevSecOps
  agent-number: '10'
  suite-position: IaC Security & Policy Enforcement
---

# IaC Policy Agent

## Overview

Agent 10 in the GRIMSEC DevSecOps suite. Performs comprehensive Infrastructure-as-Code security scanning using Checkov (750+ built-in policies) and Open Policy Agent (custom organization-specific Rego policies). Covers all major IaC frameworks and maps findings to CIS, NIST 800-53, SOC 2, HIPAA, and PCI-DSS compliance frameworks.

## When to Use This Skill

Use this skill when:
- A repository or directory contains IaC files that need security scanning
- Checkov or OPA policy evaluation is requested
- Compliance posture against CIS Benchmarks, SOC 2, NIST, HIPAA, or PCI-DSS is needed
- SBOM generation from containers or filesystems is required
- GitHub Actions workflows need security policy review
- Docker or Kubernetes configurations require security hardening review
- Terraform infrastructure needs security validation
- The executive-reporting-agent needs compliance coverage data

## GRIMSEC Suite Integration

- **Reads**: `inventory.json` (produced by devsecops-repo-analyzer) to pre-locate IaC files
- **Complements**: `devsecops-repo-analyzer` Stage 3 (Trivy IaC) — this agent provides deeper scanning with 750+ Checkov policies plus custom OPA rules
- **Complements**: `cicd-pipeline-auditor` — GitHub Actions policies overlap, but OPA custom rules add organization-specific enforcement
- **Output directory**: `iac-policy/`
  - `iac-policy/checkov-results.json`
  - `iac-policy/opa-results.json`
  - `iac-policy/sbom/` (SPDX and CycloneDX formats)
  - `iac-policy/compliance-map.json`
  - `iac-policy/iac-report.md`
- **Feeds into**: `executive-reporting-agent` for compliance coverage aggregation

## Setup

Before first use, run the installer:

```bash
bash scripts/install-iac-tools.sh
```

This installs Checkov, OPA, conftest, and Syft. The script is idempotent — safe to run again.

## Pipeline

```
Input: Repository path (auto-detects IaC files)
  │
  ├─► Phase 1: IaC Discovery
  ├─► Phase 2: Checkov Scan (750+ built-in policies)
  ├─► Phase 3: OPA Custom Policies
  ├─► Phase 4: SBOM Generation (Syft)
  ├─► Phase 5: Compliance Mapping
  └─► Phase 6: Report Generation
```

---

## Phase 1: IaC Discovery

Identify all IaC files in the target repository before scanning.

**Step 1.1** — If `inventory.json` exists from a prior devsecops-repo-analyzer run, read it to get the pre-enumerated IaC file list. Skip manual discovery for any already-catalogued paths.

**Step 1.2** — Walk the repository tree to find IaC files by extension and filename pattern:

| Framework | Patterns |
|---|---|
| Terraform | `*.tf`, `*.tfvars`, `*.tfvars.json` |
| CloudFormation | `template.yaml`, `template.json`, `*-stack.yaml`, `cloudformation/*.yaml` |
| Kubernetes | `*deployment*.yaml`, `*service*.yaml`, `*ingress*.yaml`, Helm `Chart.yaml` + `values.yaml` |
| Docker | `Dockerfile*`, `docker-compose*.yml`, `docker-compose*.yaml` |
| Ansible | `playbook*.yml`, `roles/*/tasks/main.yml`, `site.yml` |
| ARM Templates | `azuredeploy.json`, `*.arm.json` |
| GitHub Actions | `.github/workflows/*.yml`, `.github/workflows/*.yaml` |

**Step 1.3** — Produce a discovery summary:
```json
{
  "terraform": [...file paths...],
  "cloudformation": [...],
  "kubernetes": [...],
  "docker": [...],
  "ansible": [...],
  "arm": [...],
  "github_actions": [...]
}
```

**Step 1.4** — Create the output directory: `mkdir -p iac-policy/sbom`

---

## Phase 2: Checkov Scan

Run `scripts/run-checkov.py` (or invoke Checkov directly). See `references/checkov-frameworks.md` for supported frameworks, policy IDs, and flags.

**Step 2.1** — Run Checkov against the repository root, outputting JSON:

```bash
python scripts/run-checkov.py --directory <repo_path> --output iac-policy/checkov-results.json
```

The wrapper auto-selects frameworks based on discovered IaC types. For targeted scanning:

```bash
checkov -d <dir> --framework terraform --output-file-path iac-policy/ --output json
checkov -d <dir> --framework kubernetes --output-file-path iac-policy/ --output json
checkov -d <dir> --framework dockerfile --output-file-path iac-policy/ --output json
checkov -d <dir> --framework github_actions --output-file-path iac-policy/ --output json
```

**Step 2.2** — Parse `iac-policy/checkov-results.json`:
- Count: total checks, passed, failed, skipped
- Group failures by: check_id, resource, severity
- Extract: check_id, check_type, resource, file_path, guideline URL

**Step 2.3** — Flag CRITICAL failures (any check matching CIS Level 1 or scoring ≥7.0 CVSS equivalent):
- No encryption at rest (CKV_AWS_19, CKV_AWS_17, CKV_GCP_26)
- Public S3 buckets (CKV_AWS_20, CKV_AWS_70)
- No MFA on root (CKV_AWS_9)
- Unrestricted security groups (CKV_AWS_24, CKV_AWS_25)
- Publicly accessible databases (CKV_AWS_17, CKV_AZURE_28)

Consult `references/checkov-frameworks.md` for the full policy ID reference.

---

## Phase 3: OPA Custom Policies

Run `scripts/run-opa.py` with the custom Rego policies in `assets/policies/`. See `references/opa-policy-guide.md` for Rego syntax guidance.

**Step 3.1** — For each IaC type, evaluate the relevant Rego policy:

```bash
python scripts/run-opa.py \
  --policy assets/policies/docker-security.rego \
  --input <dockerfile_parsed_json> \
  --output iac-policy/opa-results.json
```

| Policy File | Applies To |
|---|---|
| `assets/policies/docker-security.rego` | Dockerfiles, docker-compose |
| `assets/policies/k8s-security.rego` | K8s manifests, Helm templates |
| `assets/policies/terraform-security.rego` | Terraform `.tf` files |
| `assets/policies/github-actions.rego` | `.github/workflows/*.yml` |

**Step 3.2** — Key rules enforced per policy:

**Docker** (`docker-security.rego`):
- `deny_root_user`: USER directive must be present and non-root
- `deny_unpinned_base`: Base image must use `@sha256:...` digest
- `deny_secrets_in_env`: ENV/ARG keys must not match secret name patterns
- `warn_no_multistage`: Single-stage builds flagged as warning
- `warn_no_healthcheck`: Missing HEALTHCHECK flagged as warning

**Kubernetes** (`k8s-security.rego`):
- `deny_root_container`: `securityContext.runAsNonRoot: true` required
- `deny_writable_root_fs`: `readOnlyRootFilesystem: true` required
- `deny_privilege_escalation`: `allowPrivilegeEscalation: false` required
- `deny_all_capabilities`: `capabilities.drop: ["ALL"]` required
- `deny_no_limits`: CPU and memory limits required on all containers
- `deny_host_network`: `hostNetwork`, `hostPID`, `hostIPC` must be false
- `warn_no_network_policy`: Namespace should have a NetworkPolicy

**Terraform** (`terraform-security.rego`):
- `deny_public_s3`: `aws_s3_bucket_public_access_block` with all true required
- `deny_unencrypted_s3`: Bucket encryption required
- `deny_unversioned_s3`: S3 versioning must be enabled
- `deny_public_rds`: `publicly_accessible = false` required
- `deny_unencrypted_rds`: `storage_encrypted = true` required
- `deny_single_az_rds`: `multi_az = true` recommended
- `deny_open_sg`: Security groups must not allow `0.0.0.0/0` on non-80/443 ports
- `deny_untagged`: All resources require mandatory tags (Name, Environment, Owner)

**GitHub Actions** (`github-actions.rego`):
- `deny_unpinned_action`: Third-party actions must be pinned to full 40-char SHA
- `deny_missing_permissions`: Workflow/job must have explicit `permissions:` block
- `deny_pull_request_target_checkout`: `pull_request_target` + checkout of `${{ github.event.pull_request.head.ref }}` is forbidden
- `deny_expression_injection`: `${{ github.event.*}}` in `run:` steps is flagged
- `deny_secret_in_arg`: Secrets must not be passed as CLI arguments

**Step 3.3** — Merge OPA results into `iac-policy/opa-results.json`:
```json
{
  "docker": {"violations": [...], "warnings": [...]},
  "kubernetes": {"violations": [...], "warnings": [...]},
  "terraform": {"violations": [...], "warnings": [...]},
  "github_actions": {"violations": [...], "warnings": [...]}
}
```

---

## Phase 4: SBOM Generation

Generate Software Bill of Materials for container images and filesystems using Syft.

**Step 4.1** — For each Dockerfile discovered, attempt SBOM generation:
```bash
# From filesystem (always works without building)
syft dir:<repo_path> -o spdx-json > iac-policy/sbom/filesystem-sbom.spdx.json
syft dir:<repo_path> -o cyclonedx-json > iac-policy/sbom/filesystem-sbom.cdx.json
```

**Step 4.2** — If container images are referenced and available locally:
```bash
syft <image:tag> -o spdx-json > iac-policy/sbom/<image-name>-sbom.spdx.json
syft <image:tag> -o cyclonedx-json > iac-policy/sbom/<image-name>-sbom.cdx.json
```

**Step 4.3** — Summarize SBOM contents:
- Total packages catalogued
- Package types (deb, rpm, apk, python, npm, go, java, etc.)
- Any packages with known CVEs (cross-reference against Syft output if Grype is available)

**Step 4.4** — If Syft is not available, note in report: "SBOM generation skipped — run `bash scripts/install-iac-tools.sh` to install Syft."

---

## Phase 5: Compliance Mapping

Map Checkov and OPA findings to compliance framework controls. See `references/compliance-mappings.md` for the full control mapping table.

**Step 5.1** — Load the compliance mapping table from `references/compliance-mappings.md`.

**Step 5.2** — For each Checkov check_id in the results, look up its compliance mappings:
- CIS AWS Benchmark (1.x, 2.x, 3.x, 4.x, 5.x)
- CIS Kubernetes Benchmark
- SOC 2 Type II (CC6.x, CC7.x, CC8.x)
- NIST 800-53 (AC, AU, CM, IA, SC, SI control families)
- HIPAA (§164.312)
- PCI-DSS (Req 1, 2, 6, 7, 8, 10, 11)

**Step 5.3** — For each control, determine status:
- **PASS**: All checks mapping to this control passed
- **FAIL**: One or more checks mapping to this control failed
- **PARTIAL**: Some checks pass, some fail
- **UNKNOWN**: No checks available for this control

**Step 5.4** — Write `iac-policy/compliance-map.json`:
```json
{
  "cis_aws": {
    "1.1": {"status": "PASS", "checks": ["CKV_AWS_9"], "description": "..."},
    "2.1.1": {"status": "FAIL", "checks": ["CKV_AWS_19"], "failing_resources": [...]}
  },
  "soc2": { ... },
  "nist_800_53": { ... },
  "hipaa": { ... },
  "pci_dss": { ... }
}
```

**Step 5.5** — Calculate per-framework pass rate:
- `(PASS controls) / (PASS + FAIL + PARTIAL controls) * 100`

---

## Phase 6: Report Generation

Produce the final security report using the template at `assets/templates/iac-report-template.md`.

**Step 6.1** — Fill in all sections of the template:
- Executive summary with pass rates and critical finding count
- IaC discovery summary table
- Checkov results by framework and severity
- OPA violation summary per policy domain
- SBOM summary
- Compliance framework heat map
- Top 10 critical findings with remediation steps
- Full findings appendix

**Step 6.2** — Write to `iac-policy/iac-report.md`.

**Step 6.3** — Print a brief console summary:
```
IaC Policy Agent — Scan Complete
=================================
Frameworks scanned: Terraform, Kubernetes, Docker, GitHub Actions
Checkov checks run: 847  |  Passed: 623  |  Failed: 224
OPA violations:     37   |  Warnings: 12
SBOM packages:      1,842
Compliance coverage: CIS AWS 74% | SOC2 68% | NIST 71%

Critical findings: 8 — see iac-policy/iac-report.md
```

---

## Error Handling

| Situation | Action |
|---|---|
| Checkov not installed | Run `bash scripts/install-iac-tools.sh`, then retry |
| OPA not in PATH | Run `bash scripts/install-iac-tools.sh`, then retry |
| No IaC files found | Report "No IaC files detected in `<path>`" and exit cleanly |
| Checkov parse error on a file | Log the file, skip it, continue scanning others |
| OPA policy evaluation error | Log the policy name and input file, skip that combination |
| Syft unavailable | Skip SBOM phase, note in report |
| `inventory.json` absent | Skip Step 1.1, perform full discovery |

---

## Output File Reference

| File | Description |
|---|---|
| `iac-policy/checkov-results.json` | Raw Checkov JSON output with all check results |
| `iac-policy/opa-results.json` | Aggregated OPA policy evaluation results |
| `iac-policy/sbom/filesystem-sbom.spdx.json` | SPDX-format filesystem SBOM |
| `iac-policy/sbom/filesystem-sbom.cdx.json` | CycloneDX-format filesystem SBOM |
| `iac-policy/compliance-map.json` | Control-by-control compliance status |
| `iac-policy/iac-report.md` | Full human-readable security report |

## References

- `references/checkov-frameworks.md` — All supported frameworks, policy IDs, and CLI flags
- `references/opa-policy-guide.md` — Writing and testing Rego policies
- `references/compliance-mappings.md` — CIS, NIST 800-53, SOC 2, HIPAA, PCI-DSS control mappings
