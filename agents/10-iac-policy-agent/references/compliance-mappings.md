# Compliance Control Mappings

Maps Checkov check IDs and OPA policy rules to compliance framework controls.
Used by Phase 5 of the IaC Policy Agent pipeline to generate `iac-policy/compliance-map.json`.

---

## CIS AWS Foundations Benchmark v1.5

| CIS Control | Title | Checkov IDs | OPA Rules |
|---|---|---|---|
| 1.1 | Maintain current contact details | — | — |
| 1.4 | Ensure no root access keys exist | CKV_AWS_9 | — |
| 1.5 | Ensure MFA is enabled for root | CKV_AWS_9 | — |
| 1.10 | Ensure MFA is enabled for IAM users | CKV_AWS_9 | — |
| 1.14 | Ensure hardware MFA is enabled for root | CKV_AWS_9 | — |
| 1.16 | Ensure IAM policies are not attached to users | CKV_AWS_40 | — |
| 2.1.1 | Ensure S3 bucket server-side encryption | CKV_AWS_19, CKV2_AWS_6 | terraform.s3_encryption |
| 2.1.2 | Ensure S3 bucket public access blocked | CKV_AWS_20, CKV_AWS_70 | terraform.deny_public_s3 |
| 2.1.5 | Ensure S3 bucket versioning enabled | CKV_AWS_21 | terraform.deny_unversioned_s3 |
| 2.2.1 | Ensure EBS volume encryption | CKV_AWS_8 | — |
| 2.3.1 | Ensure RDS encryption | CKV_AWS_16 | terraform.deny_unencrypted_rds |
| 2.3.2 | Ensure RDS auto minor upgrade | CKV_AWS_133 | — |
| 2.3.3 | Ensure RDS not publicly accessible | CKV_AWS_17 | terraform.deny_public_rds |
| 3.1 | CloudTrail enabled in all regions | CKV_AWS_67 | — |
| 3.2 | CloudTrail log validation enabled | CKV_AWS_35 | — |
| 3.4 | CloudTrail log encrypted | CKV_AWS_36 | — |
| 4.1 | No unrestricted SSH (0.0.0.0/0:22) | CKV_AWS_24 | terraform.deny_open_sg |
| 4.2 | No unrestricted RDP (0.0.0.0/0:3389) | CKV_AWS_25 | terraform.deny_open_sg |
| 4.3 | No unrestricted traffic to all ports | CKV_AWS_26 | terraform.deny_open_sg |
| 5.1 | Ensure no default VPC security group | CKV_AWS_130 | — |
| 5.4 | Ensure VPC flow logging enabled | CKV2_AWS_12 | — |

---

## CIS Kubernetes Benchmark v1.8

| CIS Control | Title | Checkov IDs | OPA Rules |
|---|---|---|---|
| 4.1.1 | Ensure service account tokens not auto-mounted | CKV_K8S_43 | — |
| 4.2.1 | Minimize privileged containers | CKV_K8S_16 | k8s.deny_privilege_escalation |
| 4.2.2 | Minimize containers that run as root | CKV_K8S_1, CKV_K8S_17 | k8s.deny_root_container |
| 4.2.3 | Minimize containers with NET_RAW | CKV_K8S_36 | k8s.deny_all_capabilities |
| 4.2.4 | Minimize containers with added capabilities | CKV_K8S_37 | k8s.deny_all_capabilities |
| 4.2.5 | Minimize containers with root FS writable | CKV_K8S_30 | k8s.deny_writable_root_fs |
| 4.2.6 | Minimize AppArmor not set to default | — | — |
| 4.2.7 | Minimize Seccomp not set | — | — |
| 4.2.8 | Minimize hostProcess privilege | CKV_K8S_20, CKV_K8S_21 | k8s.deny_host_network |
| 4.2.9 | Minimize hostNetwork | CKV_K8S_28 | k8s.deny_host_network |
| 4.2.10 | Minimize hostPort | CKV_K8S_25 | — |
| 5.1.1 | Prefer RBAC over ABAC | — | — |
| 5.2.1 | Minimize wildcard in Roles and ClusterRoles | — | — |
| 5.4.1 | Prefer secrets as files over env vars | CKV_K8S_35 | — |
| 5.6.3 | Minimize admission controller usage | — | — |
| 5.7.1 | Create network policies | — | k8s.warn_no_network_policy |
| 5.7.2 | Ensure all namespaces have network policies | — | k8s.warn_no_network_policy |
| 5.7.3 | Ensure no default deny policy missing | — | k8s.warn_no_network_policy |

---

## SOC 2 Type II — Trust Services Criteria

### CC6 — Logical and Physical Access Controls

| Control | Title | Checkov IDs | OPA Rules |
|---|---|---|---|
| CC6.1 | Logical access security software | CKV_AWS_1, CKV_AWS_40 | — |
| CC6.2 | New internal user access | — | — |
| CC6.3 | Remove/modify user access timely | — | — |
| CC6.6 | Logical access restrictions (external threats) | CKV_AWS_24, CKV_AWS_25 | terraform.deny_open_sg |
| CC6.7 | Restrict transmission of data | CKV_AWS_19, CKV_AWS_16 | terraform.deny_unencrypted_rds |
| CC6.8 | Prevent unauthorized access (malware) | CKV_AWS_20 | terraform.deny_public_s3 |

### CC7 — System Operations

| Control | Title | Checkov IDs | OPA Rules |
|---|---|---|---|
| CC7.1 | Detect and monitor for configuration changes | CKV_AWS_35, CKV_AWS_67 | — |
| CC7.2 | Monitor system components for anomalous behavior | CKV_AWS_36 | — |
| CC7.3 | Evaluate security events | CKV2_AWS_12 | — |
| CC7.4 | Respond to identified security incidents | — | — |
| CC7.5 | Recover from identified security incidents | CKV_AWS_21, CKV_AWS_157 | terraform.deny_unversioned_s3 |

### CC8 — Change Management

| Control | Title | Checkov IDs | OPA Rules |
|---|---|---|---|
| CC8.1 | Authorize and approve infrastructure changes | CKV_GHA_3 | github.deny_unpinned_action |
| CC8.1 | Pin infrastructure automation to known versions | CKV_DOCKER_7, CKV_K8S_43 | docker.deny_unpinned_base |

---

## NIST 800-53 Rev 5

### AC — Access Control

| Control | Title | Checkov IDs | OPA Rules |
|---|---|---|---|
| AC-2 | Account Management | CKV_AWS_1, CKV_AWS_2 | — |
| AC-3 | Access Enforcement | CKV_AWS_40 | k8s.deny_privilege_escalation |
| AC-6 | Least Privilege | CKV_GHA_2, CKV_K8S_16 | github.deny_missing_permissions |
| AC-17 | Remote Access | CKV_AWS_24, CKV_AWS_25 | terraform.deny_open_sg |

### AU — Audit and Accountability

| Control | Title | Checkov IDs | OPA Rules |
|---|---|---|---|
| AU-2 | Event Logging | CKV_AWS_67, CKV_AWS_35 | — |
| AU-3 | Content of Audit Records | CKV_AWS_36 | — |
| AU-9 | Protection of Audit Information | CKV_AWS_36 | — |
| AU-12 | Audit Record Generation | CKV2_AWS_12 | — |

### CM — Configuration Management

| Control | Title | Checkov IDs | OPA Rules |
|---|---|---|---|
| CM-2 | Baseline Configuration | CKV_AWS_21 | — |
| CM-6 | Configuration Settings | CKV_K8S_30, CKV_K8S_6 | k8s.deny_writable_root_fs |
| CM-7 | Least Functionality | CKV_K8S_32, CKV_K8S_37 | k8s.deny_all_capabilities |
| CM-8 | System Component Inventory | — | *(SBOM Phase 4)* |

### IA — Identification and Authentication

| Control | Title | Checkov IDs | OPA Rules |
|---|---|---|---|
| IA-2 | Identification and Authentication | CKV_AWS_9 | — |
| IA-5 | Authenticator Management | CKV_K8S_35 | docker.deny_secrets_in_env |

### SC — System and Communications Protection

| Control | Title | Checkov IDs | OPA Rules |
|---|---|---|---|
| SC-4 | Information in Shared Resources | CKV_K8S_20, CKV_K8S_21 | k8s.deny_host_network |
| SC-7 | Boundary Protection | CKV_AWS_24, CKV_AWS_25 | terraform.deny_open_sg |
| SC-8 | Transmission Confidentiality | CKV_AZURE_13 | — |
| SC-28 | Protection of Information at Rest | CKV_AWS_19, CKV_AWS_16 | terraform.deny_unencrypted_rds |

### SI — System and Information Integrity

| Control | Title | Checkov IDs | OPA Rules |
|---|---|---|---|
| SI-2 | Flaw Remediation | CKV_AWS_133, CKV_DOCKER_7 | — |
| SI-3 | Malicious Code Protection | CKV_DOCKER_3 | docker.deny_root_user |
| SI-7 | Software and Information Integrity | CKV_GHA_3 | github.deny_unpinned_action |
| SI-10 | Information Input Validation | CKV_GHA_6 | github.deny_pull_request_target |

---

## HIPAA Security Rule (45 CFR Part 164)

| Safeguard | Section | Title | Checkov IDs | OPA Rules |
|---|---|---|---|---|
| Technical | §164.312(a)(1) | Access Control | CKV_AWS_1, CKV_AWS_40 | — |
| Technical | §164.312(a)(2)(i) | Unique User Identification | CKV_AWS_9 | — |
| Technical | §164.312(b) | Audit Controls | CKV_AWS_35, CKV_AWS_67 | — |
| Technical | §164.312(c)(1) | Integrity | CKV_AWS_21, CKV_AWS_36 | — |
| Technical | §164.312(d) | Authentication | CKV_AWS_9 | — |
| Technical | §164.312(e)(1) | Transmission Security | CKV_AWS_19 | — |
| Technical | §164.312(e)(2)(ii) | Encryption and Decryption | CKV_AWS_16, CKV_AWS_19 | terraform.deny_unencrypted_rds |
| Administrative | §164.308(a)(5) | Security Awareness | — | — |

---

## PCI-DSS v4.0

| Requirement | Title | Checkov IDs | OPA Rules |
|---|---|---|---|
| Req 1.2 | Network access controls | CKV_AWS_24, CKV_AWS_25 | terraform.deny_open_sg |
| Req 1.3 | Network access controls (CDE) | CKV_AWS_130 | — |
| Req 2.2 | Develop configuration standards | CKV_K8S_30, CKV_K8S_1 | k8s.deny_root_container |
| Req 6.2 | Bespoke / custom software | CKV_GHA_3 | github.deny_unpinned_action |
| Req 6.3 | Security vulnerabilities identified | — | *(SBOM Phase 4)* |
| Req 7.2 | Access control systems | CKV_AWS_1 | — |
| Req 8.2 | User identification and authentication | CKV_AWS_9 | — |
| Req 8.3 | Strong authentication for users | CKV_AWS_9 | — |
| Req 10.2 | Audit logs implemented | CKV_AWS_35, CKV_AWS_67 | — |
| Req 10.3 | Protect audit logs | CKV_AWS_36 | — |
| Req 11.3 | External and internal vulnerability scans | — | *(Checkov+OPA combined)* |

---

## Compliance Map JSON Schema

The `iac-policy/compliance-map.json` output follows this schema:

```json
{
  "scan_timestamp": "2025-01-15T10:30:00Z",
  "repository": "/path/to/repo",
  "frameworks": {
    "cis_aws": {
      "version": "1.5",
      "total_controls": 48,
      "pass": 32,
      "fail": 10,
      "partial": 3,
      "unknown": 3,
      "pass_rate": 74.4,
      "controls": {
        "2.1.1": {
          "title": "Ensure S3 bucket server-side encryption",
          "status": "FAIL",
          "checks": ["CKV_AWS_19", "CKV2_AWS_6"],
          "failing_resources": [
            "aws_s3_bucket.app-data (main.tf:23)"
          ],
          "remediation": "Add aws_s3_bucket_server_side_encryption_configuration resource"
        },
        "4.1": {
          "title": "No unrestricted SSH access",
          "status": "PASS",
          "checks": ["CKV_AWS_24"],
          "failing_resources": []
        }
      }
    },
    "cis_kubernetes": { "..." : "..." },
    "soc2": { "..." : "..." },
    "nist_800_53": { "..." : "..." },
    "hipaa": { "..." : "..." },
    "pci_dss": { "..." : "..." }
  },
  "summary": {
    "overall_pass_rate": 71.2,
    "critical_failures": 3,
    "high_failures": 12,
    "frameworks_assessed": 6
  }
}
```

---

## Pass Rate Thresholds (GRIMSEC)

| Pass Rate | Risk Level | Action Required |
|---|---|---|
| 90–100% | LOW | Maintain current controls |
| 75–89% | MEDIUM | Address failures in next sprint |
| 60–74% | HIGH | Escalate to security team |
| < 60% | CRITICAL | Block deployment / emergency remediation |
