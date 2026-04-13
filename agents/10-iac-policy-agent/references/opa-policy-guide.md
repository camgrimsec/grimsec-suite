# OPA Policy Guide — Writing Custom Rego Policies

## Overview

Open Policy Agent (OPA) uses the Rego policy language to express security rules. This guide covers the patterns used in the GRIMSEC IaC policy suite.

**Install OPA:** `bash scripts/install-iac-tools.sh`  
**OPA Docs:** https://www.openpolicyagent.org/docs/latest/  
**Rego Playground:** https://play.openpolicyagent.org/  

---

## Rego Fundamentals

### Package Declaration

Every policy file must declare a package:

```rego
package docker.security
```

The package path (`docker.security`) determines the OPA query path:
```bash
opa eval --data policy.rego --input input.json "data.docker.security.violations"
```

### Rules

Rules define sets, booleans, or objects:

```rego
# Boolean rule (true/false)
is_root if {
    input.user == "root"
}

# Set rule (collect all matching items)
violations contains msg if {
    input.user == "root"
    msg := "Container runs as root"
}

# Default rule (fallback value)
default allow := false
allow if {
    input.role == "admin"
}
```

### Iteration

Rego iterates over collections implicitly:

```rego
# Iterate over all containers in a pod spec
violations contains msg if {
    container := input.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf("Container '%v' does not set runAsNonRoot", [container.name])
}
```

The `[_]` is a wildcard iterator — it binds to every element in the array.

### Negation

Use `not` to express absence:

```rego
# Deny if securityContext is missing entirely
violations contains msg if {
    container := input.spec.containers[_]
    not container.securityContext
    msg := sprintf("Container '%v' has no securityContext", [container.name])
}
```

### Helper Rules

Break complex logic into named helper rules:

```rego
# Helper: check if a value is a valid digest
is_digest(image) if {
    contains(image, "@sha256:")
}

# Main rule using helper
violations contains msg if {
    instr := input.instructions[_]
    instr.instruction == "FROM"
    not is_digest(instr.value)
    msg := sprintf("FROM instruction uses unpinned image: %v", [instr.value])
}
```

---

## Standard Patterns for GRIMSEC Policies

### Pattern 1: Deny with message

All GRIMSEC policies use `violations contains msg` to collect all violations as a set of strings:

```rego
violations contains msg if {
    # condition
    msg := "Human-readable violation message"
}
```

### Pattern 2: Warnings (non-blocking)

Use `warnings contains msg` for recommended but non-blocking findings:

```rego
warnings contains msg if {
    not input.has_healthcheck
    msg := "HEALTHCHECK instruction not present (recommended)"
}
```

### Pattern 3: Resource-scoped checks

When iterating over multiple resources in a manifest:

```rego
violations contains msg if {
    resource := input.resources[_]
    resource.kind == "Deployment"
    container := resource.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf("[%v/%v] Container '%v': runAsNonRoot not set",
        [resource.kind, resource.metadata.name, container.name])
}
```

### Pattern 4: String matching with regex

```rego
import future.keywords.if
import future.keywords.contains

SECRET_PATTERNS := ["PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL", "API_KEY", "PRIVATE"]

violations contains msg if {
    instr := input.instructions[_]
    instr.instruction == "ENV"
    key := split(instr.value, "=")[0]
    upper_key := upper(key)
    pattern := SECRET_PATTERNS[_]
    contains(upper_key, pattern)
    msg := sprintf("ENV instruction may expose secret: %v", [key])
}
```

### Pattern 5: Allowlists

```rego
ALLOWED_BASES := {"ubuntu:22.04@sha256:", "python:3.12@sha256:", "node:20@sha256:"}

violations contains msg if {
    instr := input.instructions[_]
    instr.instruction == "FROM"
    image := instr.value
    not any_allowed(image)
    msg := sprintf("FROM uses non-approved base image: %v", [image])
}

any_allowed(image) if {
    prefix := ALLOWED_BASES[_]
    startswith(image, prefix)
}
```

---

## Testing Rego Policies

### Unit Tests

Create test files alongside policies (suffix `_test.rego`):

```rego
# docker-security_test.rego
package docker.security_test

import future.keywords.if
import data.docker.security

test_deny_root_user if {
    violations := security.violations with input as {
        "instructions": [
            {"instruction": "FROM", "value": "ubuntu@sha256:abc123"},
            {"instruction": "RUN", "value": "apt-get update"},
            # No USER directive
        ],
        "has_user": false,
        "has_healthcheck": true,
        "has_multistage": false
    }
    count(violations) > 0
}

test_allow_non_root_user if {
    violations := security.violations with input as {
        "instructions": [
            {"instruction": "FROM", "value": "ubuntu@sha256:abc123"},
            {"instruction": "USER", "value": "1000"},
        ],
        "has_user": true,
        "has_healthcheck": true,
        "has_multistage": false
    }
    # Violations should not include root user violation
    not any_root_violation(violations)
}

any_root_violation(violations) if {
    v := violations[_]
    contains(v, "root")
}
```

Run tests:
```bash
opa test assets/policies/ -v
```

### Interactive Evaluation

```bash
# Evaluate a policy against JSON input
opa eval \
  --format pretty \
  --data assets/policies/docker-security.rego \
  --input /tmp/dockerfile-input.json \
  "data.docker.security.violations"

# Run OPA REPL for exploration
opa run assets/policies/docker-security.rego
# In REPL:
# > data.docker.security.violations
# > input.instructions[_].instruction == "FROM"
```

### conftest Testing

Use conftest to test policies against raw YAML/JSON config files:

```bash
# Test Kubernetes manifests
conftest test \
  --policy assets/policies/k8s-security.rego \
  kubernetes/deployment.yaml

# Test all YAML files against all policies
conftest test \
  --policy assets/policies/ \
  --all-namespaces \
  kubernetes/*.yaml
```

---

## Input Schemas

### Dockerfile Input (from run-opa.py)

```json
{
  "file": "path/to/Dockerfile",
  "instructions": [
    {"line": 1, "instruction": "FROM", "value": "ubuntu:22.04", "raw": "FROM ubuntu:22.04"},
    {"line": 3, "instruction": "USER", "value": "1000", "raw": "USER 1000"}
  ],
  "has_user": true,
  "has_healthcheck": false,
  "has_multistage": false,
  "from_instructions": [...],
  "env_instructions": [...]
}
```

### Kubernetes Input (from run-opa.py)

```json
{
  "file": "path/to/deployment.yaml",
  "resources": [
    {
      "apiVersion": "apps/v1",
      "kind": "Deployment",
      "metadata": {"name": "myapp", "namespace": "default"},
      "spec": {
        "template": {
          "spec": {
            "containers": [
              {
                "name": "web",
                "image": "nginx:latest",
                "securityContext": {
                  "runAsNonRoot": true,
                  "readOnlyRootFilesystem": true,
                  "allowPrivilegeEscalation": false,
                  "capabilities": {"drop": ["ALL"]}
                },
                "resources": {
                  "limits": {"cpu": "500m", "memory": "128Mi"},
                  "requests": {"cpu": "250m", "memory": "64Mi"}
                }
              }
            ]
          }
        }
      }
    }
  ]
}
```

### GitHub Actions Input (from run-opa.py)

```json
{
  "_file": ".github/workflows/ci.yml",
  "name": "CI",
  "on": {"push": {"branches": ["main"]}},
  "permissions": {"contents": "read"},
  "jobs": {
    "build": {
      "runs-on": "ubuntu-latest",
      "permissions": {"contents": "read"},
      "steps": [
        {
          "name": "Checkout",
          "uses": "actions/checkout@v4.1.1"
        },
        {
          "name": "Build",
          "run": "make build"
        }
      ]
    }
  }
}
```

---

## Rego Built-in Functions Reference

### String Functions

```rego
contains(s, substr)           # true if s contains substr
startswith(s, prefix)         # true if s starts with prefix
endswith(s, suffix)           # true if s ends with suffix
upper(s)                      # uppercase string
lower(s)                      # lowercase string
split(s, delim)               # split string into array
concat(delim, arr)            # join array with delimiter
trim(s, cutset)               # trim characters from both ends
replace(s, old, new)          # replace all occurrences
sprintf(fmt, args)            # format string
regex.match(pattern, value)   # regex match
regex.find_all_string_submatch_n(pattern, s, n)  # regex capture groups
count(s)                      # length of string, array, or set
```

### Collection Functions

```rego
count(collection)             # number of elements
any(collection)               # true if any element is true
all(collection)               # true if all elements are true
sum(collection)               # sum of numeric values
min(collection)               # minimum value
max(collection)               # maximum value
sort(collection)              # sorted array
set()                         # empty set
{x | x := arr[_]; condition}  # set comprehension
[x | x := arr[_]; condition]  # array comprehension
```

### Type Functions

```rego
is_string(x)
is_number(x)
is_boolean(x)
is_array(x)
is_set(x)
is_object(x)
is_null(x)
type_name(x)
```

---

## Common Rego Pitfalls

### Pitfall 1: Undefined vs false

In Rego, an undefined result is NOT the same as `false`. If your rule body produces no matching assignments, the rule is undefined (not false). This can cause `violations` to be empty even when you expect matches.

Fix: Use `default violations := set()` to ensure violations always has a value.

### Pitfall 2: Iterating nested arrays

Wrong:
```rego
# Only checks first container
violations contains msg if {
    container := input.spec.containers
    not container.securityContext
    msg := "..."
}
```

Right:
```rego
# Checks ALL containers
violations contains msg if {
    container := input.spec.containers[_]
    not container.securityContext
    msg := "..."
}
```

### Pitfall 3: Missing imports for future keywords

OPA 0.46+ requires explicit imports for `if`, `in`, `contains`, `every`:

```rego
import future.keywords.if
import future.keywords.in
import future.keywords.contains
import future.keywords.every
```

### Pitfall 4: Object key access on missing fields

If a field may be absent, use safe access:

```rego
# UNSAFE: panics if securityContext is nil
container.securityContext.runAsNonRoot

# SAFE: evaluates to undefined if field is missing
object.get(container, ["securityContext", "runAsNonRoot"], false)
```

---

## Policy File Layout

Follow this structure for all GRIMSEC Rego policies:

```rego
# ============================================================
# Policy Name — Brief description
# Package: package.name
# Applies to: <IaC type>
# Author: GRIMSEC
# ============================================================

package <package.name>

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Default values
default violations := set()
default warnings := set()

# ========================
# VIOLATIONS (blocking)
# ========================

violations contains msg if {
    # rule body
    msg := "..."
}

# ========================
# WARNINGS (non-blocking)
# ========================

warnings contains msg if {
    # rule body
    msg := "..."
}

# ========================
# HELPER RULES
# ========================

helper_name(arg) if {
    # helper body
}
```
