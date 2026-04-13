# ============================================================
# Kubernetes Security Policy
# Package: k8s.security
# Applies to: Kubernetes manifests (Deployments, Pods, DaemonSets, etc.)
# Author: GRIMSEC IaC Policy Agent
# ============================================================
#
# Input schema:
# {
#   "file": "path/to/manifest.yaml",
#   "resources": [
#     {
#       "apiVersion": "apps/v1",
#       "kind": "Deployment",
#       "metadata": {"name": "...", "namespace": "..."},
#       "spec": { ... }
#     }
#   ]
# }
# ============================================================

package k8s.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default violations := set()
default warnings := set()

# Workload kinds that contain pod specs and need security context checks
WORKLOAD_KINDS := {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob", "Pod"}

# ========================
# VIOLATIONS (BLOCKING)
# ========================

# Rule: Containers must run as non-root
violations contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	containers := get_containers(resource)
	container := containers[_]
	not container_runs_non_root(container, resource)
	msg := sprintf("[%v] %v/%v: Container '%v' does not set securityContext.runAsNonRoot: true",
		[input.file, resource.kind, resource.metadata.name, container.name])
}

# Rule: Root filesystem must be read-only
violations contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	containers := get_containers(resource)
	container := containers[_]
	not object.get(container, ["securityContext", "readOnlyRootFilesystem"], false)
	msg := sprintf("[%v] %v/%v: Container '%v' does not set securityContext.readOnlyRootFilesystem: true",
		[input.file, resource.kind, resource.metadata.name, container.name])
}

# Rule: Privilege escalation must be disabled
violations contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	containers := get_containers(resource)
	container := containers[_]
	not object.get(container, ["securityContext", "allowPrivilegeEscalation"], true) == false
	msg := sprintf("[%v] %v/%v: Container '%v' does not set securityContext.allowPrivilegeEscalation: false",
		[input.file, resource.kind, resource.metadata.name, container.name])
}

# Rule: ALL capabilities must be dropped
violations contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	containers := get_containers(resource)
	container := containers[_]
	not drops_all_capabilities(container)
	msg := sprintf("[%v] %v/%v: Container '%v' does not drop ALL capabilities — add securityContext.capabilities.drop: [\"ALL\"]",
		[input.file, resource.kind, resource.metadata.name, container.name])
}

# Rule: CPU and memory limits must be set
violations contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	containers := get_containers(resource)
	container := containers[_]
	not object.get(container, ["resources", "limits", "cpu"], null)
	msg := sprintf("[%v] %v/%v: Container '%v' has no CPU limit set",
		[input.file, resource.kind, resource.metadata.name, container.name])
}

violations contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	containers := get_containers(resource)
	container := containers[_]
	not object.get(container, ["resources", "limits", "memory"], null)
	msg := sprintf("[%v] %v/%v: Container '%v' has no memory limit set",
		[input.file, resource.kind, resource.metadata.name, container.name])
}

# Rule: hostNetwork must not be enabled
violations contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	pod_spec := get_pod_spec(resource)
	object.get(pod_spec, "hostNetwork", false) == true
	msg := sprintf("[%v] %v/%v: hostNetwork: true is forbidden — removes network isolation",
		[input.file, resource.kind, resource.metadata.name])
}

# Rule: hostPID must not be enabled
violations contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	pod_spec := get_pod_spec(resource)
	object.get(pod_spec, "hostPID", false) == true
	msg := sprintf("[%v] %v/%v: hostPID: true is forbidden — allows access to host process list",
		[input.file, resource.kind, resource.metadata.name])
}

# Rule: hostIPC must not be enabled
violations contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	pod_spec := get_pod_spec(resource)
	object.get(pod_spec, "hostIPC", false) == true
	msg := sprintf("[%v] %v/%v: hostIPC: true is forbidden — allows access to host IPC namespace",
		[input.file, resource.kind, resource.metadata.name])
}

# Rule: Container images should not use :latest tag
violations contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	containers := get_containers(resource)
	container := containers[_]
	image := container.image
	endswith(image, ":latest")
	msg := sprintf("[%v] %v/%v: Container '%v' uses image tag ':latest' — pin to a specific digest or version tag",
		[input.file, resource.kind, resource.metadata.name, container.name])
}

violations contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	containers := get_containers(resource)
	container := containers[_]
	image := container.image
	not contains(image, ":")
	msg := sprintf("[%v] %v/%v: Container '%v' uses image with no tag (implicit :latest) — pin to a specific version",
		[input.file, resource.kind, resource.metadata.name, container.name])
}

# Rule: Secrets should not be in environment variables as plaintext
violations contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	containers := get_containers(resource)
	container := containers[_]
	env_var := container.env[_]
	not env_var.valueFrom
	is_secret_env_name(env_var.name)
	msg := sprintf("[%v] %v/%v: Container '%v' has env var '%v' that may contain a hardcoded secret — use secretKeyRef instead",
		[input.file, resource.kind, resource.metadata.name, container.name, env_var.name])
}

# Rule: Service accounts should not auto-mount tokens unless necessary
violations contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	pod_spec := get_pod_spec(resource)
	not object.get(pod_spec, "automountServiceAccountToken", true) == false
	msg := sprintf("[%v] %v/%v: automountServiceAccountToken should be set to false unless service account access is required",
		[input.file, resource.kind, resource.metadata.name])
}

# ========================
# WARNINGS (NON-BLOCKING)
# ========================

# Warning: No NetworkPolicy in the namespace
warnings contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	ns := object.get(resource.metadata, "namespace", "default")
	not namespace_has_network_policy(ns)
	msg := sprintf("[%v] %v/%v: No NetworkPolicy found for namespace '%v' — define ingress/egress rules",
		[input.file, resource.kind, resource.metadata.name, ns])
}

# Warning: No liveness probe configured
warnings contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	containers := get_containers(resource)
	container := containers[_]
	not container.livenessProbe
	msg := sprintf("[%v] %v/%v: Container '%v' has no livenessProbe configured",
		[input.file, resource.kind, resource.metadata.name, container.name])
}

# Warning: No readiness probe configured
warnings contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	containers := get_containers(resource)
	container := containers[_]
	not container.readinessProbe
	msg := sprintf("[%v] %v/%v: Container '%v' has no readinessProbe configured",
		[input.file, resource.kind, resource.metadata.name, container.name])
}

# Warning: No CPU requests set
warnings contains msg if {
	resource := input.resources[_]
	resource.kind in WORKLOAD_KINDS
	containers := get_containers(resource)
	container := containers[_]
	not object.get(container, ["resources", "requests", "cpu"], null)
	msg := sprintf("[%v] %v/%v: Container '%v' has no CPU request set — may cause scheduling issues",
		[input.file, resource.kind, resource.metadata.name, container.name])
}

# ========================
# HELPER RULES
# ========================

# Extract containers from various workload kinds
get_containers(resource) := containers if {
	resource.kind == "Pod"
	containers := resource.spec.containers
}

get_containers(resource) := containers if {
	resource.kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet"}
	containers := resource.spec.template.spec.containers
}

get_containers(resource) := containers if {
	resource.kind == "Job"
	containers := resource.spec.template.spec.containers
}

get_containers(resource) := containers if {
	resource.kind == "CronJob"
	containers := resource.spec.jobTemplate.spec.template.spec.containers
}

# Extract pod spec from workload
get_pod_spec(resource) := spec if {
	resource.kind == "Pod"
	spec := resource.spec
}

get_pod_spec(resource) := spec if {
	resource.kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"}
	spec := resource.spec.template.spec
}

get_pod_spec(resource) := spec if {
	resource.kind == "CronJob"
	spec := resource.spec.jobTemplate.spec.template.spec
}

# Check if container runs as non-root (accounting for pod-level and container-level contexts)
container_runs_non_root(container, resource) if {
	object.get(container, ["securityContext", "runAsNonRoot"], false) == true
}

container_runs_non_root(container, resource) if {
	pod_spec := get_pod_spec(resource)
	object.get(pod_spec, ["securityContext", "runAsNonRoot"], false) == true
}

container_runs_non_root(container, resource) if {
	run_as_user := object.get(container, ["securityContext", "runAsUser"], 0)
	run_as_user > 0
}

container_runs_non_root(container, resource) if {
	pod_spec := get_pod_spec(resource)
	run_as_user := object.get(pod_spec, ["securityContext", "runAsUser"], 0)
	run_as_user > 0
}

# Check if container drops ALL capabilities
drops_all_capabilities(container) if {
	caps := object.get(container, ["securityContext", "capabilities", "drop"], [])
	"ALL" in caps
}

# Check if a namespace has a NetworkPolicy in the current file's resources
namespace_has_network_policy(ns) if {
	resource := input.resources[_]
	resource.kind == "NetworkPolicy"
	object.get(resource.metadata, "namespace", "default") == ns
}

# Secret environment variable name patterns
SECRET_ENV_PATTERNS := [
	"PASSWORD", "PASSWD", "PWD",
	"SECRET", "TOKEN", "API_KEY",
	"PRIVATE_KEY", "CREDENTIALS",
	"DATABASE_URL", "DB_PASSWORD",
	"AWS_SECRET", "AWS_ACCESS_KEY",
]

is_secret_env_name(name) if {
	upper_name := upper(name)
	pattern := SECRET_ENV_PATTERNS[_]
	contains(upper_name, pattern)
}
