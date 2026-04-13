# ============================================================
# GitHub Actions Security Policy
# Package: github.actions.security
# Applies to: .github/workflows/*.yml (parsed YAML as JSON)
# Author: GRIMSEC IaC Policy Agent
# ============================================================
#
# Input schema (parsed from workflow YAML):
# {
#   "_file": ".github/workflows/ci.yml",
#   "name": "CI",
#   "on": { "push": {...}, "pull_request": {...} },
#   "permissions": { "contents": "read" },
#   "jobs": {
#     "build": {
#       "runs-on": "ubuntu-latest",
#       "permissions": { "contents": "read" },
#       "steps": [
#         { "name": "Checkout", "uses": "actions/checkout@abc123..." },
#         { "name": "Build", "run": "make build" }
#       ]
#     }
#   }
# }
# ============================================================

package github.actions.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default violations := set()
default warnings := set()

# ========================
# VIOLATIONS (BLOCKING)
# ========================

# Rule: All third-party actions must be pinned to a full SHA (40 hex chars)
violations contains msg if {
	job_name := object.keys(input.jobs)[_]
	job := input.jobs[job_name]
	step := job.steps[_]
	action := step.uses
	action
	not is_first_party_action(action)
	not is_sha_pinned(action)
	msg := sprintf("[%v] Job '%v', step '%v': Action '%v' is not pinned to a full commit SHA — pin with @<40-char-SHA>",
		[input._file, job_name, object.get(step, "name", "(unnamed)"), action])
}

# Rule: Top-level or job-level permissions block must be explicit
violations contains msg if {
	not input.permissions
	job_name := object.keys(input.jobs)[_]
	job := input.jobs[job_name]
	not job.permissions
	msg := sprintf("[%v] Job '%v' has no explicit 'permissions' block — add permissions to follow least-privilege principle",
		[input._file, job_name])
}

# Rule: No write-all top-level permissions
violations contains msg if {
	input.permissions == "write-all"
	msg := sprintf("[%v] Top-level permissions set to 'write-all' — restrict to minimum required permissions",
		[input._file])
}

violations contains msg if {
	perms := input.permissions
	is_object(perms)
	perm_value := perms[_]
	perm_value == "write"
	msg := sprintf("[%v] Top-level permissions contain 'write' access — scope writes to only the jobs that need it",
		[input._file])
}

# Rule: pull_request_target with checkout of PR head is forbidden (code injection risk)
violations contains msg if {
	triggers := input["on"]
	triggers["pull_request_target"]
	job_name := object.keys(input.jobs)[_]
	job := input.jobs[job_name]
	step := job.steps[_]
	step.uses
	contains(step.uses, "checkout")
	step_with := object.get(step, "with", {})
	ref := object.get(step_with, "ref", "")
	is_pr_head_ref(ref)
	msg := sprintf("[%v] Job '%v': pull_request_target with checkout of PR head ref '%v' allows untrusted code execution — this is a critical security vulnerability",
		[input._file, job_name, ref])
}

# Rule: Expression injection — github.event user-controlled data in run steps
violations contains msg if {
	job_name := object.keys(input.jobs)[_]
	job := input.jobs[job_name]
	step := job.steps[_]
	run_cmd := object.get(step, "run", "")
	run_cmd != ""
	has_expression_injection(run_cmd)
	msg := sprintf("[%v] Job '%v', step '%v': run step contains potentially injectable GitHub expression — avoid '${{ github.event.* }}' directly in run commands, use intermediate env vars instead",
		[input._file, job_name, object.get(step, "name", "(unnamed)")])
}

# Rule: Secrets must not be passed as CLI arguments in run steps
violations contains msg if {
	job_name := object.keys(input.jobs)[_]
	job := input.jobs[job_name]
	step := job.steps[_]
	run_cmd := object.get(step, "run", "")
	run_cmd != ""
	has_secret_as_cli_arg(run_cmd)
	msg := sprintf("[%v] Job '%v', step '%v': Secret passed as CLI argument — use environment variables instead (secrets leak into process lists and logs)",
		[input._file, job_name, object.get(step, "name", "(unnamed)")])
}

# Rule: Workflow-level read permissions should not include write to sensitive scopes without justification
violations contains msg if {
	perms := input.permissions
	is_object(perms)
	perms["id-token"] == "write"
	msg := sprintf("[%v] Top-level id-token permission is 'write' — OIDC tokens should be scoped to specific jobs that need them",
		[input._file])
}

# Rule: No use of ACTIONS_ALLOW_UNSECURE_COMMANDS
violations contains msg if {
	job_name := object.keys(input.jobs)[_]
	job := input.jobs[job_name]
	step := job.steps[_]
	env := object.get(step, "env", {})
	env["ACTIONS_ALLOW_UNSECURE_COMMANDS"] == "true"
	msg := sprintf("[%v] Job '%v', step '%v': ACTIONS_ALLOW_UNSECURE_COMMANDS=true enables dangerous legacy workflow commands",
		[input._file, job_name, object.get(step, "name", "(unnamed)")])
}

# ========================
# WARNINGS (NON-BLOCKING)
# ========================

# Warning: Workflow uses schedule trigger without permissions restrictions
warnings contains msg if {
	triggers := input["on"]
	triggers.schedule
	not input.permissions
	msg := sprintf("[%v] Scheduled workflow without top-level permissions block — add 'permissions: read-all' as a safe default",
		[input._file])
}

# Warning: Actions pinned to version tag but not SHA
warnings contains msg if {
	job_name := object.keys(input.jobs)[_]
	job := input.jobs[job_name]
	step := job.steps[_]
	action := step.uses
	action
	not is_first_party_action(action)
	is_version_tagged(action)
	not is_sha_pinned(action)
	msg := sprintf("[%v] Job '%v', step '%v': Action '%v' is pinned to a version tag, not a SHA — version tags are mutable and can be hijacked",
		[input._file, job_name, object.get(step, "name", "(unnamed)"), action])
}

# Warning: No timeout-minutes set on jobs (can lead to runaway jobs)
warnings contains msg if {
	job_name := object.keys(input.jobs)[_]
	job := input.jobs[job_name]
	not job["timeout-minutes"]
	msg := sprintf("[%v] Job '%v' has no timeout-minutes — add a timeout to prevent runaway jobs from consuming runner minutes",
		[input._file, job_name])
}

# Warning: continue-on-error used at job level
warnings contains msg if {
	job_name := object.keys(input.jobs)[_]
	job := input.jobs[job_name]
	job["continue-on-error"] == true
	msg := sprintf("[%v] Job '%v' uses continue-on-error: true — failures will be silently ignored, which may mask security issues",
		[input._file, job_name])
}

# ========================
# HELPER RULES
# ========================

# GitHub first-party actions (trusted, don't need SHA pinning)
FIRST_PARTY_PREFIXES := [
	"actions/",
	"github/",
]

is_first_party_action(action) if {
	prefix := FIRST_PARTY_PREFIXES[_]
	startswith(action, prefix)
}

# Check if action is pinned to a 40-character hex SHA
is_sha_pinned(action) if {
	# Action format: owner/repo@<SHA> or owner/repo/path@<SHA>
	parts := split(action, "@")
	count(parts) == 2
	sha := parts[1]
	count(sha) == 40
	regex.match("^[0-9a-f]{40}$", sha)
}

# Check if action uses a version tag like @v1, @v1.2, @v1.2.3
is_version_tagged(action) if {
	parts := split(action, "@")
	count(parts) == 2
	ref := parts[1]
	startswith(ref, "v")
}

# Check if a ref is a PR head (user-controlled)
is_pr_head_ref(ref) if {
	contains(ref, "github.event.pull_request.head")
}

is_pr_head_ref(ref) if {
	contains(ref, "github.head_ref")
}

# Detect expression injection patterns in run commands
# These github.event fields are user-controlled and must not appear directly in run:
INJECTABLE_PATTERNS := [
	"github.event.issue.title",
	"github.event.issue.body",
	"github.event.pull_request.title",
	"github.event.pull_request.body",
	"github.event.comment.body",
	"github.event.review.body",
	"github.event.review_comment.body",
	"github.event.head_commit.message",
	"github.event.head_commit.author.name",
	"github.event.head_commit.author.email",
	"github.event.commits",
	"github.head_ref",
]

has_expression_injection(run_cmd) if {
	pattern := INJECTABLE_PATTERNS[_]
	contains(run_cmd, pattern)
}

# Detect secrets passed as CLI arguments (--flag ${{ secrets.X }})
has_secret_as_cli_arg(run_cmd) if {
	regex.match(`--\w+[\s=]['"]?\$\{\{.*secrets\.`, run_cmd)
}

has_secret_as_cli_arg(run_cmd) if {
	regex.match(`-\w\s+['"]?\$\{\{.*secrets\.`, run_cmd)
}
