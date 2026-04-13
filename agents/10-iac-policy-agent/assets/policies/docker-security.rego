# ============================================================
# Docker Security Policy
# Package: docker.security
# Applies to: Dockerfiles (parsed via run-opa.py)
# Author: GRIMSEC IaC Policy Agent
# ============================================================
#
# Input schema:
# {
#   "file": "path/to/Dockerfile",
#   "instructions": [
#     {"line": 1, "instruction": "FROM", "value": "ubuntu:22.04", "raw": "..."},
#     ...
#   ],
#   "has_user": true,
#   "has_healthcheck": false,
#   "has_multistage": false,
#   "from_instructions": [...],
#   "env_instructions": [...]
# }
# ============================================================

package docker.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default violations := set()
default warnings := set()

# ========================
# VIOLATIONS (BLOCKING)
# ========================

# Rule: Container must have a USER directive specifying a non-root user
violations contains msg if {
	not input.has_user
	msg := sprintf("[%v] No USER directive found — container will run as root by default", [input.file])
}

violations contains msg if {
	input.has_user
	instr := input.instructions[_]
	instr.instruction == "USER"
	last_user_is_root(instr.value)
	msg := sprintf("[%v] Line %v: USER directive sets root user ('%v') — use a non-root UID or username", [input.file, instr.line, instr.value])
}

# Rule: Base images must be pinned to a digest (@sha256:...)
violations contains msg if {
	instr := input.instructions[_]
	instr.instruction == "FROM"
	not contains(instr.value, "@sha256:")
	not is_scratch(instr.value)
	msg := sprintf("[%v] Line %v: FROM uses unpinned base image '%v' — pin to digest with @sha256:...", [input.file, instr.line, instr.value])
}

# Rule: No secrets in ENV instructions
violations contains msg if {
	instr := input.env_instructions[_]
	instr.instruction == "ENV"
	env_key := get_env_key(instr.value)
	is_secret_name(env_key)
	msg := sprintf("[%v] Line %v: ENV key '%v' may expose a secret — use Docker secrets or build args with no default value", [input.file, instr.line, env_key])
}

# Rule: No secrets in ARG instructions (if ARG has a default value)
violations contains msg if {
	instr := input.env_instructions[_]
	instr.instruction == "ARG"
	contains(instr.value, "=")
	arg_key := split(instr.value, "=")[0]
	is_secret_name(arg_key)
	msg := sprintf("[%v] Line %v: ARG '%v' has a default value and may expose a secret — set secrets at build time without defaults", [input.file, instr.line, arg_key])
}

# Rule: SSH port 22 must not be EXPOSEd
violations contains msg if {
	instr := input.instructions[_]
	instr.instruction == "EXPOSE"
	exposed_ports := get_ports(instr.value)
	"22" in exposed_ports
	msg := sprintf("[%v] Line %v: EXPOSE 22 is prohibited — never expose SSH in containers", [input.file, instr.line])
}

# Rule: ADD should not be used for local files (use COPY instead)
violations contains msg if {
	instr := input.instructions[_]
	instr.instruction == "ADD"
	not is_url_or_archive(instr.value)
	msg := sprintf("[%v] Line %v: ADD used for local files — use COPY instead (ADD has unintended side effects with local paths)", [input.file, instr.line])
}

# ========================
# WARNINGS (NON-BLOCKING)
# ========================

# Warning: Multi-stage builds recommended
warnings contains msg if {
	not input.has_multistage
	msg := sprintf("[%v] Multi-stage build not used — consider multi-stage builds to reduce final image size and attack surface", [input.file])
}

# Warning: HEALTHCHECK recommended
warnings contains msg if {
	not input.has_healthcheck
	msg := sprintf("[%v] No HEALTHCHECK instruction found — add a HEALTHCHECK to enable container health monitoring", [input.file])
}

# Warning: latest tag used (not pinned by digest)
warnings contains msg if {
	instr := input.instructions[_]
	instr.instruction == "FROM"
	not contains(instr.value, "@sha256:")
	not contains(instr.value, ":")
	msg := sprintf("[%v] Line %v: FROM '%v' uses implicit :latest tag — pin to a specific version or digest", [input.file, instr.line, instr.value])
}

warnings contains msg if {
	instr := input.instructions[_]
	instr.instruction == "FROM"
	endswith(instr.value, ":latest")
	msg := sprintf("[%v] Line %v: FROM uses :latest tag — pin to a specific version or digest", [input.file, instr.line])
}

# Warning: Running apt/yum without --no-install-recommends
warnings contains msg if {
	instr := input.instructions[_]
	instr.instruction == "RUN"
	contains(instr.value, "apt-get install")
	not contains(instr.value, "--no-install-recommends")
	msg := sprintf("[%v] Line %v: apt-get install without --no-install-recommends — increases image size unnecessarily", [input.file, instr.line])
}

# ========================
# HELPER RULES
# ========================

# Check if a USER value resolves to root
last_user_is_root(user_value) if {
	lower_value := lower(user_value)
	lower_value == "root"
}

last_user_is_root(user_value) if {
	user_value == "0"
}

last_user_is_root(user_value) if {
	# user:group format where user is root
	user_part := split(user_value, ":")[0]
	user_part == "root"
}

last_user_is_root(user_value) if {
	user_part := split(user_value, ":")[0]
	user_part == "0"
}

# Check if an image reference is scratch (valid to not have digest)
is_scratch(image) if {
	image == "scratch"
}

# Extract the key name from ENV instruction (KEY=value or KEY value)
get_env_key(env_value) := key if {
	contains(env_value, "=")
	key := split(env_value, "=")[0]
}

get_env_key(env_value) := key if {
	not contains(env_value, "=")
	key := split(env_value, " ")[0]
}

# Check if a key name matches known secret patterns
SECRET_PATTERNS := [
	"PASSWORD", "PASSWD", "PWD",
	"SECRET", "SECRETS",
	"API_KEY", "APIKEY",
	"TOKEN", "ACCESS_TOKEN", "AUTH_TOKEN",
	"PRIVATE_KEY", "PRIVATE_KEY_ID",
	"CREDENTIAL", "CREDENTIALS",
	"DATABASE_URL", "DB_PASSWORD", "DB_PASS",
	"AWS_SECRET", "AWS_ACCESS_KEY",
	"GITHUB_TOKEN", "GH_TOKEN",
	"STRIPE_KEY", "STRIPE_SECRET",
	"SENDGRID_API_KEY", "TWILIO_AUTH",
]

is_secret_name(key) if {
	upper_key := upper(key)
	pattern := SECRET_PATTERNS[_]
	contains(upper_key, pattern)
}

# Parse port numbers from EXPOSE instruction
get_ports(expose_value) := ports if {
	raw_ports := split(expose_value, " ")
	ports := {p | raw := raw_ports[_]; p := split(raw, "/")[0]}
}

# Check if ADD target is a URL or archive (legitimate ADD use cases)
is_url_or_archive(value) if {
	startswith(value, "http://")
}

is_url_or_archive(value) if {
	startswith(value, "https://")
}

is_url_or_archive(value) if {
	parts := split(value, " ")
	src := parts[0]
	endswith(src, ".tar.gz")
}

is_url_or_archive(value) if {
	parts := split(value, " ")
	src := parts[0]
	endswith(src, ".tar.bz2")
}

is_url_or_archive(value) if {
	parts := split(value, " ")
	src := parts[0]
	endswith(src, ".tar.xz")
}
