#!/usr/bin/env bash
# GRIMSEC Tool Installer
# Installs all scanning tools required by the 12-agent pipeline.
# All checks are idempotent — safe to run multiple times.
set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}  ✓ $1${RESET}"; }
skip() { echo -e "${YELLOW}  ↷ $1 (already installed)${RESET}"; }
fail() { echo -e "${RED}  ✗ $1${RESET}"; }

OS="$(uname -s)"
ARCH="$(uname -m)"

echo ""
echo "  Installing GRIMSEC tools on ${OS}/${ARCH}"
echo ""

# ────────────────────────────────────────────────────────────────────────────
# Agent 1: Repository Analyzer
# ────────────────────────────────────────────────────────────────────────────
echo "── Agent 1: Repo Analyzer tools ────────────────────────────────────────"

# Trivy (SCA, container, IaC, secrets)
if command -v trivy &>/dev/null; then
  skip "Trivy $(trivy --version 2>/dev/null | head -1)"
else
  echo "  Installing Trivy..."
  if [[ "$OS" == "Darwin" ]]; then
    brew install aquasecurity/trivy/trivy
  elif [[ "$OS" == "Linux" ]]; then
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin latest
  else
    fail "Unsupported OS for automatic Trivy install. See https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
  fi
  ok "Trivy installed"
fi

# Semgrep (SAST)
if command -v semgrep &>/dev/null; then
  skip "Semgrep $(semgrep --version 2>/dev/null)"
else
  echo "  Installing Semgrep..."
  python3 -m pip install --quiet semgrep
  ok "Semgrep installed"
fi

# Gitleaks (secrets detection)
if command -v gitleaks &>/dev/null; then
  skip "Gitleaks $(gitleaks version 2>/dev/null)"
else
  echo "  Installing Gitleaks..."
  if [[ "$OS" == "Darwin" ]]; then
    brew install gitleaks
  elif [[ "$OS" == "Linux" ]]; then
    GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4)
    ARCH_STR="x64"
    if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then ARCH_STR="arm64"; fi
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_${ARCH_STR}.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks
    chmod +x /usr/local/bin/gitleaks
  else
    fail "Unsupported OS for automatic Gitleaks install. See https://github.com/gitleaks/gitleaks#installation"
  fi
  ok "Gitleaks installed"
fi

# Grype (SCA — fast Anchore scanner)
if command -v grype &>/dev/null; then
  skip "Grype $(grype version 2>/dev/null | head -1)"
else
  echo "  Installing Grype..."
  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin
  ok "Grype installed"
fi

# Snyk (optional — requires login)
if command -v snyk &>/dev/null; then
  skip "Snyk $(snyk --version 2>/dev/null)"
else
  echo "  Installing Snyk CLI (optional)..."
  if command -v npm &>/dev/null; then
    npm install -g snyk --quiet 2>/dev/null && ok "Snyk installed" || fail "Snyk install failed (optional)"
  else
    echo "  → npm not found. Snyk is optional. Install manually: https://docs.snyk.io/snyk-cli/install-or-update-the-snyk-cli"
  fi
fi

echo ""

# ────────────────────────────────────────────────────────────────────────────
# Agent 7: DAST Scanner
# ────────────────────────────────────────────────────────────────────────────
echo "── Agent 7: DAST Scanner tools ─────────────────────────────────────────"

# Nuclei (web vulnerability scanner)
if command -v nuclei &>/dev/null; then
  skip "Nuclei $(nuclei --version 2>/dev/null)"
else
  echo "  Installing Nuclei..."
  if [[ "$OS" == "Darwin" ]]; then
    brew install nuclei
  elif [[ "$OS" == "Linux" ]]; then
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null \
      || curl -sSfL https://raw.githubusercontent.com/projectdiscovery/nuclei/main/install.sh | bash
  fi
  ok "Nuclei installed"
fi

# Update Nuclei templates
if command -v nuclei &>/dev/null; then
  echo "  Updating Nuclei templates..."
  nuclei -update-templates -silent 2>/dev/null && ok "Nuclei templates updated" || true
fi

# httpx (fast HTTP probe)
if command -v httpx &>/dev/null; then
  skip "httpx installed"
else
  echo "  Installing httpx..."
  if [[ "$OS" == "Darwin" ]]; then
    brew install httpx
  elif command -v go &>/dev/null; then
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    ok "httpx installed"
  else
    echo "  → Go not found. Install httpx manually: https://github.com/projectdiscovery/httpx#installation"
  fi
fi

echo ""

# ────────────────────────────────────────────────────────────────────────────
# Agent 10: IaC Policy Agent
# ────────────────────────────────────────────────────────────────────────────
echo "── Agent 10: IaC Policy tools ──────────────────────────────────────────"

# Checkov (IaC static analysis)
if command -v checkov &>/dev/null; then
  skip "Checkov $(checkov --version 2>/dev/null)"
else
  echo "  Installing Checkov..."
  python3 -m pip install --quiet checkov
  ok "Checkov installed"
fi

# OPA (Open Policy Agent)
if command -v opa &>/dev/null; then
  skip "OPA $(opa version 2>/dev/null | head -1)"
else
  echo "  Installing OPA..."
  if [[ "$OS" == "Darwin" ]]; then
    brew install opa
  elif [[ "$OS" == "Linux" ]]; then
    OPA_URL="https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static"
    if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
      OPA_URL="https://openpolicyagent.org/downloads/latest/opa_linux_arm64_static"
    fi
    curl -sSL -o /usr/local/bin/opa "$OPA_URL"
    chmod +x /usr/local/bin/opa
    ok "OPA installed"
  fi
fi

# Conftest (policy testing for structured config)
if command -v conftest &>/dev/null; then
  skip "Conftest $(conftest --version 2>/dev/null)"
else
  echo "  Installing Conftest..."
  if [[ "$OS" == "Darwin" ]]; then
    brew install conftest
  elif [[ "$OS" == "Linux" ]]; then
    CONFTEST_VERSION=$(curl -s https://api.github.com/repos/open-policy-agent/conftest/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v')
    curl -sSL "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz" \
      | tar -xz -C /usr/local/bin conftest
    chmod +x /usr/local/bin/conftest
    ok "Conftest installed"
  fi
fi

# Syft (SBOM generation)
if command -v syft &>/dev/null; then
  skip "Syft $(syft --version 2>/dev/null)"
else
  echo "  Installing Syft..."
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin
  ok "Syft installed"
fi

echo ""
echo "── Summary ─────────────────────────────────────────────────────────────"
echo ""
for tool in trivy semgrep gitleaks grype nuclei httpx checkov opa conftest syft; do
  if command -v "$tool" &>/dev/null; then
    echo -e "  ${GREEN}✓${RESET} $tool"
  else
    echo -e "  ${YELLOW}↷${RESET} $tool (not installed)"
  fi
done
echo ""
echo "  Run: python grimsec.py status   for full verification"
echo ""
