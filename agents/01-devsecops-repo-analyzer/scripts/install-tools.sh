#!/usr/bin/env bash
# install-tools.sh — Install all scanning tools required by devsecops-repo-analyzer
# Idempotent: safe to run multiple times.
set -euo pipefail

echo "=== DevSecOps Repo Analyzer — Tool Installation ==="

# ---------- Python tools ----------
echo "[1/6] Installing Semgrep..."
if command -v semgrep &>/dev/null; then
  echo "  Semgrep already installed: $(semgrep --version 2>/dev/null || echo 'unknown version')"
else
  pip install --quiet semgrep
  echo "  Semgrep installed: $(semgrep --version 2>/dev/null || echo 'done')"
fi

# ---------- Trivy ----------
echo "[2/6] Installing Trivy..."
if command -v trivy &>/dev/null; then
  echo "  Trivy already installed: $(trivy --version 2>/dev/null | head -1)"
else
  # Install via official install script
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin latest 2>/dev/null
  echo "  Trivy installed: $(trivy --version 2>/dev/null | head -1)"
fi

# ---------- Grype ----------
echo "[3/6] Installing Grype..."
if command -v grype &>/dev/null; then
  echo "  Grype already installed: $(grype version 2>/dev/null | head -1)"
else
  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null
  echo "  Grype installed: $(grype version 2>/dev/null | head -1)"
fi

# ---------- Gitleaks ----------
echo "[4/6] Installing Gitleaks..."
if command -v gitleaks &>/dev/null; then
  echo "  Gitleaks already installed: $(gitleaks version 2>/dev/null)"
else
  GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
  if [ -z "$GITLEAKS_VERSION" ]; then
    GITLEAKS_VERSION="8.21.2"
  fi
  curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar xz -C /usr/local/bin gitleaks 2>/dev/null
  chmod +x /usr/local/bin/gitleaks
  echo "  Gitleaks installed: $(gitleaks version 2>/dev/null)"
fi

# ---------- Snyk CLI ----------
echo "[5/6] Installing Snyk CLI..."
if command -v snyk &>/dev/null; then
  echo "  Snyk already installed: $(snyk --version 2>/dev/null)"
else
  if command -v npm &>/dev/null; then
    npm install -g snyk 2>/dev/null
    echo "  Snyk installed: $(snyk --version 2>/dev/null)"
  else
    # Fallback: download standalone binary
    curl --compressed https://downloads.snyk.io/cli/stable/snyk-linux -o /usr/local/bin/snyk 2>/dev/null
    chmod +x /usr/local/bin/snyk
    echo "  Snyk installed (standalone): $(snyk --version 2>/dev/null)"
  fi
fi

# ---------- Python dependencies ----------
echo "[6/6] Installing Python dependencies..."
pip install --quiet jinja2 tabulate 2>/dev/null
echo "  Python dependencies installed."

echo ""
echo "=== All tools installed ==="
echo ""
echo "Verification:"
echo "  semgrep:  $(command -v semgrep 2>/dev/null && echo 'OK' || echo 'MISSING')"
echo "  trivy:    $(command -v trivy 2>/dev/null && echo 'OK' || echo 'MISSING')"
echo "  grype:    $(command -v grype 2>/dev/null && echo 'OK' || echo 'MISSING')"
echo "  gitleaks: $(command -v gitleaks 2>/dev/null && echo 'OK' || echo 'MISSING')"
echo "  snyk:     $(command -v snyk 2>/dev/null && echo 'OK' || echo 'MISSING')"
echo ""
echo "Note: Snyk requires authentication. Run 'snyk auth' or set SNYK_TOKEN env var."
echo "      Snyk will be skipped during scans if not authenticated."
