#!/usr/bin/env bash
# =============================================================================
# GRIMSEC IaC Policy Agent — Tool Installer
# Installs: Checkov, OPA, conftest, Syft
# Idempotent: safe to run multiple times
# =============================================================================

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()    { echo -e "${BOLD}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*" >&2; }

# Detect OS and architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH_SHORT="amd64" ;;
  aarch64|arm64) ARCH_SHORT="arm64" ;;
  *) warn "Unknown architecture: $ARCH — some tools may not install correctly" ;;
esac

LOCAL_BIN="${HOME}/.local/bin"
mkdir -p "$LOCAL_BIN"

# Ensure ~/.local/bin is on PATH for this session
export PATH="${LOCAL_BIN}:${PATH}"

# =============================================================================
# 1. Checkov — Python-based IaC scanner (750+ built-in policies)
# =============================================================================
install_checkov() {
  info "Checking Checkov..."
  if command -v checkov &>/dev/null; then
    CURRENT=$(checkov --version 2>/dev/null | head -1 || echo "unknown")
    success "Checkov already installed: $CURRENT"
    return 0
  fi

  info "Installing Checkov via pip..."
  if command -v pip3 &>/dev/null; then
    pip3 install --quiet --upgrade checkov
  elif command -v pip &>/dev/null; then
    pip install --quiet --upgrade checkov
  else
    error "pip not found — please install Python 3 and pip first"
    return 1
  fi

  if command -v checkov &>/dev/null; then
    success "Checkov installed: $(checkov --version 2>/dev/null | head -1)"
  else
    error "Checkov installation failed"
    return 1
  fi
}

# =============================================================================
# 2. OPA — Open Policy Agent binary
# =============================================================================
install_opa() {
  info "Checking OPA..."
  if command -v opa &>/dev/null; then
    CURRENT=$(opa version 2>/dev/null | head -1 || echo "unknown")
    success "OPA already installed: $CURRENT"
    return 0
  fi

  info "Installing OPA binary from GitHub releases..."

  # Determine the correct OPA binary name
  case "${OS}" in
    linux)
      OPA_BINARY="opa_linux_${ARCH_SHORT}_static"
      ;;
    darwin)
      OPA_BINARY="opa_darwin_${ARCH_SHORT}"
      ;;
    mingw*|msys*|cygwin*)
      OPA_BINARY="opa_windows_${ARCH_SHORT}.exe"
      ;;
    *)
      error "Unsupported OS for OPA: ${OS}"
      return 1
      ;;
  esac

  OPA_URL="https://openpolicyagent.org/downloads/latest/${OPA_BINARY}"
  DEST="${LOCAL_BIN}/opa"

  info "Downloading OPA from ${OPA_URL}..."
  if curl -fsSL -o "${DEST}" "${OPA_URL}"; then
    chmod +x "${DEST}"
    success "OPA installed: $(opa version 2>/dev/null | head -1)"
  else
    error "Failed to download OPA from ${OPA_URL}"
    warn "Try manual install: https://www.openpolicyagent.org/docs/latest/#running-opa"
    return 1
  fi
}

# =============================================================================
# 3. conftest — OPA policy testing for structured config files
# =============================================================================
install_conftest() {
  info "Checking conftest..."
  if command -v conftest &>/dev/null; then
    CURRENT=$(conftest --version 2>/dev/null | head -1 || echo "unknown")
    success "conftest already installed: $CURRENT"
    return 0
  fi

  info "Installing conftest from GitHub releases..."

  # Get latest version
  CONFTEST_VERSION=$(curl -fsSL https://api.github.com/repos/open-policy-agent/conftest/releases/latest \
    | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')

  if [[ -z "$CONFTEST_VERSION" ]]; then
    warn "Could not determine latest conftest version, using 0.52.0"
    CONFTEST_VERSION="0.52.0"
  fi

  case "${OS}" in
    linux)  CONFTEST_OS="Linux" ;;
    darwin) CONFTEST_OS="Darwin" ;;
    *)
      warn "conftest not available for ${OS} — skipping"
      return 0
      ;;
  esac

  case "${ARCH_SHORT}" in
    amd64) CONFTEST_ARCH="x86_64" ;;
    arm64) CONFTEST_ARCH="arm64" ;;
    *)     CONFTEST_ARCH="x86_64" ;;
  esac

  CONFTEST_URL="https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_${CONFTEST_OS}_${CONFTEST_ARCH}.tar.gz"

  info "Downloading conftest v${CONFTEST_VERSION}..."
  TMPDIR_CONFTEST=$(mktemp -d)
  if curl -fsSL "${CONFTEST_URL}" | tar -xz -C "${TMPDIR_CONFTEST}"; then
    mv "${TMPDIR_CONFTEST}/conftest" "${LOCAL_BIN}/conftest"
    chmod +x "${LOCAL_BIN}/conftest"
    rm -rf "${TMPDIR_CONFTEST}"
    success "conftest installed: $(conftest --version 2>/dev/null | head -1)"
  else
    error "Failed to download conftest"
    warn "Try manual install: https://www.conftest.dev/install/"
    rm -rf "${TMPDIR_CONFTEST}"
    return 1
  fi
}

# =============================================================================
# 4. Syft — SBOM generation (Anchore)
# =============================================================================
install_syft() {
  info "Checking Syft..."
  if command -v syft &>/dev/null; then
    CURRENT=$(syft --version 2>/dev/null | head -1 || echo "unknown")
    success "Syft already installed: $CURRENT"
    return 0
  fi

  info "Installing Syft via official installer script..."
  if curl -fsSL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "${LOCAL_BIN}"; then
    success "Syft installed: $(syft --version 2>/dev/null | head -1)"
  else
    error "Syft installation failed"
    warn "Try manual install: https://github.com/anchore/syft#installation"
    return 1
  fi
}

# =============================================================================
# Main
# =============================================================================
echo ""
echo "=================================================================="
echo "  GRIMSEC IaC Policy Agent — Tool Installer"
echo "=================================================================="
echo ""

FAILED=0

install_checkov  || FAILED=$((FAILED+1))
echo ""
install_opa      || FAILED=$((FAILED+1))
echo ""
install_conftest || FAILED=$((FAILED+1))
echo ""
install_syft     || FAILED=$((FAILED+1))

echo ""
echo "=================================================================="
if [[ $FAILED -eq 0 ]]; then
  echo -e "${GREEN}All tools installed successfully.${NC}"
  echo ""
  echo "Installed versions:"
  echo "  Checkov:  $(checkov --version 2>/dev/null | head -1 || echo 'not found')"
  echo "  OPA:      $(opa version 2>/dev/null | head -1 || echo 'not found')"
  echo "  conftest: $(conftest --version 2>/dev/null | head -1 || echo 'not found')"
  echo "  Syft:     $(syft --version 2>/dev/null | head -1 || echo 'not found')"
  echo ""
  echo "If tools are not found in your shell, add to PATH:"
  echo "  export PATH=\"${LOCAL_BIN}:\${PATH}\""
else
  echo -e "${YELLOW}Installation completed with ${FAILED} failure(s). Check errors above.${NC}"
fi
echo "=================================================================="
