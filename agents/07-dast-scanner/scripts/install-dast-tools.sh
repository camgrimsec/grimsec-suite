#!/usr/bin/env bash
# =============================================================================
# install-dast-tools.sh — GRIMSEC DAST Scanner (Agent 7)
# Installs Nuclei, OWASP ZAP (Docker), and httpx for dynamic security testing.
# Idempotent: safe to run multiple times.
# =============================================================================

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*" >&2; }

# ── Configuration ─────────────────────────────────────────────────────────────
NUCLEI_MIN_VERSION="3.0.0"
ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:stable"
HTTPX_MIN_VERSION="1.3.0"
INSTALL_DIR="${DAST_INSTALL_DIR:-$HOME/.local/bin}"
GO_BIN="${GOPATH:-$HOME/go}/bin"

mkdir -p "$INSTALL_DIR"

# Ensure INSTALL_DIR is on PATH for this session
export PATH="$INSTALL_DIR:$GO_BIN:$PATH"

# ── Helpers ───────────────────────────────────────────────────────────────────
version_gte() {
    # Returns 0 if $1 >= $2 (semver, no pre-release handling needed)
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

# ── 1. Go toolchain check (needed for go install fallback) ────────────────────
install_go() {
    info "Go not found. Installing Go 1.22 ..."
    local GO_VERSION="1.22.3"
    local ARCH
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv6l)  ARCH="armv6l" ;;
        *)       error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    local OS
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    local TARBALL="go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
    local URL="https://go.dev/dl/${TARBALL}"

    curl -fsSL "$URL" -o "/tmp/${TARBALL}"
    sudo tar -C /usr/local -xzf "/tmp/${TARBALL}"
    rm "/tmp/${TARBALL}"
    export PATH="/usr/local/go/bin:$PATH"
    success "Go ${GO_VERSION} installed."
}

# ── 2. Nuclei ─────────────────────────────────────────────────────────────────
install_nuclei() {
    info "Installing Nuclei ..."

    # Prefer pre-built binary download (faster than go install)
    local ARCH
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *)       ARCH="amd64" ;;
    esac
    local OS
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')

    # Fetch latest release tag from GitHub
    local LATEST_TAG
    LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest" \
        | grep '"tag_name"' | cut -d'"' -f4)
    local VERSION="${LATEST_TAG#v}"

    local FILENAME="nuclei_${VERSION}_${OS}_${ARCH}.zip"
    local URL="https://github.com/projectdiscovery/nuclei/releases/download/${LATEST_TAG}/${FILENAME}"

    info "Downloading Nuclei ${LATEST_TAG} from GitHub ..."
    if curl -fsSL "$URL" -o "/tmp/${FILENAME}"; then
        unzip -qo "/tmp/${FILENAME}" nuclei -d "$INSTALL_DIR"
        chmod +x "$INSTALL_DIR/nuclei"
        rm "/tmp/${FILENAME}"
        success "Nuclei ${LATEST_TAG} installed to ${INSTALL_DIR}/nuclei"
    else
        warn "Binary download failed. Falling back to go install ..."
        if ! check_command go; then install_go; fi
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        # Symlink from GOPATH to INSTALL_DIR if different
        if [[ "$GO_BIN/nuclei" != "$INSTALL_DIR/nuclei" ]]; then
            ln -sf "$GO_BIN/nuclei" "$INSTALL_DIR/nuclei"
        fi
        success "Nuclei installed via go install"
    fi
}

check_nuclei() {
    if check_command nuclei; then
        local CURRENT
        CURRENT=$(nuclei -version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "0.0.0")
        if version_gte "$CURRENT" "$NUCLEI_MIN_VERSION"; then
            success "Nuclei ${CURRENT} already installed (>= ${NUCLEI_MIN_VERSION})"
            return 0
        else
            warn "Nuclei ${CURRENT} is older than minimum ${NUCLEI_MIN_VERSION}. Upgrading ..."
        fi
    fi
    install_nuclei
}

update_nuclei_templates() {
    info "Updating Nuclei templates ..."
    if nuclei -update-templates -silent 2>&1; then
        success "Nuclei templates updated."
    else
        warn "Template update failed (check connectivity). Continuing with existing templates."
    fi
}

# ── 3. httpx ─────────────────────────────────────────────────────────────────
install_httpx() {
    info "Installing httpx ..."

    local ARCH
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *)       ARCH="amd64" ;;
    esac
    local OS
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')

    local LATEST_TAG
    LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/projectdiscovery/httpx/releases/latest" \
        | grep '"tag_name"' | cut -d'"' -f4)
    local VERSION="${LATEST_TAG#v}"

    local FILENAME="httpx_${VERSION}_${OS}_${ARCH}.zip"
    local URL="https://github.com/projectdiscovery/httpx/releases/download/${LATEST_TAG}/${FILENAME}"

    info "Downloading httpx ${LATEST_TAG} ..."
    if curl -fsSL "$URL" -o "/tmp/${FILENAME}"; then
        unzip -qo "/tmp/${FILENAME}" httpx -d "$INSTALL_DIR"
        chmod +x "$INSTALL_DIR/httpx"
        rm "/tmp/${FILENAME}"
        success "httpx ${LATEST_TAG} installed to ${INSTALL_DIR}/httpx"
    else
        warn "Binary download failed. Falling back to go install ..."
        if ! check_command go; then install_go; fi
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        if [[ "$GO_BIN/httpx" != "$INSTALL_DIR/httpx" ]]; then
            ln -sf "$GO_BIN/httpx" "$INSTALL_DIR/httpx"
        fi
        success "httpx installed via go install"
    fi
}

check_httpx() {
    if check_command httpx; then
        local CURRENT
        CURRENT=$(httpx -version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "0.0.0")
        if version_gte "$CURRENT" "$HTTPX_MIN_VERSION"; then
            success "httpx ${CURRENT} already installed (>= ${HTTPX_MIN_VERSION})"
            return 0
        else
            warn "httpx ${CURRENT} is older than minimum ${HTTPX_MIN_VERSION}. Upgrading ..."
        fi
    fi
    install_httpx
}

# ── 4. OWASP ZAP (Docker) ────────────────────────────────────────────────────
check_docker() {
    if ! check_command docker; then
        error "Docker is not installed or not on PATH."
        error "Install Docker: https://docs.docker.com/get-docker/"
        error "ZAP scans require Docker. Exiting."
        exit 1
    fi
    if ! docker info >/dev/null 2>&1; then
        error "Docker daemon is not running. Start Docker and retry."
        exit 1
    fi
    success "Docker is available."
}

pull_zap_image() {
    info "Pulling ZAP Docker image: ${ZAP_IMAGE} ..."
    if docker image inspect "$ZAP_IMAGE" >/dev/null 2>&1; then
        # Check if image is fresh (pulled within last 7 days)
        local CREATED
        CREATED=$(docker inspect --format='{{.Created}}' "$ZAP_IMAGE" 2>/dev/null || echo "")
        success "ZAP image already present: ${ZAP_IMAGE}"
        info "Run 'docker pull ${ZAP_IMAGE}' to force an update."
    else
        docker pull "$ZAP_IMAGE"
        success "ZAP image pulled: ${ZAP_IMAGE}"
    fi
}

# ── 5. Python dependencies ────────────────────────────────────────────────────
install_python_deps() {
    info "Installing Python dependencies for scanner wrappers ..."
    local REQUIRED_PKGS="requests xmltodict"
    if check_command pip3; then
        pip3 install -q --user $REQUIRED_PKGS
    elif check_command pip; then
        pip install -q --user $REQUIRED_PKGS
    else
        warn "pip not found. Install Python 3 and pip, then run: pip install ${REQUIRED_PKGS}"
        return 0
    fi
    success "Python dependencies installed: ${REQUIRED_PKGS}"
}

# ── 6. Smoke tests ────────────────────────────────────────────────────────────
smoke_test() {
    info "Running smoke tests ..."
    local FAILED=0

    if check_command nuclei; then
        nuclei -version >/dev/null 2>&1 && success "nuclei: OK" || { warn "nuclei: FAILED"; FAILED=1; }
    else
        warn "nuclei: NOT FOUND"; FAILED=1
    fi

    if check_command httpx; then
        httpx -version >/dev/null 2>&1 && success "httpx:  OK" || { warn "httpx: FAILED"; FAILED=1; }
    else
        warn "httpx: NOT FOUND"; FAILED=1
    fi

    if check_command docker; then
        docker image inspect "$ZAP_IMAGE" >/dev/null 2>&1 && success "zap:    OK (image present)" \
            || { warn "zap: image NOT found — run: docker pull ${ZAP_IMAGE}"; FAILED=1; }
    else
        warn "docker: NOT FOUND (ZAP unavailable)"; FAILED=1
    fi

    if [[ $FAILED -eq 0 ]]; then
        success "All tools ready. GRIMSEC DAST Agent 7 is operational."
    else
        error "Some tools failed smoke tests. Review warnings above."
        exit 1
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo "=============================================="
    echo "  GRIMSEC DAST Scanner — Tool Installer"
    echo "  Agent 7 of the GRIMSEC DevSecOps Suite"
    echo "=============================================="
    echo ""

    check_nuclei
    update_nuclei_templates
    check_httpx
    check_docker
    pull_zap_image
    install_python_deps
    smoke_test

    echo ""
    echo "Installation complete. Add ${INSTALL_DIR} to your PATH if not already present:"
    echo "  export PATH=\"\$PATH:${INSTALL_DIR}\""
    echo ""
}

main "$@"
