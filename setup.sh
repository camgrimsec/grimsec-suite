#!/usr/bin/env bash
# GRIMSEC Setup Script
# Installs Python dependencies and all scanning tools, then verifies the install.
set -euo pipefail

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║         GRIMSEC — DevSecOps Agent Suite              ║"
echo "║              One-Command Installer                    ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Python dependencies ─────────────────────────────────────────────────────
echo "[1/3] Installing Python dependencies..."
python3 -m pip install --quiet --upgrade pip
python3 -m pip install --quiet pyyaml requests rich

echo "      ✓ Python dependencies installed"
echo ""

# ── Scanning tools ──────────────────────────────────────────────────────────
echo "[2/3] Installing scanning tools..."
bash "$(dirname "$0")/scripts/install-tools.sh"
echo ""

# ── Verify ──────────────────────────────────────────────────────────────────
echo "[3/3] Verifying installation..."
python3 "$(dirname "$0")/grimsec.py" status
