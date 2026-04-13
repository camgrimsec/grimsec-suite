#!/usr/bin/env bash
# GRIMSEC — Full Pipeline Runner
# Runs the complete 12-agent pipeline against a target repository.
#
# Usage:
#   bash scripts/run-pipeline.sh <repo-url> [--quick|--deep]
#
# Examples:
#   bash scripts/run-pipeline.sh https://github.com/org/repo
#   bash scripts/run-pipeline.sh https://github.com/org/repo --quick
#   bash scripts/run-pipeline.sh https://github.com/org/repo --deep

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

REPO_URL="${1:-}"
MODE="${2:---standard}"

if [[ -z "$REPO_URL" ]]; then
  echo "Usage: $0 <repo-url> [--quick|--deep]"
  exit 1
fi

REPO_NAME=$(basename "$REPO_URL" .git)
TIMESTAMP=$(date +%Y-%m-%dT%H-%M-%S)
OUTPUT_DIR="grimsec-output/${REPO_NAME}/${TIMESTAMP}"

mkdir -p "$OUTPUT_DIR"

echo ""
echo -e "${BOLD}${CYAN}  GRIMSEC Pipeline${RESET}"
echo -e "  Target: ${CYAN}${REPO_URL}${RESET}"
echo -e "  Mode:   ${YELLOW}${MODE}${RESET}"
echo -e "  Output: ${OUTPUT_DIR}"
echo ""

case "$MODE" in
  --quick)
    echo -e "${YELLOW}  [QUICK MODE] Agents 1-3 only${RESET}"
    python3 grimsec.py analyze "$REPO_URL" --quick
    ;;
  --deep)
    echo -e "${YELLOW}  [DEEP MODE] All 12 agents including DAST + adversary sim${RESET}"
    python3 grimsec.py analyze "$REPO_URL" --deep
    ;;
  *)
    echo -e "${GREEN}  [STANDARD MODE] Full 12-agent pipeline${RESET}"
    python3 grimsec.py analyze "$REPO_URL"
    ;;
esac

echo ""
echo -e "${GREEN}  Pipeline complete. Results at: ${OUTPUT_DIR}${RESET}"
echo -e "  Generate executive report: ${CYAN}python grimsec.py report ${OUTPUT_DIR}${RESET}"
echo ""
