#!/usr/bin/env bash
# =============================================================================
# setup-redamon.sh — Install and configure RedAmon for GRIMSEC adversary simulation
# GRIMSEC DevSecOps Suite — Agent 12: Adversary Simulation Agent
# =============================================================================
#
# USAGE:
#   ./scripts/setup-redamon.sh [OPTIONS]
#
# OPTIONS:
#   --env <path>         Path to .env file with secrets (default: .env)
#   --neo4j-uri <uri>    Neo4j URI (default: bolt://localhost:7687)
#   --no-neo4j           Skip Neo4j setup (graph features disabled)
#   --update             Update existing RedAmon installation
#   --dry-run            Print actions without executing
#
# PREREQUISITES:
#   - Docker and docker-compose
#   - Python 3.10+
#   - Git
#   - Sufficient disk space (RedAmon + Neo4j ≈ 5GB)
#
# =============================================================================

set -euo pipefail

# --- Configuration ---
REDAMON_REPO="${REDAMON_REPO:-https://github.com/grimsec/redamon}"
REDAMON_DIR="${REDAMON_DIR:-$HOME/.redamon}"
REDAMON_VERSION="${REDAMON_VERSION:-latest}"
NEO4J_URI="${NEO4J_URI:-bolt://localhost:7687}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASS="${NEO4J_PASS:-redamon-grimsec}"
ENV_FILE=".env"
DRY_RUN=false
SKIP_NEO4J=false
UPDATE_MODE=false

# --- Colors ---
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[setup-redamon]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }

run() {
  if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "${YELLOW}[DRY-RUN]${NC} $*"
  else
    "$@"
  fi
}

# --- Argument parsing ---
while [[ $# -gt 0 ]]; do
  case $1 in
    --env)         ENV_FILE="$2"; shift 2 ;;
    --neo4j-uri)   NEO4J_URI="$2"; shift 2 ;;
    --no-neo4j)    SKIP_NEO4J=true; shift ;;
    --update)      UPDATE_MODE=true; shift ;;
    --dry-run)     DRY_RUN=true; shift ;;
    *) err "Unknown option: $1"; exit 1 ;;
  esac
done

# --- Load .env if present ---
if [[ -f "$ENV_FILE" ]]; then
  log "Loading environment from $ENV_FILE"
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

# =============================================================================
# 1. Dependency checks
# =============================================================================
log "Checking dependencies..."

check_cmd() {
  if command -v "$1" &>/dev/null; then
    ok "$1 found: $(command -v "$1")"
  else
    err "$1 is required but not installed."
    echo "  Install guide: $2"
    exit 1
  fi
}

check_cmd docker   "https://docs.docker.com/engine/install/"
check_cmd git      "https://git-scm.com/book/en/v2/Getting-Started-Installing-Git"
check_cmd python3  "https://www.python.org/downloads/"
check_cmd pip3     "https://pip.pypa.io/en/stable/installation/"

PYTHON_VERSION=$(python3 --version | grep -oP '\d+\.\d+' | head -1)
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [[ "$PYTHON_MAJOR" -lt 3 || ("$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -lt 10) ]]; then
  err "Python 3.10+ required. Found: $PYTHON_VERSION"
  exit 1
fi
ok "Python $PYTHON_VERSION OK"

# Check Docker daemon
if ! docker info &>/dev/null; then
  err "Docker daemon is not running. Start Docker and retry."
  exit 1
fi
ok "Docker daemon running"

# =============================================================================
# 2. Install RedAmon
# =============================================================================
if [[ -d "$REDAMON_DIR" && "$UPDATE_MODE" == "false" ]]; then
  log "RedAmon already installed at $REDAMON_DIR (use --update to upgrade)"
else
  if [[ "$UPDATE_MODE" == "true" && -d "$REDAMON_DIR" ]]; then
    log "Updating RedAmon..."
    run git -C "$REDAMON_DIR" pull origin main
  else
    log "Cloning RedAmon from $REDAMON_REPO..."
    run git clone --depth 1 "$REDAMON_REPO" "$REDAMON_DIR"
  fi
fi

# Install Python dependencies
log "Installing RedAmon Python dependencies..."
run pip3 install -q -r "$REDAMON_DIR/requirements.txt"

# Install additional GRIMSEC tooling
log "Installing GRIMSEC offensive toolchain..."
run pip3 install -q \
  neo4j \
  python-dotenv \
  rich \
  typer \
  httpx \
  sqlmap-python \
  nuclei-wrapper \
  wappalyzer-python

# =============================================================================
# 3. Neo4j setup (attack surface graph)
# =============================================================================
if [[ "$SKIP_NEO4J" == "false" ]]; then
  log "Starting Neo4j for attack surface graph..."
  
  NEO4J_CONTAINER="redamon-neo4j"
  
  if docker ps -a --format '{{.Names}}' | grep -q "^${NEO4J_CONTAINER}$"; then
    if [[ "$UPDATE_MODE" == "true" ]]; then
      run docker rm -f "$NEO4J_CONTAINER"
    else
      log "Neo4j container already exists: $NEO4J_CONTAINER"
    fi
  fi

  run docker run -d \
    --name "$NEO4J_CONTAINER" \
    --restart unless-stopped \
    -p 7474:7474 \
    -p 7687:7687 \
    -e NEO4J_AUTH="${NEO4J_USER}/${NEO4J_PASS}" \
    -e NEO4J_PLUGINS='["apoc", "graph-data-science"]' \
    -v redamon-neo4j-data:/data \
    neo4j:5

  log "Waiting for Neo4j to be ready..."
  for i in {1..30}; do
    if docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASS" "RETURN 1" &>/dev/null 2>&1; then
      ok "Neo4j ready"
      break
    fi
    sleep 2
    echo -n "."
  done
  echo
else
  warn "Skipping Neo4j setup (--no-neo4j). Graph features will be disabled."
fi

# =============================================================================
# 4. Metasploit (msfrpcd for API access)
# =============================================================================
log "Checking Metasploit installation..."
if command -v msfconsole &>/dev/null; then
  ok "Metasploit found: $(msfconsole --version 2>/dev/null | head -1)"
else
  warn "Metasploit not found. Starting via Docker..."
  run docker pull metasploitframework/metasploit-framework:latest
  
  # Create wrapper script
  cat > /usr/local/bin/msfconsole << 'MSFEOF'
#!/usr/bin/env bash
docker run --rm -it \
  --network host \
  -v "$HOME/.msf4:/root/.msf4" \
  metasploitframework/metasploit-framework msfconsole "$@"
MSFEOF
  run chmod +x /usr/local/bin/msfconsole
  ok "Metasploit Docker wrapper installed"
fi

# =============================================================================
# 5. Hydra (credential testing)
# =============================================================================
log "Checking Hydra..."
if command -v hydra &>/dev/null; then
  ok "Hydra found: $(hydra -h 2>&1 | head -1)"
else
  warn "Hydra not found. Install with: apt-get install -y hydra"
  if command -v apt-get &>/dev/null; then
    run apt-get install -y -qq hydra
  elif command -v brew &>/dev/null; then
    run brew install hydra
  else
    warn "Cannot auto-install Hydra. Install manually."
  fi
fi

# =============================================================================
# 6. Nuclei (vulnerability scanning)
# =============================================================================
log "Checking Nuclei..."
if command -v nuclei &>/dev/null; then
  ok "Nuclei found: $(nuclei -version 2>&1 | head -1)"
else
  log "Installing Nuclei..."
  NUCLEI_VERSION="latest"
  NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/${NUCLEI_VERSION}/download/nuclei_linux_amd64.zip"
  run curl -sL "$NUCLEI_URL" -o /tmp/nuclei.zip
  run unzip -qo /tmp/nuclei.zip nuclei -d /usr/local/bin/
  run chmod +x /usr/local/bin/nuclei
  ok "Nuclei installed"
fi

# Update Nuclei templates
log "Updating Nuclei templates (9,000+)..."
run nuclei -update-templates -silent || warn "Nuclei template update failed — using cached templates"

# =============================================================================
# 7. RedAmon configuration
# =============================================================================
log "Writing RedAmon configuration..."

REDAMON_CONFIG="$REDAMON_DIR/config/grimsec.yaml"
run mkdir -p "$(dirname "$REDAMON_CONFIG")"

cat > "$REDAMON_CONFIG" << YAMLEOF
# RedAmon configuration for GRIMSEC adversary-simulation-agent
# Generated by setup-redamon.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")

grimsec:
  suite: devSecOps
  agent: adversary-simulation-agent
  agent_number: 12

neo4j:
  uri: "${NEO4J_URI}"
  user: "${NEO4J_USER}"
  password: "${NEO4J_PASS}"

tools:
  metasploit:
    enabled: true
    rpc_host: "127.0.0.1"
    rpc_port: 55553
  hydra:
    enabled: true
    max_threads: 16
    timeout: 30
  sqlmap:
    enabled: true
    level: 3
    risk: 2
    batch: true
  nuclei:
    enabled: true
    severity: ["medium", "high", "critical"]
    templates: "all"

safety:
  no_dos: true
  no_data_exfil: true
  no_production_writes: true
  require_human_approval: true
  audit_log: true
  emergency_stop_command: "./redamon.sh down"

evograph:
  enabled: true
  persist_chains: true
  output_dir: "adversary-simulation/"

output:
  base_dir: "adversary-simulation/"
  formats: ["json", "markdown"]
YAMLEOF

ok "RedAmon configuration written to $REDAMON_CONFIG"

# =============================================================================
# 8. Symlink redamon.sh to PATH
# =============================================================================
if [[ ! -f "/usr/local/bin/redamon.sh" ]]; then
  log "Symlinking redamon.sh to /usr/local/bin..."
  run ln -sf "$REDAMON_DIR/redamon.sh" /usr/local/bin/redamon.sh
  run chmod +x "$REDAMON_DIR/redamon.sh"
fi

# =============================================================================
# 9. Validate installation
# =============================================================================
log "Validating RedAmon installation..."

VALIDATION_OK=true

for tool in nuclei; do
  if command -v "$tool" &>/dev/null; then
    ok "$tool: available"
  else
    warn "$tool: NOT FOUND"
    VALIDATION_OK=false
  fi
done

if [[ "$SKIP_NEO4J" == "false" ]]; then
  if docker ps --format '{{.Names}}' | grep -q "redamon-neo4j"; then
    ok "Neo4j: running"
  else
    warn "Neo4j: NOT running"
    VALIDATION_OK=false
  fi
fi

if [[ "$VALIDATION_OK" == "true" ]]; then
  ok "RedAmon setup complete. Run './redamon.sh --help' to get started."
else
  warn "Setup completed with warnings. Review above before running simulations."
fi

echo ""
log "Next steps:"
echo "  1. Copy your signed RoE into adversary-simulation/roe.json"
echo "  2. Run: python scripts/run-simulation.py --help"
echo "  3. Review references/rules-of-engagement.md before any testing"
echo ""
warn "REMINDER: NEVER run against production systems without a signed RoE document."
