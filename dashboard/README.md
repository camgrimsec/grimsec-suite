# GRIMSEC Dashboard

GRIMSEC does not ship a built-in dashboard. This document explains how to set up a dashboard using your preferred tooling.

All GRIMSEC output is structured JSON, making it compatible with any JSON-capable analytics or visualization tool.

---

## Output Files to Visualize

After a pipeline run, the key files for a dashboard are:

| File | Contents |
|------|----------|
| `findings.json` | All findings with severity, risk score, reachability |
| `executive-summary.json` | Risk score, financial exposure, compliance gaps |
| `enriched-findings.json` | CVEs with EPSS, KEV status, ATT&CK mapping |
| `cicd-findings.json` | CI/CD pipeline findings |
| `threat-intel-report.json` | New CVEs from last 48h check |

All files are under `grimsec-output/<repo-name>/<timestamp>/`.

---

## Option 1: Grafana + JSON API

Grafana can read JSON files directly using the [JSON API datasource plugin](https://grafana.com/grafana/plugins/marcusolsson-json-datasource/).

**Setup:**

1. Install Grafana (local or Docker):
   ```bash
   docker run -d -p 3000:3000 grafana/grafana
   ```

2. Install the JSON API datasource plugin:
   ```bash
   grafana-cli plugins install marcusolsson-json-datasource
   ```

3. Serve your output directory as a simple HTTP API:
   ```bash
   cd grimsec-output/your-repo/latest/
   python3 -m http.server 8080
   ```

4. Add a JSON API datasource in Grafana pointing to `http://localhost:8080`

5. Create panels using JSONPath to extract data:
   - `$.summary.critical_exploitable` — critical finding count
   - `$.summary.noise_reduction_pct` — noise reduction percentage
   - `$.findings[*].real_risk_score` — risk score distribution

---

## Option 2: Metabase

Metabase can visualize JSON data loaded into a SQLite database.

**Setup:**

1. Load findings into SQLite:
   ```python
   import json, sqlite3

   conn = sqlite3.connect("grimsec.db")
   cur = conn.cursor()
   cur.execute("""CREATE TABLE IF NOT EXISTS findings
     (finding_id TEXT, type TEXT, severity TEXT, real_risk_score REAL,
      reachability TEXT, in_cisa_kev INTEGER, exploit_status TEXT)""")

   with open("grimsec-output/repo/latest/findings.json") as f:
       data = json.load(f)

   for finding in data["findings"]:
       cur.execute("INSERT INTO findings VALUES (?,?,?,?,?,?,?)", (
           finding["finding_id"], finding["type"], finding["severity"],
           finding["real_risk_score"], finding["reachability"],
           1 if finding.get("in_cisa_kev") else 0, finding.get("exploit_status", "UNKNOWN")
       ))
   conn.commit()
   ```

2. Start Metabase and connect to `grimsec.db`

3. Create questions and dashboards using the Metabase UI

---

## Option 3: Simple HTML Dashboard

A minimal HTML dashboard can be generated directly from the JSON output.

```bash
python3 - <<'EOF'
import json, os

output_dir = "grimsec-output"
repos = []
for repo in os.listdir(output_dir):
    latest = sorted(os.listdir(f"{output_dir}/{repo}"))[-1]
    findings_path = f"{output_dir}/{repo}/{latest}/findings.json"
    if os.path.exists(findings_path):
        with open(findings_path) as f:
            data = json.load(f)
        repos.append({"repo": repo, "timestamp": latest, **data["summary"]})

print(json.dumps(repos, indent=2))
EOF
```

Use this output as the data source for any static HTML dashboard.

---

## Option 4: GitHub Actions Integration

Add GRIMSEC to your CI/CD pipeline and post results to GitHub Security tab:

```yaml
# .github/workflows/grimsec.yml
name: GRIMSEC Security Scan
on:
  schedule:
    - cron: '0 6 * * 1'  # Every Monday at 6am
  workflow_dispatch:

jobs:
  grimsec:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4  # pin to SHA in production

      - name: Install GRIMSEC
        run: |
          git clone https://github.com/yourusername/grimsec-suite.git /opt/grimsec
          bash /opt/grimsec/setup.sh

      - name: Run GRIMSEC scan
        run: |
          python /opt/grimsec/grimsec.py scan ${{ github.server_url }}/${{ github.repository }}

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: grimsec-output/
```

**Note:** Convert `findings.json` to SARIF format for GitHub Security tab integration. The SARIF format is supported by most SAST tools and CI platforms.

---

## Dashboard Metrics to Track

| Metric | Source Field | Ideal Trend |
|--------|-------------|-------------|
| Critical findings count | `summary.critical_exploitable` | Decreasing |
| Noise reduction % | `summary.noise_reduction_pct` | Stable (85-96%) |
| Mean Real Risk Score | `findings[*].real_risk_score` (avg) | Decreasing |
| CISA KEV exposure | `findings[?in_cisa_kev==true]` count | Zero |
| Open CI/CD findings | `cicd-findings.json` count | Decreasing |
| Compliance gap count | `executive-summary.compliance_gaps` | Decreasing |
| Days to remediation | Track finding → fix PR merge time | Decreasing |
