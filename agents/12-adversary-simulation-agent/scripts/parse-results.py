#!/usr/bin/env python3
"""
parse-results.py — Parse RedAmon Neo4j/report output and generate MITRE ATT&CK mapping
GRIMSEC DevSecOps Suite — Agent 12: Adversary Simulation Agent

Consumes:
  - adversary-simulation/exploitation-log.json
  - adversary-simulation/post-exploitation-findings.json
  - references/mitre-attack-mapping.md (loaded for technique lookups)

Produces:
  - adversary-simulation/attack-mapping.json   (MITRE ATT&CK structured output)
  - adversary-simulation/dashboard-data.json   (GRIMSEC dashboard feed)

USAGE:
    python scripts/parse-results.py [OPTIONS]

    Options:
      --exploitation-log FILE    Path to exploitation-log.json
      --post-exploit FILE        Path to post-exploitation-findings.json
      --mitre-ref FILE           Path to MITRE ATT&CK reference markdown
      --output FILE              Output path for attack-mapping.json
      --dashboard-output FILE    Output path for dashboard-data.json
      --neo4j-uri URI            Query Neo4j graph for additional chain data
      --verbose                  Print full mapping details
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------- #
# MITRE ATT&CK technique mapping — static reference
# Full reference in references/mitre-attack-mapping.md
# --------------------------------------------------------------------------- #

# Maps exploitation log fields → ATT&CK technique IDs
VULN_TYPE_TO_TECHNIQUE: dict[str, dict] = {
    "CVE": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access"
    },
    "RCE": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution"
    },
    "SQLI": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access"
    },
    "CREDENTIAL": {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactic": "Credential Access"
    },
    "JWT": {
        "technique_id": "T1539",
        "technique_name": "Steal Web Session Cookie",
        "tactic": "Credential Access"
    },
    "CONTAINER_ESCAPE": {
        "technique_id": "T1611",
        "technique_name": "Escape to Host",
        "tactic": "Privilege Escalation"
    },
    "SSRF": {
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement"
    },
    "SUPPLY_CHAIN": {
        "technique_id": "T1195",
        "technique_name": "Supply Chain Compromise",
        "tactic": "Initial Access"
    },
    "WEBSOCKET": {
        "technique_id": "T1539",
        "technique_name": "Steal Web Session Cookie",
        "tactic": "Credential Access"
    },
    "XSS": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution"
    },
    "PATH_TRAVERSAL": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "Collection"
    },
    "IDOR": {
        "technique_id": "T1213",
        "technique_name": "Data from Information Repositories",
        "tactic": "Collection"
    },
}

POST_EXPLOIT_TECHNIQUE_MAP: dict[str, dict] = {
    "lateral_movement": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement"
    },
    "privilege_escalation": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation"
    },
    "persistence": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Persistence"
    },
    "data_access": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "Collection"
    },
    "exfiltration": {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration"
    },
}

# Full ATT&CK tactic ordering (kill chain order)
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


# --------------------------------------------------------------------------- #
# Parser class
# --------------------------------------------------------------------------- #
class ResultsParser:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.exploitation_log: dict = {}
        self.post_exploit: dict = {}
        self.mapped_techniques: list[dict] = []
        self.attack_chain: list[dict] = []
        self.coverage_gaps: list[str] = []

    def load_exploitation_log(self) -> bool:
        path = Path(self.args.exploitation_log)
        if not path.exists():
            print(f"[ERROR] exploitation-log.json not found: {path}", file=sys.stderr)
            return False
        with open(path) as f:
            self.exploitation_log = json.load(f)
        print(f"[parse-results] Loaded {len(self.exploitation_log.get('attempts', []))} attempts")
        return True

    def load_post_exploit(self) -> bool:
        path = Path(self.args.post_exploit)
        if not path.exists():
            print(f"[WARN] post-exploitation-findings.json not found: {path} (skipping)")
            return True  # Optional
        with open(path) as f:
            self.post_exploit = json.load(f)
        return True

    # ------------------------------------------------------------------ #
    # Map exploitation attempts → ATT&CK techniques
    # ------------------------------------------------------------------ #
    def map_exploitation_attempts(self) -> None:
        """Map each successful exploit attempt to ATT&CK."""
        attempts = self.exploitation_log.get("attempts", [])

        for attempt in attempts:
            if not attempt.get("success"):
                continue

            vuln_type = attempt.get("vuln_type", "UNKNOWN").upper()
            technique_info = VULN_TYPE_TO_TECHNIQUE.get(vuln_type, {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access"
            })

            mapped = {
                "attempt_id": attempt.get("attempt_id"),
                "finding_id": attempt.get("finding_id"),
                "vuln_type": vuln_type,
                "target": attempt.get("target"),
                "endpoint": attempt.get("endpoint"),
                "technique_id": technique_info["technique_id"],
                "technique_name": technique_info["technique_name"],
                "tactic": technique_info["tactic"],
                "tool_used": attempt.get("tool_used"),
                "timestamp": attempt.get("timestamp_start"),
                "evidence_reference": attempt.get("attempt_id"),
                "evograph_node_id": attempt.get("evograph_node_id"),
            }
            self.mapped_techniques.append(mapped)

    # ------------------------------------------------------------------ #
    # Map post-exploitation findings → ATT&CK
    # ------------------------------------------------------------------ #
    def map_post_exploitation(self) -> None:
        """Map post-exploitation findings to ATT&CK techniques."""
        for phase_key, technique_info in POST_EXPLOIT_TECHNIQUE_MAP.items():
            phase_data = self.post_exploit.get(phase_key, {})
            if not phase_data.get("possible") and not phase_data.get("sensitive_data_reachable"):
                continue

            mapped = {
                "phase": phase_key,
                "technique_id": technique_info["technique_id"],
                "technique_name": technique_info["technique_name"],
                "tactic": technique_info["tactic"],
                "details": phase_data,
                "source": "post-exploitation",
            }
            self.mapped_techniques.append(mapped)

    # ------------------------------------------------------------------ #
    # Build attack chain (ordered by kill chain)
    # ------------------------------------------------------------------ #
    def build_attack_chain(self) -> None:
        """Assemble ordered attack chain following kill chain progression."""
        # Sort by tactic order
        tactic_index = {t: i for i, t in enumerate(TACTIC_ORDER)}
        sorted_techniques = sorted(
            self.mapped_techniques,
            key=lambda t: tactic_index.get(t["tactic"], 99)
        )

        chain_step = 1
        for tech in sorted_techniques:
            self.attack_chain.append({
                "step": chain_step,
                "tactic": tech["tactic"],
                "technique_id": tech["technique_id"],
                "technique_name": tech["technique_name"],
                "target": tech.get("target", ""),
                "tool": tech.get("tool_used", ""),
                "mitre_url": f"https://attack.mitre.org/techniques/{tech['technique_id'].replace('.', '/')}/"
            })
            chain_step += 1

    # ------------------------------------------------------------------ #
    # Identify ATT&CK coverage gaps
    # ------------------------------------------------------------------ #
    def identify_coverage_gaps(self) -> None:
        """Find ATT&CK tactics not tested in this simulation."""
        tested_tactics = {t["tactic"] for t in self.mapped_techniques}
        self.coverage_gaps = [t for t in TACTIC_ORDER if t not in tested_tactics]

    # ------------------------------------------------------------------ #
    # Build ATT&CK heat map data
    # ------------------------------------------------------------------ #
    def build_heat_map(self) -> dict[str, Any]:
        """Generate ATT&CK heat map data for GRIMSEC dashboard."""
        heat_map: dict[str, list] = {tactic: [] for tactic in TACTIC_ORDER}

        for tech in self.mapped_techniques:
            tactic = tech["tactic"]
            if tactic in heat_map:
                heat_map[tactic].append({
                    "technique_id": tech["technique_id"],
                    "technique_name": tech["technique_name"],
                    "fired": True,
                    "count": 1
                })

        return heat_map

    # ------------------------------------------------------------------ #
    # Neo4j chain extraction (optional)
    # ------------------------------------------------------------------ #
    def query_neo4j_chain(self) -> list[dict]:
        """Query Neo4j EvoGraph for attack chain nodes."""
        neo4j_uri = getattr(self.args, "neo4j_uri", None)
        if not neo4j_uri:
            return []

        try:
            from neo4j import GraphDatabase
            driver = GraphDatabase.driver(
                neo4j_uri,
                auth=(
                    os.environ.get("NEO4J_USER", "neo4j"),
                    os.environ.get("NEO4J_PASS", "redamon-grimsec")
                )
            )
            with driver.session() as session:
                result = session.run(
                    "MATCH (n:ExploitAttempt)-[r:LED_TO]->(m) "
                    "WHERE n.success = true "
                    "RETURN n, r, m ORDER BY n.timestamp"
                )
                return [dict(record) for record in result]
        except Exception as e:
            print(f"[WARN] Neo4j query failed: {e} — using log-based chain only")
            return []

    # ------------------------------------------------------------------ #
    # Generate attack-mapping.json
    # ------------------------------------------------------------------ #
    def write_attack_mapping(self) -> None:
        output_path = Path(self.args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Deduplicate technique IDs
        seen_ids: set[str] = set()
        unique_techniques = []
        for t in self.mapped_techniques:
            tid = t["technique_id"]
            if tid not in seen_ids:
                seen_ids.add(tid)
                unique_techniques.append(tid)

        tactics_covered = sorted(
            list({t["tactic"] for t in self.mapped_techniques}),
            key=lambda x: TACTIC_ORDER.index(x) if x in TACTIC_ORDER else 99
        )

        output = {
            "engagement_id": self.exploitation_log.get("engagement_id", str(uuid.uuid4())),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "attack_chain": self.attack_chain,
            "techniques_used": [
                {
                    "technique_id": t["technique_id"],
                    "technique_name": t["technique_name"],
                    "tactic": t["tactic"],
                    "mitre_url": f"https://attack.mitre.org/techniques/{t['technique_id'].replace('.', '/')}/"
                }
                for t in self.mapped_techniques
            ],
            "unique_technique_ids": unique_techniques,
            "tactics_covered": tactics_covered,
            "coverage_gaps": self.coverage_gaps,
            "heat_map_data": self.build_heat_map(),
            "attack_chain_length": len(self.attack_chain),
            "total_techniques_fired": len(unique_techniques),
        }

        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)

        print(f"[parse-results] Attack mapping written: {output_path}")
        print(f"[parse-results] Techniques fired: {len(unique_techniques)}")
        print(f"[parse-results] Tactics covered: {', '.join(tactics_covered)}")
        print(f"[parse-results] Coverage gaps: {', '.join(self.coverage_gaps)}")

    # ------------------------------------------------------------------ #
    # Generate dashboard-data.json
    # ------------------------------------------------------------------ #
    def write_dashboard_data(self) -> None:
        output_path = Path(self.args.dashboard_output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        sim_start = self.exploitation_log.get("simulation_start", "")
        sim_end = self.exploitation_log.get("simulation_end", "")
        duration_s = self.exploitation_log.get("duration_seconds", 0)

        # Determine impact severity from post-exploitation
        severity = "LOW"
        if self.post_exploit.get("privilege_escalation", {}).get("possible"):
            severity = "CRITICAL"
        elif self.post_exploit.get("lateral_movement", {}).get("possible"):
            severity = "HIGH"
        elif self.post_exploit.get("data_access", {}).get("sensitive_data_reachable"):
            severity = "HIGH"
        elif self.exploitation_log.get("successful_exploits", 0) > 0:
            severity = "MEDIUM"

        # Build remediation items (ordered by attack chain position)
        remediation_items = []
        for step in self.attack_chain:
            remediation_items.append({
                "step": step["step"],
                "tactic": step["tactic"],
                "technique_id": step["technique_id"],
                "fix_priority": "CRITICAL" if step["step"] == 1 else "HIGH",
                "rationale": f"Fix {step['technique_id']} ({step['tactic']}) to break the chain at step {step['step']}"
            })

        dashboard = {
            "engagement_id": self.exploitation_log.get("engagement_id"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "simulation_start": sim_start,
            "simulation_end": sim_end,
            "time_to_compromise_seconds": duration_s,
            "time_to_compromise_minutes": round(duration_s / 60, 1),
            "phases_completed": ["Phase 1", "Phase 2", "Phase 3", "Phase 4", "Phase 5", "Phase 6"],
            "attack_chain_length": len(self.attack_chain),
            "successful_exploits": self.exploitation_log.get("successful_exploits", 0),
            "total_attempts": self.exploitation_log.get("attempts_made", 0),
            "techniques_fired": [t["technique_id"] for t in self.mapped_techniques],
            "tactics_covered": list({t["tactic"] for t in self.mapped_techniques}),
            "impact_severity": severity,
            "post_exploitation_summary": {
                "lateral_movement": self.post_exploit.get("lateral_movement", {}).get("possible", False),
                "privilege_escalation": self.post_exploit.get("privilege_escalation", {}).get("possible", False),
                "data_access": self.post_exploit.get("data_access", {}).get("sensitive_data_reachable", False),
                "persistence": self.post_exploit.get("persistence", {}).get("possible", False),
            },
            "remediation_items": remediation_items,
            "att_ck_heat_map": self.build_heat_map(),
            "coverage_gaps": self.coverage_gaps,
        }

        with open(output_path, "w") as f:
            json.dump(dashboard, f, indent=2)

        print(f"[parse-results] Dashboard data written: {output_path}")

    # ------------------------------------------------------------------ #
    # Main
    # ------------------------------------------------------------------ #
    def run(self) -> int:
        print("[parse-results] === GRIMSEC ATT&CK Results Parser ===")

        if not self.load_exploitation_log():
            return 1
        self.load_post_exploit()

        self.map_exploitation_attempts()
        self.map_post_exploitation()
        self.build_attack_chain()
        self.identify_coverage_gaps()

        self.write_attack_mapping()
        self.write_dashboard_data()

        print(f"[parse-results] Done. Attack chain: {len(self.attack_chain)} steps.")
        return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    import os
    p = argparse.ArgumentParser(
        description="GRIMSEC RedAmon Results Parser — ATT&CK Mapping",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    p.add_argument("--exploitation-log",
                   default="adversary-simulation/exploitation-log.json")
    p.add_argument("--post-exploit",
                   default="adversary-simulation/post-exploitation-findings.json")
    p.add_argument("--mitre-ref",
                   default="references/mitre-attack-mapping.md")
    p.add_argument("--output",
                   default="adversary-simulation/attack-mapping.json")
    p.add_argument("--dashboard-output",
                   default="adversary-simulation/dashboard-data.json")
    p.add_argument("--neo4j-uri",
                   default=os.environ.get("NEO4J_URI"))
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    parser = ResultsParser(args)
    sys.exit(parser.run())
