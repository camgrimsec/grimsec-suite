#!/usr/bin/env python3
"""
map-attack-surface.py — GRIMSEC Code Understanding Agent (Agent 9)
Entry point enumeration + dangerous sink cataloging.

Usage:
  python map-attack-surface.py <target_dir> [--output <out_dir>] [--inventory <inventory.json>]

Outputs:
  code-understanding/context-map.json

Designed to be run by the agent as a programmatic assist for Mode 1 (--map).
The agent reads the output and enriches it with semantic analysis.
"""

import argparse
import ast
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Sink and entry-point patterns
# ---------------------------------------------------------------------------

# Each pattern: (label, regex, language_hint, risk_level)
SINK_PATTERNS: list[tuple[str, str, str, str]] = [
    # SQL — raw query construction
    ("sql_raw_query",       r'(?i)(db|conn|tx|pool)\.(Query|Exec|QueryRow|QueryContext|ExecContext)\s*\(',  "go",         "CRITICAL"),
    ("sql_fmt_sprintf",     r'(?i)fmt\.Sprintf\s*\(\s*["\'].*SELECT|INSERT|UPDATE|DELETE',                  "go",         "CRITICAL"),
    ("sql_string_format",   r'(?i)f["\'].*SELECT|INSERT|UPDATE|DELETE.*\{',                                  "python",     "CRITICAL"),
    ("sql_percent_s",       r'(?i)["\'].*SELECT.*%s|INSERT.*%s|UPDATE.*%s|DELETE.*%s',                       "python",     "CRITICAL"),
    ("sql_template_literal",r'(?i)`.*SELECT|INSERT|UPDATE|DELETE.*\$\{',                                     "typescript", "CRITICAL"),
    ("sql_string_concat",   r'(?i)(SELECT|INSERT|UPDATE|DELETE).*\+\s*\w',                                   "java",       "CRITICAL"),
    # Command execution
    ("exec_go",             r'(?i)(exec\.Command|syscall\.Exec|os\.StartProcess)\s*\(',                       "go",         "CRITICAL"),
    ("exec_node",           r'(?i)(exec|execSync|spawn|spawnSync|execFile)\s*\(',                             "typescript", "CRITICAL"),
    ("exec_python",         r'(?i)(subprocess\.(run|call|Popen|check_output)|os\.(system|popen))\s*\(',      "python",     "CRITICAL"),
    ("exec_rust",           r'(?i)Command::new\s*\(',                                                         "rust",       "CRITICAL"),
    ("exec_java",           r'(?i)Runtime\.getRuntime\(\)\.(exec|)\s*\(|ProcessBuilder\s*\(',                "java",       "CRITICAL"),
    # File system — path from user input
    ("fs_open_go",          r'(?i)os\.(Open|Create|OpenFile|Remove|Mkdir)\s*\(',                              "go",         "HIGH"),
    ("fs_open_python",      r'(?i)open\s*\(|pathlib\.Path\s*\(',                                             "python",     "HIGH"),
    ("fs_readfile_node",    r'(?i)(fs\.readFile|fs\.writeFile|fs\.appendFile|fs\.readFileSync)\s*\(',         "typescript", "HIGH"),
    ("fs_path_join_node",   r'(?i)path\.join\s*\(',                                                           "typescript", "MEDIUM"),
    # Template rendering
    ("tmpl_inner_html",     r'(?i)innerHTML\s*=',                                                             "typescript", "HIGH"),
    ("tmpl_dangerous_html", r'(?i)dangerouslySetInnerHTML',                                                   "typescript", "HIGH"),
    ("tmpl_go_html",        r'(?i)template\.HTML\s*\(',                                                       "go",         "HIGH"),
    ("tmpl_jinja_safe",     r'(?i)\|\s*safe',                                                                 "python",     "HIGH"),
    # Deserialization
    ("deser_pickle",        r'(?i)pickle\.(loads?|Unpickler)',                                                "python",     "CRITICAL"),
    ("deser_yaml",          r'(?i)yaml\.load\s*\([^,)]+\)',                                                   "python",     "HIGH"),
    ("deser_java_object",   r'(?i)ObjectInputStream|readObject\s*\(',                                         "java",       "CRITICAL"),
    ("deser_node_serialize",r'(?i)unserialize\s*\(',                                                          "typescript", "CRITICAL"),
    # Cryptography
    ("crypto_weak_algo",    r'(?i)(md5|sha1|des|rc4|ecb)\.',                                                  "any",        "HIGH"),
    ("crypto_hardcoded_key",r'(?i)(secret|key|password|token)\s*[:=]\s*["\'][a-zA-Z0-9+/=]{8,}["\']',        "any",        "HIGH"),
    ("crypto_math_random",  r'(?i)Math\.random\s*\(',                                                         "typescript", "MEDIUM"),
    ("crypto_rand_seed",    r'(?i)rand\.Seed\s*\(',                                                           "go",         "MEDIUM"),
    # Network — SSRF
    ("ssrf_http_go",        r'(?i)http\.(Get|Post|Do|NewRequest)\s*\(',                                       "go",         "HIGH"),
    ("ssrf_requests_py",    r'(?i)requests\.(get|post|put|delete|head|patch)\s*\(',                           "python",     "HIGH"),
    ("ssrf_fetch_node",     r'(?i)\bfetch\s*\(',                                                               "typescript", "HIGH"),
    ("ssrf_axios",          r'(?i)axios\.(get|post|put|delete|request)\s*\(',                                  "typescript", "HIGH"),
    # Auth
    ("auth_jwt_no_verify",  r'(?i)jwt\.decode\s*\([^,)]+\)',                                                  "python",     "CRITICAL"),
    ("auth_jwt_none_alg",   r'(?i)algorithms\s*=\s*\[["\']none["\']',                                         "python",     "CRITICAL"),
]

# Entry-point patterns: (label, regex, language_hint)
ENTRY_PATTERNS: list[tuple[str, str, str]] = [
    # Go HTTP
    ("go_http_handlefunc",   r'(?i)(http\.HandleFunc|router\.(GET|POST|PUT|DELETE|PATCH|Handle))\s*\(',  "go"),
    ("go_gin_route",         r'(?i)(r|router|engine)\.(GET|POST|PUT|DELETE|PATCH|Group|Any)\s*\(',       "go"),
    ("go_echo_route",        r'(?i)(e|echo)\.(GET|POST|PUT|DELETE|PATCH|Group|Add)\s*\(',                "go"),
    ("go_fiber_route",       r'(?i)(app|fiber)\.(GET|POST|PUT|DELETE|PATCH|Group|Add)\s*\(',             "go"),
    ("go_chi_route",         r'(?i)(r|chi)\.(Get|Post|Put|Delete|Patch|Route|Mount)\s*\(',               "go"),
    ("go_grpc_server",       r'(?i)pb\.Register\w+Server\s*\(',                                          "go"),
    # TypeScript / Node
    ("ts_express_route",     r'(?i)(app|router)\.(get|post|put|delete|patch|all|use)\s*\(',              "typescript"),
    ("ts_fastify_route",     r'(?i)fastify\.(get|post|put|delete|patch|all|register)\s*\(',              "typescript"),
    ("ts_nestjs_decorator",  r'(?i)@(Get|Post|Put|Delete|Patch|Controller|Param|Body|Query)\(',          "typescript"),
    ("ts_nextjs_api",        r'(?i)export\s+(default\s+)?function\s+handler\s*\(',                       "typescript"),
    ("ts_graphql_resolver",  r'(?i)(Query|Mutation|Subscription)\s*:\s*\{',                              "typescript"),
    ("ts_ws_message",        r'(?i)(ws|socket|io)\.(on|message)\s*\(\s*["\']message["\']',               "typescript"),
    # Python
    ("py_flask_route",       r'(?i)@(app|blueprint)\.(route|get|post|put|delete|patch)\s*\(',            "python"),
    ("py_fastapi_route",     r'(?i)@(app|router)\.(get|post|put|delete|patch|websocket)\s*\(',           "python"),
    ("py_django_url",        r'(?i)(path|re_path|url)\s*\(',                                             "python"),
    # Rust
    ("rs_actix_route",       r'(?i)#\[(get|post|put|delete|patch)\s*\(',                                 "rust"),
    ("rs_axum_route",        r'(?i)\.(get|post|put|delete|patch|route)\s*\(',                            "rust"),
    # Java
    ("java_spring_mapping",  r'(?i)@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(',                   "java"),
    ("java_spring_rest",     r'(?i)@RestController|@Controller',                                         "java"),
    # Cross-language: MQ consumers, CLI
    ("mq_kafka_consumer",    r'(?i)(consumer\.subscribe|KafkaConsumer|consume_messages)\s*\(',           "any"),
    ("mq_rabbit_consumer",   r'(?i)(channel\.basicConsume|amqp\.subscribe|pika\.BlockingConnection)',    "any"),
    ("mq_sqs_consumer",      r'(?i)(sqs\.receive|receive_message|ReceiveMessage)',                       "any"),
    ("cli_arg_parse",        r'(?i)(argparse|flag\.Parse|cobra\.Command|clap::Command|args\.parse)',     "any"),
    ("env_var_read",         r'(?i)(os\.Getenv|os\.environ|process\.env|std::env::var)\s*\(',            "any"),
    ("cron_job",             r'(?i)(@Scheduled|cron\.|schedule\.|AddFunc)\s*\(',                         "any"),
]

# ---------------------------------------------------------------------------
# Extension → language mapping
# ---------------------------------------------------------------------------

EXT_TO_LANG: dict[str, str] = {
    ".go": "go",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "typescript",
    ".jsx": "typescript",
    ".mjs": "typescript",
    ".py": "python",
    ".rs": "rust",
    ".java": "java",
}

SKIP_DIRS = {
    "node_modules", ".git", "vendor", "dist", "build", "__pycache__",
    ".venv", "venv", "target", ".idea", ".vscode",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def detect_language(file_path: Path) -> str:
    return EXT_TO_LANG.get(file_path.suffix, "unknown")


def iter_source_files(root: Path) -> list[Path]:
    """Walk the target directory and yield source files, skipping noise dirs."""
    result = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fp = Path(dirpath) / fname
            if fp.suffix in EXT_TO_LANG:
                result.append(fp)
    return result


def scan_file(file_path: Path, patterns: list[tuple], root: Path) -> list[dict]:
    """Return a list of match records for the given pattern list."""
    matches = []
    lang = detect_language(file_path)
    try:
        lines = file_path.read_text(errors="replace").splitlines()
    except OSError:
        return matches

    for lineno, line in enumerate(lines, start=1):
        for pattern_tuple in patterns:
            label = pattern_tuple[0]
            regex = pattern_tuple[1]
            pattern_lang = pattern_tuple[2]
            # Only check language-matched or 'any' patterns
            if pattern_lang not in ("any", lang):
                continue
            if re.search(regex, line):
                record: dict[str, Any] = {
                    "label": label,
                    "file": str(file_path.relative_to(root)),
                    "line": lineno,
                    "snippet": line.strip()[:200],
                    "language": lang,
                }
                if len(pattern_tuple) > 3:
                    record["risk"] = pattern_tuple[3]
                matches.append(record)
                break  # one match per line per scan pass
    return matches


# ---------------------------------------------------------------------------
# Trust boundary classifier
# ---------------------------------------------------------------------------

def classify_trust_boundary(entry: dict) -> str:
    label = entry.get("label", "")
    if any(x in label for x in ("cli_arg", "env_var")):
        return "external→app (operator-controlled)"
    if any(x in label for x in ("mq_", "cron")):
        return "service→service (async)"
    if any(x in label for x in ("grpc", "java_spring")):
        return "service→service (RPC)"
    if any(x in label for x in ("graphql", "ws_")):
        return "external→app (authenticated or public)"
    return "external→app (HTTP)"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="GRIMSEC Code Understanding Agent — Attack Surface Mapper"
    )
    parser.add_argument("target_dir", help="Root directory of the codebase to analyze")
    parser.add_argument(
        "--output", default="code-understanding",
        help="Output directory (default: ./code-understanding)"
    )
    parser.add_argument(
        "--inventory", default=None,
        help="Path to inventory.json from devsecops-repo-analyzer Stage 1"
    )
    args = parser.parse_args()

    root = Path(args.target_dir).resolve()
    if not root.is_dir():
        print(f"[ERROR] Target directory not found: {root}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Scanning: {root}")
    source_files = iter_source_files(root)
    print(f"[*] Found {len(source_files)} source files")

    # Load inventory context if available
    inventory: dict = {}
    if args.inventory:
        inv_path = Path(args.inventory)
        if inv_path.exists():
            with open(inv_path) as f:
                inventory = json.load(f)
            print(f"[*] Loaded inventory context from {inv_path}")

    all_entries: list[dict] = []
    all_sinks: list[dict] = []

    for fp in source_files:
        entries = scan_file(fp, ENTRY_PATTERNS, root)
        sinks = scan_file(fp, SINK_PATTERNS, root)
        all_entries.extend(entries)
        all_sinks.extend(sinks)

    print(f"[*] Entry points found: {len(all_entries)}")
    print(f"[*] Dangerous sinks found: {len(all_sinks)}")

    # Annotate entries with trust boundaries
    for entry in all_entries:
        entry["trust_boundary"] = classify_trust_boundary(entry)

    # Group sinks by risk
    critical_sinks = [s for s in all_sinks if s.get("risk") == "CRITICAL"]
    high_sinks = [s for s in all_sinks if s.get("risk") == "HIGH"]
    medium_sinks = [s for s in all_sinks if s.get("risk") == "MEDIUM"]

    # Produce unchecked flow candidates:
    # Pair entry points and sinks that share the same file (heuristic — agent enriches this)
    entry_files = {e["file"] for e in all_entries}
    sink_files = {s["file"] for s in all_sinks}
    co_located_files = entry_files & sink_files

    unchecked_candidates: list[dict] = []
    for f in sorted(co_located_files):
        file_entries = [e for e in all_entries if e["file"] == f]
        file_sinks = [s for s in all_sinks if s["file"] == f]
        for entry in file_entries:
            for sink in file_sinks:
                unchecked_candidates.append({
                    "file": f,
                    "entry_line": entry["line"],
                    "entry_label": entry["label"],
                    "sink_line": sink["line"],
                    "sink_label": sink["label"],
                    "sink_risk": sink.get("risk", "UNKNOWN"),
                    "status": "NEEDS_TRACE",
                    "note": "Entry and sink co-located in same file — agent should trace to confirm"
                })

    context_map = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "agent": "code-understanding-agent",
        "suite_position": 9,
        "target": str(root),
        "inventory_context": inventory.get("summary", {}),
        "stats": {
            "source_files_scanned": len(source_files),
            "entry_points_found": len(all_entries),
            "sinks_found": len(all_sinks),
            "critical_sinks": len(critical_sinks),
            "high_sinks": len(high_sinks),
            "medium_sinks": len(medium_sinks),
            "unchecked_flow_candidates": len(unchecked_candidates),
        },
        "entry_points": all_entries,
        "dangerous_sinks": all_sinks,
        "unchecked_flow_candidates": unchecked_candidates,
    }

    out_path = out_dir / "context-map.json"
    with open(out_path, "w") as f:
        json.dump(context_map, f, indent=2)

    print(f"[+] context-map.json written to: {out_path}")
    print()
    print("=== Attack Surface Summary ===")
    print(f"  Entry points  : {len(all_entries)}")
    print(f"  Critical sinks: {len(critical_sinks)}")
    print(f"  High sinks    : {len(high_sinks)}")
    print(f"  Flow candidates to trace: {len(unchecked_candidates)}")
    print()
    if critical_sinks:
        print("Critical sinks (top 10):")
        for s in critical_sinks[:10]:
            print(f"  [{s['label']}] {s['file']}:{s['line']}  {s['snippet'][:80]}")
    print()
    print("[*] Hand off context-map.json to the agent for semantic enrichment.")


if __name__ == "__main__":
    main()
