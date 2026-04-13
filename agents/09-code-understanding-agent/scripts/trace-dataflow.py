#!/usr/bin/env python3
"""
trace-dataflow.py — GRIMSEC Code Understanding Agent (Agent 9)
Source-to-sink data flow tracing assistant.

Usage:
  python trace-dataflow.py <target_dir> --entry <entry_point> [--output <out_dir>]

  <entry_point>  A string identifying the entry point to trace, e.g.:
                 "POST /api/query"
                 "handleUpload"
                 "cmd flag --config"

Outputs:
  code-understanding/flow-traces/flow-trace-<id>.json

The script performs a heuristic text-based analysis to locate the entry point
and identify downstream function calls and sink candidates. The agent then uses
this output to perform full semantic taint analysis.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Patterns for locating entry point handlers in source
# ---------------------------------------------------------------------------

ROUTE_LOCATORS: list[tuple[str, str, str]] = [
    # (language, label, regex that captures a handler name near a route)
    ("go",         "gin/echo/fiber",  r'(?i)\.(GET|POST|PUT|DELETE|PATCH)\s*\(\s*["\'][^"\']+["\'],\s*(\w+)'),
    ("go",         "net/http",        r'(?i)http\.HandleFunc\s*\(\s*["\'][^"\']+["\'],\s*(\w+)'),
    ("go",         "chi",             r'(?i)r\.(Get|Post|Put|Delete|Patch)\s*\(\s*["\'][^"\']+["\'],\s*(\w+)'),
    ("typescript", "express",         r'(?i)(app|router)\.(get|post|put|delete|patch)\s*\(\s*["\'][^"\']+["\'],\s*(?:async\s+)?(\w+)'),
    ("typescript", "fastify",         r'(?i)fastify\.(get|post|put|delete|patch)\s*\(\s*["\'][^"\']+["\'],\s*(?:\{[^}]*\},\s*)?(?:async\s+)?(\w+)'),
    ("python",     "flask",           r'(?i)@(?:app|blueprint)\.(route|get|post|put|delete|patch)\s*\(\s*["\'][^"\']+["\']'),
    ("python",     "fastapi",         r'(?i)@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["\'][^"\']+["\']'),
    ("rust",       "actix",           r'(?i)#\[(get|post|put|delete|patch)\s*\(\s*["\'][^"\']+["\']'),
    ("rust",       "axum",            r'(?i)\.(get|post|put|delete|patch)\s*\(\s*["\'][^"\']+["\'],\s*(\w+)'),
    ("java",       "spring",          r'(?i)@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\([^)]*["\'][^"\']*["\']'),
]

# Patterns that indicate validation / sanitization at a call site
SANITIZATION_PATTERNS: list[str] = [
    r'(?i)(validate|sanitize|escape|clean|strip|encode|allowlist|whitelist|parameteriz)',
    r'(?i)(prepared?Statement|bindParam|executeQuery\s*\()',
    r'(?i)(html\.EscapeString|template\.HTMLEscapeString)',
    r'(?i)(strconv\.(Atoi|ParseInt|ParseFloat|ParseBool))',
    r'(?i)(parseInt|parseFloat|Number\s*\()',
    r'(?i)(zod\.|joi\.|yup\.|pydantic|marshmallow)',
    r'(?i)(regexp\.MustCompile|re\.compile|re\.match|re\.fullmatch)',
]

# Patterns that indicate taint propagation
TAINT_PROPAGATION: list[str] = [
    r'(?i)(fmt\.Sprintf|fmt\.Fprintf|strings\.Join)',
    r'(?i)(string interpolation|\$\{|\%s|\%v|\%d)',
    r'(?i)(\.concat\(|template literal|`.*\$\{)',
    r'(?i)(base64\.(encode|decode)|url\.(encode|decode))',
    r'(?i)(json\.(Marshal|Unmarshal|stringify|parse))',
    r'(?i)(strings?\.Replace|str\.replace|str\.format)',
]

EXT_TO_LANG: dict[str, str] = {
    ".go": "go",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "typescript",
    ".py": "python",
    ".rs": "rust",
    ".java": "java",
}

SKIP_DIRS = {
    "node_modules", ".git", "vendor", "dist", "build", "__pycache__",
    ".venv", "venv", "target",
}


def iter_source_files(root: Path) -> list[Path]:
    result = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fp = Path(dirpath) / fname
            if fp.suffix in EXT_TO_LANG:
                result.append(fp)
    return result


def find_entry_handler(
    files: list[Path],
    entry_str: str,
    root: Path,
) -> list[dict]:
    """
    Locate source lines that define the handler for the given entry point string.
    Returns a list of candidate records with file, line, and snippet.
    """
    # Build a simple search term from the entry string
    # e.g. "POST /api/query" → look for "/api/query" in route definitions
    search_terms: list[str] = []
    # Extract path portion if HTTP method present
    m = re.match(r'(?i)(GET|POST|PUT|DELETE|PATCH|HEAD)\s+(\S+)', entry_str)
    if m:
        search_terms.append(re.escape(m.group(2)))
    else:
        # Treat entire entry string as identifier/function name
        search_terms.append(re.escape(entry_str))

    candidates = []
    for fp in files:
        try:
            content = fp.read_text(errors="replace")
            lines = content.splitlines()
        except OSError:
            continue

        for lineno, line in enumerate(lines, start=1):
            for term in search_terms:
                if re.search(term, line, re.IGNORECASE):
                    candidates.append({
                        "file": str(fp.relative_to(root)),
                        "line": lineno,
                        "snippet": line.strip()[:300],
                        "language": EXT_TO_LANG.get(fp.suffix, "unknown"),
                    })
    return candidates


def extract_function_body(
    file_path: Path,
    start_line: int,
    max_lines: int = 80,
) -> list[tuple[int, str]]:
    """Return lines of code starting from start_line, up to max_lines."""
    try:
        all_lines = file_path.read_text(errors="replace").splitlines()
    except OSError:
        return []
    end = min(start_line - 1 + max_lines, len(all_lines))
    return [(i + 1, all_lines[i]) for i in range(start_line - 1, end)]


def analyze_hop(lineno: int, line: str) -> dict:
    """Classify a single line: is it sanitization, taint propagation, a sink?"""
    hop: dict = {
        "line": lineno,
        "code": line.strip()[:200],
        "sanitization_detected": False,
        "taint_propagation": False,
        "sink_candidate": False,
        "notes": [],
    }
    for pattern in SANITIZATION_PATTERNS:
        if re.search(pattern, line):
            hop["sanitization_detected"] = True
            hop["notes"].append("Possible sanitization/validation detected — verify it's sufficient")
            break
    for pattern in TAINT_PROPAGATION:
        if re.search(pattern, line):
            hop["taint_propagation"] = True
            hop["notes"].append("Taint propagation likely — attacker-controlled data may survive this transform")
            break
    # Heuristic: if line references DB, exec, or file ops near end of function
    if re.search(r'(?i)(\.Query|\.Exec|exec\.Command|os\.Open|subprocess|innerHTML|pickle\.loads?)', line):
        hop["sink_candidate"] = True
        hop["notes"].append("Potential dangerous sink — verify this consumes tainted data")
    return hop


def trace_entry_point(
    files: list[Path],
    root: Path,
    entry_str: str,
) -> dict:
    """Perform a heuristic trace from the entry point handler."""
    candidates = find_entry_handler(files, entry_str, root)

    if not candidates:
        return {
            "entry_point": entry_str,
            "status": "NOT_FOUND",
            "message": f"Could not locate handler for '{entry_str}' in source files. "
                       "Verify the entry point string matches a route or function name.",
            "hops": [],
        }

    # Use the first candidate as starting point
    primary = candidates[0]
    file_path = root / primary["file"]
    start_line = primary["line"]

    body_lines = extract_function_body(file_path, start_line, max_lines=100)

    hops = []
    for lineno, line in body_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            continue
        hop = analyze_hop(lineno, line)
        hops.append(hop)

    # Overall classification
    has_sink = any(h["sink_candidate"] for h in hops)
    has_sanitization = any(h["sanitization_detected"] for h in hops)

    if has_sink and not has_sanitization:
        status = "EXPLOITABLE_CANDIDATE"
        message = "Sink reached from entry point with no sanitization detected — full manual taint trace recommended."
    elif has_sink and has_sanitization:
        status = "CONDITIONAL"
        message = "Sink reached but sanitization was also detected — verify sanitization is applied before the sink."
    elif has_sanitization and not has_sink:
        status = "SANITIZED_CANDIDATE"
        message = "Sanitization detected, no direct sink in handler body — sink may be in a downstream callee."
    else:
        status = "UNCLEAR"
        message = "No definitive sink or sanitization pattern detected in handler body — may be in a downstream callee."

    return {
        "entry_point": entry_str,
        "handler_candidates": candidates,
        "primary_handler": primary,
        "status": status,
        "message": message,
        "hops": hops,
        "agent_instructions": (
            "1. Verify which candidate is the actual handler for this entry point. "
            "2. For each hop marked sink_candidate=True, determine if tainted data from the "
            "entry point reaches it. "
            "3. For each hop marked sanitization_detected=True, verify the sanitization is "
            "applied before any sink and cannot be bypassed. "
            "4. If a callee is invoked (function call), recursively trace into that function. "
            "5. Update status to EXPLOITABLE, CONDITIONAL, BLOCKED, or UNCLEAR."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="GRIMSEC Code Understanding Agent — Data Flow Tracer"
    )
    parser.add_argument("target_dir", help="Root directory of the codebase to analyze")
    parser.add_argument(
        "--entry", required=True,
        help='Entry point to trace, e.g. "POST /api/query" or "handleUpload"'
    )
    parser.add_argument(
        "--output", default="code-understanding",
        help="Output directory (default: ./code-understanding)"
    )
    args = parser.parse_args()

    root = Path(args.target_dir).resolve()
    if not root.is_dir():
        print(f"[ERROR] Target directory not found: {root}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.output) / "flow-traces"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Target: {root}")
    print(f"[*] Tracing entry point: {args.entry}")

    files = iter_source_files(root)
    print(f"[*] Source files indexed: {len(files)}")

    trace = trace_entry_point(files, root, args.entry)

    # Stable ID based on entry point string
    trace_id = hashlib.sha1(args.entry.encode()).hexdigest()[:8]
    trace["trace_id"] = trace_id
    trace["generated_at"] = datetime.now(timezone.utc).isoformat()
    trace["agent"] = "code-understanding-agent"
    trace["suite_position"] = 9
    trace["target"] = str(root)

    out_path = out_dir / f"flow-trace-{trace_id}.json"
    with open(out_path, "w") as f:
        json.dump(trace, f, indent=2)

    print(f"[+] Flow trace written to: {out_path}")
    print()
    print(f"Status : {trace['status']}")
    print(f"Message: {trace['message']}")
    print(f"Hops analyzed: {len(trace['hops'])}")
    sinks_found = [h for h in trace["hops"] if h["sink_candidate"]]
    if sinks_found:
        print(f"Sink candidates ({len(sinks_found)}):")
        for h in sinks_found:
            print(f"  Line {h['line']}: {h['code'][:80]}")
    print()
    print("[*] Hand off flow-trace JSON to the agent for semantic taint confirmation.")


if __name__ == "__main__":
    main()
