#!/usr/bin/env python3
"""
check-threats.py — Threat Intel Monitor for GRIMSEC DevSecOps Suite
Author: cambamwham2
Version: 1.0

Fetches recent high-severity CVEs from CISA KEV, OSV.dev, and NVD,
cross-references them against dependency inventories from previously
analyzed repositories, and produces a structured exposure report.

Usage:
    python check-threats.py --lookback 7d --inventory-dir devsecops-analysis/ \
        --output-dir devsecops-analysis/threat-intel/
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
import urllib.request
import urllib.error
import urllib.parse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"

LOOKBACK_MAP = {
    "1d": 1,
    "7d": 7,
    "30d": 30,
}

# OSV ecosystem name mapping from inventory keys
ECOSYSTEM_MAP = {
    "npm": "npm",
    "pip": "PyPI",
    "go": "Go",
    "maven": "Maven",
    "cargo": "crates.io",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
}

log = logging.getLogger("threat-intel-monitor")


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _http_get(url: str, headers: dict = None, timeout: int = 30) -> dict | list | None:
    """GET request using requests if available, fallback to urllib."""
    headers = headers or {}
    try:
        if HAS_REQUESTS:
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        else:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
    except Exception as exc:
        log.warning("GET %s failed: %s", url, exc)
        return None


def _http_post(url: str, payload: dict, headers: dict = None, timeout: int = 60) -> dict | None:
    """POST JSON using requests if available, fallback to urllib."""
    headers = headers or {"Content-Type": "application/json"}
    if "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    body = json.dumps(payload).encode()
    try:
        if HAS_REQUESTS:
            resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        else:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
    except Exception as exc:
        log.warning("POST %s failed: %s", url, exc)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Inventory Loading
# ─────────────────────────────────────────────────────────────────────────────

def load_inventories(inventory_dir: Path) -> list[dict]:
    """
    Walk inventory_dir looking for inventory.json files.
    Returns a list of inventory dicts enriched with a 'repo_name' field.
    """
    inventories = []
    for inv_path in sorted(inventory_dir.rglob("inventory.json")):
        try:
            with open(inv_path) as f:
                data = json.load(f)
            # Derive repo name from directory structure if not present
            if "repo" not in data:
                data["repo"] = inv_path.parent.name
            data["_inventory_path"] = str(inv_path)
            inventories.append(data)
            log.info("Loaded inventory: %s (%s)", data["repo"], inv_path)
        except Exception as exc:
            log.warning("Failed to load %s: %s", inv_path, exc)
    return inventories


def extract_dependencies(inventory: dict) -> list[dict]:
    """
    Extract all dependencies from an inventory.json into a flat list.
    Each entry: {repo, name, version, ecosystem, osv_ecosystem}
    """
    deps = []
    repo = inventory.get("repo", "unknown")
    dep_section = inventory.get("dependencies", {})

    if isinstance(dep_section, dict):
        for ecosystem_key, packages in dep_section.items():
            osv_eco = ECOSYSTEM_MAP.get(ecosystem_key.lower(), ecosystem_key)
            if isinstance(packages, list):
                for pkg in packages:
                    if isinstance(pkg, dict):
                        name = pkg.get("name") or pkg.get("package")
                        version = pkg.get("version") or pkg.get("installed_version")
                        if name:
                            deps.append({
                                "repo": repo,
                                "name": name,
                                "version": version or "",
                                "ecosystem": ecosystem_key,
                                "osv_ecosystem": osv_eco,
                            })
    elif isinstance(dep_section, list):
        # Flat list format
        for pkg in dep_section:
            if isinstance(pkg, dict):
                name = pkg.get("name") or pkg.get("package")
                version = pkg.get("version") or pkg.get("installed_version")
                ecosystem_key = pkg.get("ecosystem", "unknown")
                osv_eco = ECOSYSTEM_MAP.get(ecosystem_key.lower(), ecosystem_key)
                if name:
                    deps.append({
                        "repo": repo,
                        "name": name,
                        "version": version or "",
                        "ecosystem": ecosystem_key,
                        "osv_ecosystem": osv_eco,
                    })

    return deps


# ─────────────────────────────────────────────────────────────────────────────
# CISA KEV Feed
# ─────────────────────────────────────────────────────────────────────────────

def fetch_cisa_kev(cache_dir: Path, max_age_hours: int = 12) -> list[dict]:
    """
    Download (or load from cache) the CISA KEV JSON feed.
    Returns the list of vulnerability entries.
    """
    cache_file = cache_dir / "cisa_kev.json"
    now = datetime.now(timezone.utc)

    # Use cached file if fresh enough
    if cache_file.exists():
        age_hours = (now.timestamp() - cache_file.stat().st_mtime) / 3600
        if age_hours < max_age_hours:
            log.info("Using cached CISA KEV (%.1fh old)", age_hours)
            try:
                with open(cache_file) as f:
                    data = json.load(f)
                return data.get("vulnerabilities", [])
            except Exception:
                pass  # Fall through to re-download

    log.info("Downloading CISA KEV feed from %s", CISA_KEV_URL)
    data = _http_get(CISA_KEV_URL, timeout=60)
    if data is None:
        log.error("Failed to fetch CISA KEV feed — using cache if available")
        if cache_file.exists():
            with open(cache_file) as f:
                data = json.load(f)
            return data.get("vulnerabilities", [])
        return []

    # Cache to disk
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        with open(cache_file, "w") as f:
            json.dump(data, f)
        log.info("CISA KEV cached to %s", cache_file)
    except Exception as exc:
        log.warning("Could not cache CISA KEV: %s", exc)

    return data.get("vulnerabilities", [])


def filter_kev_by_date(entries: list[dict], since: datetime) -> list[dict]:
    """Filter KEV entries to those added on or after `since`."""
    result = []
    for entry in entries:
        date_str = entry.get("dateAdded", "")
        if not date_str:
            continue
        try:
            added = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if added >= since:
                result.append(entry)
        except ValueError:
            pass
    return result


def kev_to_threat(entry: dict) -> dict:
    """Convert a CISA KEV entry to our internal threat format."""
    return {
        "cve_id": entry.get("cveID", ""),
        "source": "cisa_kev",
        "severity": "CRITICAL",  # All KEV entries are treated as critical priority
        "title": entry.get("vulnerabilityName", ""),
        "description": f"{entry.get('vendorProject', '')} {entry.get('product', '')} — {entry.get('shortDescription', '')}".strip(" —"),
        "date_published": entry.get("dateAdded", ""),
        "known_exploited": True,
        "ransomware_use": entry.get("knownRansomwareCampaignUse", "Unknown").lower() == "known",
        "due_date": entry.get("dueDate", ""),
        "vendor": entry.get("vendorProject", ""),
        "product": entry.get("product", ""),
        "affected_repos": [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# OSV.dev Batch API
# ─────────────────────────────────────────────────────────────────────────────

def build_osv_queries(deps: list[dict]) -> list[dict]:
    """Build OSV batch query list from dependency list."""
    queries = []
    seen = set()
    for dep in deps:
        key = (dep["osv_ecosystem"], dep["name"], dep["version"])
        if key in seen:
            continue
        seen.add(key)
        query = {
            "package": {
                "name": dep["name"],
                "ecosystem": dep["osv_ecosystem"],
            }
        }
        if dep["version"]:
            query["version"] = dep["version"]
        queries.append({"_dep_ref": dep, "query": query})
    return queries


def query_osv_batch(queries: list[dict], batch_size: int = 1000) -> dict[tuple, list]:
    """
    Query OSV.dev batch API for all packages.
    Returns a dict mapping (ecosystem, name, version) -> list of vuln IDs.
    """
    results = {}
    query_list = [q["query"] for q in queries]
    dep_refs = [q["_dep_ref"] for q in queries]

    log.info("Querying OSV.dev batch API for %d packages", len(query_list))

    for i in range(0, len(query_list), batch_size):
        chunk = query_list[i:i + batch_size]
        dep_chunk = dep_refs[i:i + batch_size]
        payload = {"queries": chunk}
        data = _http_post(OSV_BATCH_URL, payload, timeout=120)
        if data is None:
            log.error("OSV batch query %d-%d failed — skipping chunk", i, i + len(chunk))
            continue

        for j, result in enumerate(data.get("results", [])):
            dep = dep_chunk[j]
            key = (dep["osv_ecosystem"], dep["name"], dep["version"])
            vulns = result.get("vulns", [])
            if vulns:
                results[key] = vulns
                log.debug("  %s@%s [%s]: %d vulns", dep["name"], dep["version"], dep["osv_ecosystem"], len(vulns))

        # Small delay between batch chunks
        if i + batch_size < len(query_list):
            time.sleep(0.5)

    log.info("OSV.dev: found vulnerabilities in %d package versions", len(results))
    return results


def enrich_osv_vulns(vuln_ids: list[str]) -> list[dict]:
    """Fetch individual OSV vuln details for enrichment."""
    enriched = []
    for vid in vuln_ids:
        url = f"https://api.osv.dev/v1/vulns/{vid}"
        data = _http_get(url, timeout=20)
        if data:
            enriched.append(data)
        time.sleep(0.1)
    return enriched


# ─────────────────────────────────────────────────────────────────────────────
# NVD API v2
# ─────────────────────────────────────────────────────────────────────────────

def fetch_nvd_recent(since: datetime, api_key: str = None,
                     severities: list[str] = None, max_results: int = 500) -> list[dict]:
    """
    Fetch recent CVEs from NVD API v2 filtered by date and severity.
    Returns list of CVE items.
    """
    severities = severities or ["CRITICAL", "HIGH"]
    results = []
    end_dt = datetime.now(timezone.utc)
    start_str = since.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_str = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    elif os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]

    # Rate limit: 5 req/30s without key, 50 with key
    rate_delay = 6 if not headers.get("apiKey") else 0.7

    for severity in severities:
        params = {
            "pubStartDate": start_str,
            "pubEndDate": end_str,
            "cvssV3Severity": severity,
            "resultsPerPage": 100,
            "startIndex": 0,
        }
        start_index = 0
        while True:
            params["startIndex"] = start_index
            url = NVD_BASE_URL + "?" + urllib.parse.urlencode(params)
            log.info("NVD query: severity=%s, startIndex=%d", severity, start_index)
            data = _http_get(url, headers=headers, timeout=45)

            if data is None:
                log.warning("NVD query failed for severity=%s — skipping", severity)
                break

            vulns = data.get("vulnerabilities", [])
            results.extend(vulns)

            total = data.get("totalResults", 0)
            fetched = start_index + len(vulns)
            log.info("  NVD %s: %d/%d fetched", severity, fetched, total)

            if fetched >= total or fetched >= max_results or not vulns:
                break

            start_index += 100
            time.sleep(rate_delay)

        time.sleep(rate_delay)

    log.info("NVD: fetched %d total CVE items", len(results))
    return results


def nvd_item_to_threat(item: dict) -> dict | None:
    """Convert an NVD CVE item to our internal threat format."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # Get description
    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    # Get severity from metrics
    metrics = cve.get("metrics", {})
    severity = "UNKNOWN"
    cvss_score = None
    cvss_vector = None

    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key, [])
        if metric_list:
            m = metric_list[0].get("cvssData", {})
            severity = m.get("baseSeverity", severity)
            cvss_score = m.get("baseScore", cvss_score)
            cvss_vector = m.get("vectorString", cvss_vector)
            break

    pub_date = cve.get("published", "")[:10]

    return {
        "cve_id": cve_id,
        "source": "nvd",
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "title": description[:120] if description else cve_id,
        "description": description,
        "date_published": pub_date,
        "known_exploited": False,
        "ransomware_use": False,
        "affected_repos": [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# GitHub Advisory Database
# ─────────────────────────────────────────────────────────────────────────────

def fetch_github_advisories(since: datetime, token: str = None,
                             severities: list[str] = None) -> list[dict]:
    """
    Fetch recent GitHub Security Advisories via the REST API.
    Requires GITHUB_TOKEN for higher rate limits.
    """
    token = token or os.environ.get("GITHUB_TOKEN")
    severities = severities or ["critical", "high"]
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    results = []
    for severity in severities:
        params = {
            "type": "reviewed",
            "severity": severity,
            "per_page": 100,
            "page": 1,
            "published": f">={since.strftime('%Y-%m-%d')}",
        }
        url = GITHUB_ADVISORIES_URL + "?" + urllib.parse.urlencode(params)
        data = _http_get(url, headers=headers, timeout=30)
        if data is None:
            log.warning("GitHub Advisories query for severity=%s failed", severity)
            continue
        if isinstance(data, list):
            results.extend(data)
            log.info("GitHub Advisories: %d entries for severity=%s", len(data), severity)
        time.sleep(0.5)

    return results


def github_advisory_to_threat(advisory: dict) -> dict | None:
    """Convert a GitHub advisory to our internal threat format."""
    ghsa_id = advisory.get("ghsa_id", "")
    cve_id = advisory.get("cve_id") or ghsa_id
    if not cve_id:
        return None

    return {
        "cve_id": cve_id,
        "ghsa_id": ghsa_id,
        "source": "github_advisory",
        "severity": (advisory.get("severity") or "UNKNOWN").upper(),
        "title": advisory.get("summary", "")[:120],
        "description": advisory.get("description", ""),
        "date_published": (advisory.get("published_at") or "")[:10],
        "known_exploited": False,
        "ransomware_use": False,
        "affected_repos": [],
        "ecosystems": [v.get("package", {}).get("ecosystem") for v in advisory.get("vulnerabilities", []) if v.get("package")],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Cross-Reference Engine
# ─────────────────────────────────────────────────────────────────────────────

def version_in_range(version: str, range_str: str) -> bool | None:
    """
    Check if a version string satisfies a range expression.
    Returns True/False/None (None = unknown/cannot parse).
    Handles common formats: <X.Y.Z, >=X.Y.Z, <=X.Y.Z, >X.Y.Z, =X.Y.Z, [X.Y.Z, Y.Y.Y)
    """
    if not version or not range_str:
        return None

    def parse_version(v: str) -> tuple[int, ...] | None:
        """Parse a dotted version string into a tuple of ints."""
        try:
            parts = []
            for p in v.strip().split(".")[:4]:
                # Strip non-numeric suffixes (e.g., "1rc1" -> 1)
                num = ""
                for ch in p:
                    if ch.isdigit():
                        num += ch
                    else:
                        break
                parts.append(int(num) if num else 0)
            return tuple(parts)
        except Exception:
            return None

    v = parse_version(version)
    if v is None:
        return None

    range_str = range_str.strip()

    # Handle compound ranges separated by comma or space
    for sep in [",", " && "]:
        if sep in range_str:
            parts = [p.strip() for p in range_str.split(sep)]
            results = [version_in_range(version, p) for p in parts if p]
            if any(r is None for r in results):
                return None
            return all(r is True for r in results)

    # Single range expression
    ops = [(">=", lambda a, b: a >= b), ("<=", lambda a, b: a <= b),
           (">", lambda a, b: a > b), ("<", lambda a, b: a < b),
           ("=", lambda a, b: a == b), ("~=", lambda a, b: a[:2] == b[:2] and a >= b)]

    for op, fn in ops:
        if range_str.startswith(op):
            bound = parse_version(range_str[len(op):].strip())
            if bound is None:
                return None
            return fn(v, bound)

    # Maven/Gradle range notation [min, max]
    if range_str.startswith("[") or range_str.startswith("("):
        try:
            incl_start = range_str[0] == "["
            incl_end = range_str[-1] == "]"
            inner = range_str[1:-1]
            lo_str, hi_str = inner.split(",", 1)
            lo = parse_version(lo_str.strip()) if lo_str.strip() else (0,)
            hi = parse_version(hi_str.strip()) if hi_str.strip() else (999999,)
            if lo is None or hi is None:
                return None
            lo_ok = v >= lo if incl_start else v > lo
            hi_ok = v <= hi if incl_end else v < hi
            return lo_ok and hi_ok
        except Exception:
            pass

    # Bare version string — exact match
    bound = parse_version(range_str)
    if bound:
        return v == bound

    return None


def cross_reference_osv(deps: list[dict], osv_results: dict[tuple, list],
                         osv_details: dict[str, dict]) -> list[dict]:
    """
    Cross-reference dependency list against OSV findings.
    Returns list of exposure records.
    """
    exposures = []
    for dep in deps:
        key = (dep["osv_ecosystem"], dep["name"], dep["version"])
        vulns = osv_results.get(key)
        if not vulns:
            continue

        for vuln_ref in vulns:
            vuln_id = vuln_ref.get("id", "")
            detail = osv_details.get(vuln_id, {})

            # Get CVE alias
            cve_id = vuln_id
            aliases = detail.get("aliases", [])
            for alias in aliases:
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break

            # Find affected version range for this package
            affected_versions = ""
            fixed_version = ""
            for affected in detail.get("affected", []):
                pkg = affected.get("package", {})
                if pkg.get("name") != dep["name"]:
                    continue
                ranges = affected.get("ranges", [])
                for r in ranges:
                    for event in r.get("events", []):
                        if "fixed" in event:
                            fixed_version = event["fixed"]
                    if ranges:
                        # Build a human-readable range string
                        introduced = next((e.get("introduced") for e in r.get("events", []) if "introduced" in e), "")
                        fixed = next((e.get("fixed") for e in r.get("events", []) if "fixed" in e), "")
                        if introduced and fixed:
                            affected_versions = f">={introduced}, <{fixed}"
                        elif introduced:
                            affected_versions = f">={introduced}"
                        elif fixed:
                            affected_versions = f"<{fixed}"
                break

            # Determine exposure status
            if affected_versions:
                in_range = version_in_range(dep["version"], affected_versions)
                if in_range is True:
                    status = "EXPOSED"
                elif in_range is False:
                    status = "NOT_AFFECTED"
                else:
                    status = "POTENTIALLY_EXPOSED"
            else:
                status = "POTENTIALLY_EXPOSED"

            severity = detail.get("database_specific", {}).get("severity") or \
                       detail.get("severity", [{}])[0].get("score", "") if detail.get("severity") else "UNKNOWN"
            # Normalize severity
            if isinstance(severity, str) and severity.replace(".", "").isdigit():
                score = float(severity)
                if score >= 9.0:
                    severity = "CRITICAL"
                elif score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

            exposures.append({
                "osv_id": vuln_id,
                "cve_id": cve_id,
                "source": "osv",
                "repo": dep["repo"],
                "package": dep["name"],
                "ecosystem": dep["osv_ecosystem"],
                "installed_version": dep["version"],
                "affected_versions": affected_versions,
                "fixed_version": fixed_version,
                "status": status,
                "severity": severity,
                "title": detail.get("summary", detail.get("id", vuln_id)),
                "date_published": detail.get("published", "")[:10],
                "known_exploited": False,
                "ransomware_use": False,
            })

    return exposures


# ─────────────────────────────────────────────────────────────────────────────
# Report Generation
# ─────────────────────────────────────────────────────────────────────────────

def build_report(threats: list[dict], osv_exposures: list[dict],
                 lookback: str, sources_checked: list[str],
                 report_date: str) -> dict:
    """
    Build the final JSON report structure.
    Merges CISA KEV / NVD threats with OSV exposure data.
    """
    # Index OSV exposures by CVE ID
    osv_by_cve: dict[str, list[dict]] = {}
    for exp in osv_exposures:
        cid = exp["cve_id"]
        osv_by_cve.setdefault(cid, []).append(exp)

    # Build per-CVE threat entries
    merged_threats = []
    seen_cves = set()

    for threat in threats:
        cid = threat["cve_id"]
        seen_cves.add(cid)

        # Attach affected repo info from OSV cross-reference
        affected_repos = []
        for exp in osv_by_cve.get(cid, []):
            affected_repos.append({
                "repo": exp["repo"],
                "package": exp["package"],
                "ecosystem": exp["ecosystem"],
                "installed_version": exp["installed_version"],
                "affected_versions": exp["affected_versions"],
                "fixed_version": exp["fixed_version"],
                "status": exp["status"],
            })

        entry = dict(threat)
        entry["affected_repos"] = affected_repos
        merged_threats.append(entry)

    # Add OSV-only findings (CVEs not in CISA KEV / NVD but found via OSV)
    for cid, exps in osv_by_cve.items():
        if cid in seen_cves:
            continue
        first = exps[0]
        affected_repos = [{
            "repo": e["repo"],
            "package": e["package"],
            "ecosystem": e["ecosystem"],
            "installed_version": e["installed_version"],
            "affected_versions": e["affected_versions"],
            "fixed_version": e["fixed_version"],
            "status": e["status"],
        } for e in exps]
        merged_threats.append({
            "cve_id": cid,
            "source": "osv",
            "severity": first.get("severity", "UNKNOWN"),
            "title": first.get("title", cid),
            "description": "",
            "date_published": first.get("date_published", ""),
            "known_exploited": False,
            "ransomware_use": False,
            "affected_repos": affected_repos,
        })

    # Summary statistics
    threats_with_exposure = [t for t in merged_threats if t["affected_repos"]]
    exposed_repos = set()
    critical_count = 0
    high_count = 0

    for t in threats_with_exposure:
        for ar in t["affected_repos"]:
            if ar["status"] == "EXPOSED":
                exposed_repos.add(ar["repo"])
                sev = t.get("severity", "")
                if sev == "CRITICAL":
                    critical_count += 1
                elif sev == "HIGH":
                    high_count += 1

    return {
        "report_date": report_date,
        "lookback_period": lookback,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources_checked": sources_checked,
        "new_threats": merged_threats,
        "summary": {
            "total_new_threats": len(merged_threats),
            "threats_affecting_monitored_repos": len(threats_with_exposure),
            "repos_with_exposure": len(exposed_repos),
            "critical_exposures": critical_count,
            "high_exposures": high_count,
        },
    }


def build_markdown_summary(report: dict) -> str:
    """Generate a markdown summary from the report."""
    summary = report["summary"]
    date = report["report_date"]
    lookback = report["lookback_period"]
    sources = ", ".join(report["sources_checked"])

    lines = [
        f"# Threat Intel Monitor Report — {date}",
        "",
        f"**Lookback Period:** {lookback}  ",
        f"**Sources Checked:** {sources}  ",
        f"**Generated:** {report.get('generated_at', '')[:19]}Z",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total New Threats | {summary['total_new_threats']} |",
        f"| Threats Affecting Monitored Repos | {summary['threats_affecting_monitored_repos']} |",
        f"| Repos With Exposure | {summary['repos_with_exposure']} |",
        f"| Critical Exposures | {summary['critical_exposures']} |",
        f"| High Exposures | {summary['high_exposures']} |",
        "",
    ]

    # Priority: threats with EXPOSED repos
    exposed_threats = [t for t in report["new_threats"]
                       if any(ar["status"] == "EXPOSED" for ar in t["affected_repos"])]

    if exposed_threats:
        lines += [
            "---",
            "",
            "## ⚠ Active Exposures — Immediate Action Required",
            "",
        ]
        for t in exposed_threats:
            known = " 🔴 ACTIVELY EXPLOITED" if t.get("known_exploited") else ""
            ransomware = " 💀 RANSOMWARE" if t.get("ransomware_use") else ""
            lines += [
                f"### {t['cve_id']} — {t['severity']}{known}{ransomware}",
                f"**Title:** {t.get('title', 'N/A')}  ",
                f"**Source:** {t['source']}  ",
                f"**Published:** {t.get('date_published', 'N/A')}  ",
                "",
                "**Affected Repositories:**",
                "",
                "| Repo | Package | Installed | Affected Range | Fixed In | Status |",
                "|------|---------|-----------|---------------|----------|--------|",
            ]
            for ar in t["affected_repos"]:
                if ar["status"] == "EXPOSED":
                    lines.append(
                        f"| {ar['repo']} | `{ar['package']}` | `{ar['installed_version']}` "
                        f"| `{ar['affected_versions']}` | `{ar.get('fixed_version', 'N/A')}` | **EXPOSED** |"
                    )
            lines.append("")

    # Threats with potential exposure
    potential_threats = [t for t in report["new_threats"]
                         if any(ar["status"] == "POTENTIALLY_EXPOSED" for ar in t["affected_repos"])
                         and not any(ar["status"] == "EXPOSED" for ar in t["affected_repos"])]

    if potential_threats:
        lines += [
            "---",
            "",
            "## ⚡ Potential Exposures — Verification Required",
            "",
            "| CVE | Severity | Title | Repo | Package | Installed |",
            "|-----|----------|-------|------|---------|-----------|",
        ]
        for t in potential_threats:
            for ar in t["affected_repos"]:
                if ar["status"] == "POTENTIALLY_EXPOSED":
                    lines.append(
                        f"| {t['cve_id']} | {t['severity']} | {t.get('title', '')[:50]} "
                        f"| {ar['repo']} | `{ar['package']}` | `{ar['installed_version']}` |"
                    )
        lines.append("")

    # New KEV entries (even if no repo exposure found)
    kev_threats = [t for t in report["new_threats"]
                   if t.get("known_exploited") and not t.get("affected_repos")]
    if kev_threats:
        lines += [
            "---",
            "",
            "## CISA KEV Entries (No Monitored Repos Affected)",
            "",
            "_These CVEs are actively exploited but no currently monitored repos appear exposed._",
            "",
            "| CVE | Title | Date Added | Ransomware |",
            "|-----|-------|-----------|-----------|",
        ]
        for t in kev_threats[:20]:  # Cap at 20 for readability
            ransomware = "Yes" if t.get("ransomware_use") else "No"
            lines.append(
                f"| {t['cve_id']} | {t.get('title', '')[:60]} "
                f"| {t.get('date_published', 'N/A')} | {ransomware} |"
            )
        if len(kev_threats) > 20:
            lines.append(f"| _(+{len(kev_threats) - 20} more)_ | | | |")
        lines.append("")

    lines += [
        "---",
        "",
        "## Recommended Actions",
        "",
        "1. **EXPOSED packages** — Update immediately to the fixed version.",
        "2. **POTENTIALLY_EXPOSED packages** — Manually verify version against CVE advisory.",
        "3. **CISA KEV entries** — Treat with highest urgency; these are confirmed exploits.",
        "4. For ransomware-associated CVEs, consider incident response readiness.",
        "",
        "---",
        f"_Generated by threat-intel-monitor v1.0 (GRIMSEC Suite)_",
    ]

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Threat Intel Monitor — cross-reference CVE feeds against repo inventories"
    )
    parser.add_argument("--lookback", default="7d", choices=["1d", "7d", "30d"],
                        help="Time window for CVE lookback (default: 7d)")
    parser.add_argument("--inventory-dir", default="devsecops-analysis/",
                        help="Root directory containing repo subdirs with inventory.json")
    parser.add_argument("--output-dir", default="devsecops-analysis/threat-intel/",
                        help="Directory to write reports to")
    parser.add_argument("--nvd-api-key", default=None,
                        help="NVD API key for higher rate limits")
    parser.add_argument("--no-nvd", action="store_true",
                        help="Skip NVD enrichment")
    parser.add_argument("--no-github", action="store_true",
                        help="Skip GitHub Advisory Database")
    parser.add_argument("--cache-dir", default="/tmp/threat-intel-cache/",
                        help="Local cache directory for feeds")
    parser.add_argument("--severity", default="HIGH,CRITICAL",
                        help="Comma-separated severity filter (default: HIGH,CRITICAL)")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose logging")
    return parser.parse_args()


def main():
    args = parse_args()

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    inventory_dir = Path(args.inventory_dir)
    output_dir = Path(args.output_dir)
    cache_dir = Path(args.cache_dir)
    lookback_days = LOOKBACK_MAP.get(args.lookback, 7)
    severities = [s.strip().upper() for s in args.severity.split(",")]

    now = datetime.now(timezone.utc)
    since = now - timedelta(days=lookback_days)
    report_date = now.strftime("%Y-%m-%d")

    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    log.info("="*60)
    log.info("Threat Intel Monitor — GRIMSEC Suite")
    log.info("Lookback: %s (since %s)", args.lookback, since.strftime("%Y-%m-%d"))
    log.info("Inventory dir: %s", inventory_dir)
    log.info("Output dir: %s", output_dir)
    log.info("="*60)

    # ── Phase 1: Load Inventories ─────────────────────────────────────────
    log.info("[Phase 1] Loading dependency inventories...")
    inventories = load_inventories(inventory_dir)
    if not inventories:
        log.warning("No inventory.json files found in %s", inventory_dir)

    all_deps = []
    for inv in inventories:
        deps = extract_dependencies(inv)
        all_deps.extend(deps)
        log.info("  Repo '%s': %d dependencies extracted", inv["repo"], len(deps))

    log.info("Total dependencies across all repos: %d", len(all_deps))

    # ── Phase 2: Fetch Threat Intel Feeds ────────────────────────────────
    log.info("[Phase 2] Fetching threat intel feeds...")
    all_threats = []
    sources_checked = []

    # 2a. CISA KEV
    log.info("  [CISA KEV] Fetching...")
    kev_all = fetch_cisa_kev(cache_dir)
    kev_recent = filter_kev_by_date(kev_all, since)
    log.info("  [CISA KEV] %d total entries, %d in lookback window", len(kev_all), len(kev_recent))
    kev_threats = [kev_to_threat(e) for e in kev_recent]
    all_threats.extend(kev_threats)
    if kev_all:
        sources_checked.append("cisa_kev")

    # 2b. NVD
    if not args.no_nvd:
        log.info("  [NVD] Fetching recent %s CVEs...", "/".join(severities))
        nvd_items = fetch_nvd_recent(since, api_key=args.nvd_api_key, severities=severities)
        nvd_threats = [t for t in (nvd_item_to_threat(i) for i in nvd_items) if t]
        # Deduplicate against KEV (KEV already has these, keep KEV version)
        kev_cve_ids = {t["cve_id"] for t in kev_threats}
        nvd_threats = [t for t in nvd_threats if t["cve_id"] not in kev_cve_ids]
        log.info("  [NVD] %d new CVEs (after KEV dedup)", len(nvd_threats))
        all_threats.extend(nvd_threats)
        sources_checked.append("nvd")

    # 2c. GitHub Advisories
    if not args.no_github:
        log.info("  [GitHub Advisories] Fetching...")
        gh_raw = fetch_github_advisories(since, severities=[s.lower() for s in severities])
        gh_threats = [t for t in (github_advisory_to_threat(a) for a in gh_raw) if t]
        # Deduplicate by CVE ID
        seen_ids = {t["cve_id"] for t in all_threats}
        gh_threats = [t for t in gh_threats if t["cve_id"] not in seen_ids]
        log.info("  [GitHub Advisories] %d new entries (after dedup)", len(gh_threats))
        all_threats.extend(gh_threats)
        if gh_raw:
            sources_checked.append("github_advisory")

    log.info("Total unique threats collected: %d", len(all_threats))

    # ── Phase 3: OSV Cross-Reference ─────────────────────────────────────
    log.info("[Phase 3] Running OSV.dev exposure cross-reference...")
    osv_exposures = []

    if all_deps:
        osv_queries = build_osv_queries(all_deps)
        osv_results = query_osv_batch(osv_queries)

        # Collect unique vuln IDs to enrich
        all_vuln_ids = set()
        for vulns in osv_results.values():
            for v in vulns:
                all_vuln_ids.add(v.get("id", ""))
        all_vuln_ids.discard("")

        log.info("  Enriching %d unique OSV vulnerability records...", len(all_vuln_ids))
        osv_detail_list = enrich_osv_vulns(list(all_vuln_ids))
        osv_details = {d["id"]: d for d in osv_detail_list if d.get("id")}

        osv_exposures = cross_reference_osv(all_deps, osv_results, osv_details)
        exposed_count = sum(1 for e in osv_exposures if e["status"] == "EXPOSED")
        log.info("  OSV cross-reference: %d exposures (%d EXPOSED)", len(osv_exposures), exposed_count)

        if osv_results:
            sources_checked.append("osv")

    # ── Phase 4: Build & Write Reports ───────────────────────────────────
    log.info("[Phase 4] Generating reports...")
    report = build_report(all_threats, osv_exposures, args.lookback, sources_checked, report_date)
    markdown = build_markdown_summary(report)

    json_path = output_dir / f"{report_date}-report.json"
    md_path = output_dir / f"{report_date}-summary.md"

    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    with open(md_path, "w") as f:
        f.write(markdown)

    log.info("="*60)
    log.info("Reports written:")
    log.info("  JSON: %s", json_path)
    log.info("  Markdown: %s", md_path)
    log.info("")
    log.info("Summary:")
    s = report["summary"]
    log.info("  Total new threats:           %d", s["total_new_threats"])
    log.info("  Affecting monitored repos:   %d", s["threats_affecting_monitored_repos"])
    log.info("  Repos with exposure:         %d", s["repos_with_exposure"])
    log.info("  Critical exposures:          %d", s["critical_exposures"])
    log.info("  High exposures:              %d", s["high_exposures"])
    log.info("="*60)

    # Exit with non-zero if critical exposures found
    if s["critical_exposures"] > 0:
        log.warning("CRITICAL exposures detected — review report immediately!")
        sys.exit(2)
    elif s["repos_with_exposure"] > 0:
        log.warning("Exposures detected — review report.")
        sys.exit(1)
    else:
        log.info("No exposures detected in monitored repos.")
        sys.exit(0)


if __name__ == "__main__":
    main()
