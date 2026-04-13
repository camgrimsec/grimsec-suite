#!/usr/bin/env python3
"""
collect-evidence.py — GRIMSEC OSS Forensics Agent (Agent 11)

Multi-source evidence gathering for forensic investigation of GitHub repositories.
Collects data from: GitHub REST/GraphQL API, GH Archive, Wayback Machine, package registries.

Usage:
    python collect-evidence.py --repo owner/repo [--token GITHUB_TOKEN] [--output-dir forensics/evidence]

Environment:
    GITHUB_TOKEN — GitHub personal access token (fine-grained or classic with repo scope)
"""

import argparse
import gzip
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] {msg}", file=sys.stderr)


def make_headers(token: str | None = None) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "GRIMSEC-OSS-Forensics/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def gh_get(path: str, token: str | None = None, base: str = "https://api.github.com") -> dict | list:
    """GitHub REST API GET with automatic pagination."""
    url = f"{base}{path}" if path.startswith("/") else path
    all_items = []
    while url:
        req = urllib.request.Request(url, headers=make_headers(token))
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
                link_header = resp.headers.get("Link", "")
                if isinstance(data, list):
                    all_items.extend(data)
                    # Parse next page from Link header
                    next_url = None
                    for part in link_header.split(","):
                        part = part.strip()
                        if 'rel="next"' in part:
                            next_url = part.split(";")[0].strip().strip("<>")
                    url = next_url
                else:
                    return data
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            log(f"HTTP {e.code} for {url}: {body[:200]}")
            if e.code == 404:
                return {}
            raise
        except Exception as e:
            log(f"Error fetching {url}: {e}")
            raise
    return all_items


def save_json(data: object, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    log(f"Saved: {path} ({path.stat().st_size:,} bytes)")


def fetch_url_raw(url: str, headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "GRIMSEC-OSS-Forensics/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


# ---------------------------------------------------------------------------
# Phase 1a: GitHub API Evidence
# ---------------------------------------------------------------------------

def collect_github_api(owner: str, repo: str, token: str | None, out_dir: Path) -> dict:
    log(f"=== Phase 1a: GitHub API — {owner}/{repo} ===")
    evidence = {}

    endpoints = {
        "repo": f"/repos/{owner}/{repo}",
        "branches": f"/repos/{owner}/{repo}/branches?per_page=100",
        "releases": f"/repos/{owner}/{repo}/releases?per_page=100",
        "contributors": f"/repos/{owner}/{repo}/contributors?per_page=100&anon=1",
        "collaborators": f"/repos/{owner}/{repo}/collaborators?per_page=100",
        "hooks": f"/repos/{owner}/{repo}/hooks",
        "deploy_keys": f"/repos/{owner}/{repo}/keys",
        "workflows": f"/repos/{owner}/{repo}/actions/workflows",
        "workflow_runs": f"/repos/{owner}/{repo}/actions/runs?per_page=50",
        "teams": f"/repos/{owner}/{repo}/teams",
    }

    for key, path in endpoints.items():
        log(f"  Fetching: {key}")
        try:
            evidence[key] = gh_get(path, token)
            time.sleep(0.3)  # Respect rate limits
        except Exception as e:
            log(f"  Warning: Could not fetch {key}: {e}")
            evidence[key] = {"error": str(e)}

    # Commits — get up to 500
    log("  Fetching: commits (up to 500)")
    try:
        commits_raw = gh_get(f"/repos/{owner}/{repo}/commits?per_page=100", token)
        if isinstance(commits_raw, list) and len(commits_raw) == 100:
            # Try to get more pages
            page = 2
            while page <= 5:
                more = gh_get(f"/repos/{owner}/{repo}/commits?per_page=100&page={page}", token)
                if not more:
                    break
                commits_raw.extend(more)
                if len(more) < 100:
                    break
                page += 1
                time.sleep(0.3)
        evidence["commits"] = commits_raw
    except Exception as e:
        log(f"  Warning: Could not fetch commits: {e}")
        evidence["commits"] = {"error": str(e)}

    # Branch protection for default branch
    try:
        default_branch = evidence.get("repo", {}).get("default_branch", "main")
        log(f"  Fetching branch protection for: {default_branch}")
        evidence["branch_protection"] = gh_get(
            f"/repos/{owner}/{repo}/branches/{default_branch}/protection", token
        )
    except Exception as e:
        log(f"  Warning: branch protection: {e}")
        evidence["branch_protection"] = {"error": str(e)}

    # Pull requests — open and closed
    log("  Fetching: pull requests")
    try:
        prs = gh_get(f"/repos/{owner}/{repo}/pulls?state=all&per_page=100", token)
        evidence["pull_requests"] = prs
    except Exception as e:
        log(f"  Warning: PRs: {e}")
        evidence["pull_requests"] = {"error": str(e)}

    # Issues
    log("  Fetching: issues")
    try:
        issues = gh_get(f"/repos/{owner}/{repo}/issues?state=all&per_page=100", token)
        evidence["issues"] = issues
    except Exception as e:
        log(f"  Warning: issues: {e}")
        evidence["issues"] = {"error": str(e)}

    save_json(evidence, out_dir / f"github-api-{owner}-{repo}.json")
    return evidence


# ---------------------------------------------------------------------------
# Phase 1b: Commit Detail Extraction
# ---------------------------------------------------------------------------

def collect_commit_details(owner: str, repo: str, token: str | None,
                            evidence: dict, out_dir: Path,
                            max_commits: int = 50) -> list:
    """Fetch detailed patch data for commits (files changed, diffs)."""
    log(f"=== Phase 1b: Commit Detail (top {max_commits}) ===")
    commits = evidence.get("commits", [])
    if not isinstance(commits, list):
        log("  No commits list available.")
        return []

    details = []
    for commit in commits[:max_commits]:
        sha = commit.get("sha", "")
        if not sha:
            continue
        try:
            detail = gh_get(f"/repos/{owner}/{repo}/commits/{sha}", token)
            details.append(detail)
            time.sleep(0.2)
        except Exception as e:
            log(f"  Warning: could not fetch commit {sha}: {e}")

    save_json(details, out_dir / f"commits-detail-{owner}-{repo}.json")
    log(f"  Collected {len(details)} commit details.")
    return details


# ---------------------------------------------------------------------------
# Phase 1c: GH Archive
# ---------------------------------------------------------------------------

def collect_gh_archive(owner: str, repo: str, out_dir: Path,
                        days_back: int = 90) -> list:
    """
    Download and filter GH Archive hourly files for events related to this repo.
    Covers: PushEvent, PullRequestEvent, MemberEvent, ReleaseEvent, DeleteEvent,
            TeamAddEvent, PublicEvent.
    """
    log(f"=== Phase 1c: GH Archive — last {days_back} days ===")
    from datetime import timedelta

    target_repo = f"{owner}/{repo}"
    relevant_types = {
        "PushEvent", "PullRequestEvent", "MemberEvent", "TeamAddEvent",
        "ReleaseEvent", "DeleteEvent", "PublicEvent", "ForkEvent",
        "CreateEvent", "IssuesEvent", "IssueCommentEvent",
    }

    events = []
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days_back)

    current = start_date
    files_checked = 0
    files_with_data = 0

    while current <= end_date:
        # GH Archive format: YYYY-MM-DD-H (hour 0-23)
        for hour in range(24):
            date_str = current.strftime("%Y-%m-%d")
            url = f"https://data.gharchive.org/{date_str}-{hour}.json.gz"
            try:
                raw = fetch_url_raw(url)
                files_checked += 1
                content = gzip.decompress(raw).decode("utf-8", errors="replace")
                for line in content.strip().split("\n"):
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        if (event.get("repo", {}).get("name") == target_repo and
                                event.get("type") in relevant_types):
                            events.append(event)
                            files_with_data += 1
                    except json.JSONDecodeError:
                        continue
            except Exception as e:
                # Many hours will 404 for recent/future dates, skip silently
                if "404" not in str(e):
                    log(f"  Warning GH Archive {date_str}-{hour}: {e}")

        current += timedelta(days=1)

        # Progress update every 7 days
        if (current - start_date).days % 7 == 0:
            log(f"  Progress: {current.date()} — {len(events)} events found so far")

    log(f"  GH Archive: checked {files_checked} files, found {len(events)} events for {target_repo}")
    save_json(events, out_dir / "gh-archive-events.json")
    return events


def build_gh_archive_bigquery_query(owner: str, repo: str, start_date: str, end_date: str) -> str:
    """Generate a BigQuery query for GH Archive (use when BQ access is available)."""
    return f"""
-- GH Archive BigQuery Query for {owner}/{repo}
-- Run in: https://console.cloud.google.com/bigquery
-- Dataset: githubarchive.day.*
SELECT
  created_at,
  type,
  actor.login AS actor_login,
  repo.name AS repo_name,
  payload
FROM
  `githubarchive.day.*`
WHERE
  _TABLE_SUFFIX BETWEEN '{start_date.replace("-", "")}' AND '{end_date.replace("-", "")}'
  AND repo.name = '{owner}/{repo}'
  AND type IN (
    'PushEvent', 'PullRequestEvent', 'MemberEvent', 'TeamAddEvent',
    'ReleaseEvent', 'DeleteEvent', 'PublicEvent', 'ForkEvent',
    'CreateEvent', 'IssuesEvent', 'IssueCommentEvent'
  )
ORDER BY created_at ASC
"""


# ---------------------------------------------------------------------------
# Phase 1d: Wayback Machine
# ---------------------------------------------------------------------------

def collect_wayback(owner: str, repo: str, out_dir: Path) -> dict:
    """Query Wayback Machine CDX API for historical snapshots of key repo URLs."""
    log("=== Phase 1d: Wayback Machine ===")

    target_urls = [
        f"https://github.com/{owner}/{repo}",
        f"https://github.com/{owner}/{repo}/blob/main/package.json",
        f"https://github.com/{owner}/{repo}/blob/main/setup.py",
        f"https://github.com/{owner}/{repo}/blob/main/.github/workflows/",
        f"https://github.com/{owner}/{repo}/releases",
    ]

    snapshots = {}
    base_cdx = "https://web.archive.org/cdx/search/cdx"

    for target_url in target_urls:
        params = urllib.parse.urlencode({
            "url": target_url,
            "output": "json",
            "fl": "timestamp,statuscode,original,mimetype",
            "limit": "200",
            "collapse": "timestamp:8",  # Daily dedup
        })
        cdx_url = f"{base_cdx}?{params}"
        try:
            raw = fetch_url_raw(cdx_url)
            data = json.loads(raw)
            if data and len(data) > 1:
                # First row is header
                headers = data[0]
                rows = [dict(zip(headers, row)) for row in data[1:]]
                snapshots[target_url] = rows
                log(f"  {target_url}: {len(rows)} snapshots found")
            else:
                snapshots[target_url] = []
        except Exception as e:
            log(f"  Warning: Wayback CDX for {target_url}: {e}")
            snapshots[target_url] = {"error": str(e)}

    save_json(snapshots, out_dir / "wayback-snapshots.json")
    return snapshots


def fetch_wayback_snapshot(timestamp: str, original_url: str) -> str:
    """Fetch a specific Wayback Machine snapshot."""
    wayback_url = f"https://web.archive.org/web/{timestamp}/{original_url}"
    raw = fetch_url_raw(wayback_url)
    return raw.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Phase 1e: Package Registry
# ---------------------------------------------------------------------------

def collect_npm_history(package_name: str, out_dir: Path) -> dict:
    """Fetch npm package publish history and maintainer info."""
    log(f"=== Phase 1e: npm — {package_name} ===")
    try:
        raw = fetch_url_raw(f"https://registry.npmjs.org/{urllib.parse.quote(package_name)}")
        data = json.loads(raw)
        # Extract key forensic fields
        forensic = {
            "name": data.get("name"),
            "description": data.get("description"),
            "dist-tags": data.get("dist-tags"),
            "time": data.get("time"),  # version publish timestamps
            "maintainers": data.get("maintainers"),
            "versions_summary": {},
        }
        for version, vdata in data.get("versions", {}).items():
            forensic["versions_summary"][version] = {
                "publish_time": data.get("time", {}).get(version),
                "_npmUser": vdata.get("_npmUser"),
                "maintainers": vdata.get("maintainers"),
                "scripts": vdata.get("scripts"),
                "dependencies": vdata.get("dependencies"),
                "dist": vdata.get("dist"),
            }
        save_json(forensic, out_dir / f"registry-npm-{package_name.replace('/', '-')}-history.json")
        return forensic
    except Exception as e:
        log(f"  Warning: npm {package_name}: {e}")
        return {"error": str(e)}


def collect_pypi_history(package_name: str, out_dir: Path) -> dict:
    """Fetch PyPI package release history."""
    log(f"=== Phase 1e: PyPI — {package_name} ===")
    try:
        raw = fetch_url_raw(f"https://pypi.org/pypi/{urllib.parse.quote(package_name)}/json")
        data = json.loads(raw)
        forensic = {
            "name": data.get("info", {}).get("name"),
            "author": data.get("info", {}).get("author"),
            "author_email": data.get("info", {}).get("author_email"),
            "home_page": data.get("info", {}).get("home_page"),
            "releases": {},
        }
        for version, files in data.get("releases", {}).items():
            forensic["releases"][version] = [
                {
                    "upload_time": f.get("upload_time"),
                    "filename": f.get("filename"),
                    "md5_digest": f.get("md5_digest"),
                    "sha256_digest": f.get("digests", {}).get("sha256"),
                    "requires_python": f.get("requires_python"),
                }
                for f in files
            ]
        save_json(forensic, out_dir / f"registry-pypi-{package_name}-history.json")
        return forensic
    except Exception as e:
        log(f"  Warning: PyPI {package_name}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="GRIMSEC OSS Forensics — Multi-source evidence collector"
    )
    parser.add_argument("--repo", required=True, help="owner/repo format")
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"), help="GitHub token")
    parser.add_argument("--output-dir", default="forensics/evidence", help="Output directory")
    parser.add_argument("--npm-package", help="npm package name to check (if different from repo)")
    parser.add_argument("--pypi-package", help="PyPI package name to check")
    parser.add_argument("--days-archive", type=int, default=30,
                        help="Days of GH Archive to search (default: 30; set 0 to skip)")
    parser.add_argument("--skip-archive", action="store_true",
                        help="Skip GH Archive download (slow for large ranges)")
    args = parser.parse_args()

    if "/" not in args.repo:
        print("ERROR: --repo must be in owner/repo format", file=sys.stderr)
        sys.exit(1)

    owner, repo = args.repo.split("/", 1)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    log(f"Starting evidence collection for {owner}/{repo}")
    if args.token:
        log("GitHub token: provided")
    else:
        log("WARNING: No GitHub token — rate limits apply (60 req/hr)")

    # Phase 1a: GitHub API
    evidence = collect_github_api(owner, repo, args.token, out_dir)

    # Phase 1b: Commit details
    collect_commit_details(owner, repo, args.token, evidence, out_dir)

    # Phase 1c: GH Archive
    if not args.skip_archive and args.days_archive > 0:
        collect_gh_archive(owner, repo, out_dir, days_back=args.days_archive)
        # Also print the BigQuery query for manual use
        bq_query = build_gh_archive_bigquery_query(
            owner, repo,
            start_date="2024-01-01",
            end_date=datetime.now(timezone.utc).strftime("%Y-%m-%d")
        )
        (out_dir / "gh-archive-bigquery-query.sql").write_text(bq_query)
        log("GH Archive BigQuery query saved.")
    else:
        log("Skipping GH Archive download.")

    # Phase 1d: Wayback Machine
    collect_wayback(owner, repo, out_dir)

    # Phase 1e: Package registries
    if args.npm_package:
        collect_npm_history(args.npm_package, out_dir)
    if args.pypi_package:
        collect_pypi_history(args.pypi_package, out_dir)

    # Manifest
    manifest = {
        "repo": f"{owner}/{repo}",
        "collection_timestamp": datetime.now(timezone.utc).isoformat(),
        "token_provided": bool(args.token),
        "sources_collected": [
            "github_api",
            "commit_details",
            "wayback_machine",
            *(["gh_archive"] if not args.skip_archive else []),
            *(["npm_registry"] if args.npm_package else []),
            *(["pypi_registry"] if args.pypi_package else []),
        ],
        "output_dir": str(out_dir),
    }
    save_json(manifest, out_dir / "collection-manifest.json")
    log("Evidence collection complete.")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
