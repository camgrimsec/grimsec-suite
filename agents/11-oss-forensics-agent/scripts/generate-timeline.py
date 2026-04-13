#!/usr/bin/env python3
"""
generate-timeline.py — GRIMSEC OSS Forensics Agent (Agent 11)

Event timeline reconstruction from collected forensic evidence.
Correlates git commits, GitHub API events, GH Archive events, package registry
publishes, and Wayback Machine snapshots into a unified chronological timeline.

Usage:
    python generate-timeline.py --evidence-dir forensics/evidence [--output-dir forensics]

Input files (from collect-evidence.py and analyze-commits.py):
    forensics/evidence/github-api-{owner}-{repo}.json
    forensics/evidence/gh-archive-events.json
    forensics/evidence/commits-detail-{owner}-{repo}.json
    forensics/evidence/wayback-snapshots.json
    forensics/evidence/registry-npm-*.json
    forensics/evidence/registry-pypi-*.json
    forensics/ioc-candidates.json  (from analyze-commits.py)

Output:
    forensics/timeline.json
"""

import argparse
import glob
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] {msg}", file=sys.stderr)


def parse_iso(date_str: str | None) -> datetime | None:
    """Parse ISO 8601 string to UTC datetime. Returns None if unparseable."""
    if not date_str:
        return None
    # Try a few formats
    for fmt in [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]:
        try:
            dt = datetime.strptime(date_str[:len(fmt) + 6], fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    # Try dateutil as fallback
    try:
        from datetime import timedelta
        # Attempt basic offset parsing: 2024-01-15T12:00:00+05:30
        m = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})([+-])(\d{2}):(\d{2})', date_str)
        if m:
            dt = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
            sign = 1 if m.group(2) == "+" else -1
            offset = timedelta(hours=int(m.group(3)), minutes=int(m.group(4)))
            dt = dt - sign * offset
            return dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    return None


def save_json(data: object, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    log(f"Saved: {path} ({path.stat().st_size:,} bytes)")


def load_json(path: Path) -> object:
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Event Builders
# ---------------------------------------------------------------------------

def classify_event(event_type: str, actor: str, summary: str,
                   ioc_sha_map: dict) -> str:
    """
    Classify an event as NORMAL, SUSPICIOUS, MALICIOUS, RESPONSE, or UNKNOWN.
    Override with IOC map if we have evidence from the commit.
    """
    summary_lower = summary.lower()
    # Response signals
    if any(kw in summary_lower for kw in [
        "revert", "fix security", "remove malicious", "hotfix",
        "emergency", "patch cve", "disclose", "advisory"
    ]):
        return "RESPONSE"
    # Suspicious signals
    if any(kw in summary_lower for kw in [
        "force push", "forced update", "delete branch", "remove maintainer",
        "disable protection", "workflow modified", "add webhook",
    ]):
        return "SUSPICIOUS"
    # Let IOC map override
    if event_type == "commit" and summary in ioc_sha_map:
        return "MALICIOUS"
    return "NORMAL"


def events_from_git_api(github_data: dict, ioc_sha_map: dict) -> list[dict]:
    """Extract timeline events from GitHub API commit data."""
    events = []
    commits = github_data.get("commits", [])
    if not isinstance(commits, list):
        return events

    for c in commits:
        sha = c.get("sha", "")
        commit_obj = c.get("commit", {})
        author = commit_obj.get("author", {})
        committer = commit_obj.get("committer", {})
        actor = (c.get("author") or {}).get("login") or author.get("email", "unknown")
        date = author.get("date") or committer.get("date")
        message = commit_obj.get("message", "")
        subject = message.split("\n")[0][:120]

        classification = "MALICIOUS" if sha in ioc_sha_map else "NORMAL"

        events.append({
            "timestamp": date,
            "event_type": "commit",
            "classification": classification,
            "actor": actor,
            "summary": f"Commit: {subject}",
            "ioc_refs": ioc_sha_map.get(sha, []),
            "evidence_url": c.get("html_url", ""),
            "raw": {
                "sha": sha,
                "author_email": author.get("email"),
                "committer_email": committer.get("email"),
                "files_count": len(c.get("files", [])),
            },
        })
    return events


def events_from_releases(github_data: dict) -> list[dict]:
    """Extract release events."""
    events = []
    releases = github_data.get("releases", [])
    if not isinstance(releases, list):
        return events

    for r in releases:
        actor = (r.get("author") or {}).get("login", "unknown")
        events.append({
            "timestamp": r.get("published_at") or r.get("created_at"),
            "event_type": "release",
            "classification": "NORMAL",
            "actor": actor,
            "summary": f"Release: {r.get('tag_name', '')} — {r.get('name', '')}",
            "ioc_refs": [],
            "evidence_url": r.get("html_url", ""),
            "raw": {
                "tag_name": r.get("tag_name"),
                "prerelease": r.get("prerelease"),
                "draft": r.get("draft"),
                "assets_count": len(r.get("assets", [])),
            },
        })
    return events


def events_from_pull_requests(github_data: dict) -> list[dict]:
    """Extract PR open/merge/close events."""
    events = []
    prs = github_data.get("pull_requests", [])
    if not isinstance(prs, list):
        return events

    for pr in prs:
        actor = (pr.get("user") or {}).get("login", "unknown")
        # PR opened
        events.append({
            "timestamp": pr.get("created_at"),
            "event_type": "pr_opened",
            "classification": "NORMAL",
            "actor": actor,
            "summary": f"PR #{pr.get('number')} opened: {pr.get('title', '')[:80]}",
            "ioc_refs": [],
            "evidence_url": pr.get("html_url", ""),
            "raw": {"number": pr.get("number"), "state": pr.get("state")},
        })
        # PR merged
        if pr.get("merged_at"):
            merger = (pr.get("merged_by") or {}).get("login", "unknown")
            events.append({
                "timestamp": pr.get("merged_at"),
                "event_type": "pr_merged",
                "classification": "NORMAL",
                "actor": merger,
                "summary": f"PR #{pr.get('number')} merged: {pr.get('title', '')[:80]}",
                "ioc_refs": [],
                "evidence_url": pr.get("html_url", ""),
                "raw": {"number": pr.get("number")},
            })
    return events


def events_from_collaborators(github_data: dict) -> list[dict]:
    """Extract collaborator additions (from API snapshot — no timestamps available)."""
    events = []
    collaborators = github_data.get("collaborators", [])
    if not isinstance(collaborators, list):
        return events
    # We can't get the exact time from the current collaborators list,
    # but we record their current presence as a UNKNOWN-time event
    for col in collaborators:
        login = col.get("login", "unknown")
        perm = col.get("role_name") or col.get("permissions", {})
        events.append({
            "timestamp": None,  # Unknown — check GH Archive MemberEvents
            "event_type": "collaborator_present",
            "classification": "UNKNOWN",
            "actor": login,
            "summary": f"Collaborator present: {login} (permission: {perm})",
            "ioc_refs": [],
            "evidence_url": col.get("html_url", ""),
            "raw": col,
        })
    return events


def events_from_gh_archive(archive_events: list) -> list[dict]:
    """Convert GH Archive raw events to timeline format."""
    events = []
    for ev in archive_events:
        ev_type = ev.get("type", "")
        actor = ev.get("actor", {}).get("login", "unknown")
        created_at = ev.get("created_at")
        payload = ev.get("payload", {})

        # Map event types to human-readable summaries
        if ev_type == "PushEvent":
            forced = payload.get("forced", False)
            commits_count = len(payload.get("commits", []))
            summary = f"Push ({commits_count} commits)" + (" [FORCE PUSH]" if forced else "")
            classification = "SUSPICIOUS" if forced else "NORMAL"
        elif ev_type == "MemberEvent":
            action = payload.get("action", "")
            member = (payload.get("member") or {}).get("login", "unknown")
            summary = f"Member {action}: {member}"
            classification = "SUSPICIOUS" if action == "added" else "NORMAL"
        elif ev_type == "TeamAddEvent":
            member = (payload.get("user") or {}).get("login", "unknown")
            summary = f"Team member added: {member}"
            classification = "SUSPICIOUS"
        elif ev_type == "ReleaseEvent":
            action = payload.get("action", "")
            tag = (payload.get("release") or {}).get("tag_name", "")
            summary = f"Release {action}: {tag}"
            classification = "NORMAL"
        elif ev_type == "DeleteEvent":
            ref_type = payload.get("ref_type", "")
            ref = payload.get("ref", "")
            summary = f"Deleted {ref_type}: {ref}"
            classification = "SUSPICIOUS"
        elif ev_type == "PublicEvent":
            summary = "Repository made public"
            classification = "NORMAL"
        elif ev_type == "CreateEvent":
            ref_type = payload.get("ref_type", "")
            ref = payload.get("ref", "")
            summary = f"Created {ref_type}: {ref}"
            classification = "NORMAL"
        else:
            summary = f"{ev_type}"
            classification = "UNKNOWN"

        events.append({
            "timestamp": created_at,
            "event_type": ev_type.lower().replace("event", ""),
            "classification": classification,
            "actor": actor,
            "summary": f"[GH Archive] {summary}",
            "ioc_refs": [],
            "evidence_url": f"https://data.gharchive.org/{created_at[:10] if created_at else 'unknown'}.json.gz",
            "raw": {
                "gh_archive_type": ev_type,
                "forced": payload.get("forced") if ev_type == "PushEvent" else None,
            },
        })
    return events


def events_from_npm_registry(npm_data: dict) -> list[dict]:
    """Extract npm publish events from registry data."""
    events = []
    times = npm_data.get("time", {})
    versions_summary = npm_data.get("versions_summary", {})
    pkg_name = npm_data.get("name", "unknown")

    for version, ts in times.items():
        if version in ("created", "modified"):
            continue
        publisher = (versions_summary.get(version, {}).get("_npmUser") or {}).get("name", "unknown")
        events.append({
            "timestamp": ts,
            "event_type": "registry_publish",
            "classification": "NORMAL",
            "actor": publisher,
            "summary": f"npm publish: {pkg_name}@{version} by {publisher}",
            "ioc_refs": [],
            "evidence_url": f"https://www.npmjs.com/package/{pkg_name}/v/{version}",
            "raw": {
                "package": pkg_name,
                "version": version,
                "publisher": publisher,
                "has_postinstall": bool(
                    (versions_summary.get(version, {}).get("scripts") or {}).get("postinstall")
                ),
            },
        })
    return events


def events_from_pypi_registry(pypi_data: dict) -> list[dict]:
    """Extract PyPI publish events."""
    events = []
    pkg_name = pypi_data.get("name", "unknown")

    for version, files in pypi_data.get("releases", {}).items():
        for f in files[:1]:  # One event per version
            events.append({
                "timestamp": f.get("upload_time"),
                "event_type": "registry_publish",
                "classification": "NORMAL",
                "actor": pypi_data.get("author", "unknown"),
                "summary": f"PyPI publish: {pkg_name}=={version}",
                "ioc_refs": [],
                "evidence_url": f"https://pypi.org/project/{pkg_name}/{version}/",
                "raw": {
                    "package": pkg_name,
                    "version": version,
                    "filename": f.get("filename"),
                    "sha256": f.get("sha256_digest"),
                },
            })
    return events


# ---------------------------------------------------------------------------
# Timeline Assembly
# ---------------------------------------------------------------------------

def deduplicate_events(events: list[dict]) -> list[dict]:
    """Remove near-duplicate events (same timestamp, type, actor, summary)."""
    seen = set()
    deduped = []
    for ev in events:
        key = (
            (ev.get("timestamp") or "")[:16],
            ev.get("event_type", ""),
            ev.get("actor", ""),
            (ev.get("summary") or "")[:50],
        )
        if key not in seen:
            seen.add(key)
            deduped.append(ev)
    return deduped


def sort_events(events: list[dict]) -> list[dict]:
    """Sort events chronologically, placing None timestamps at the end."""
    def sort_key(ev):
        ts = parse_iso(ev.get("timestamp"))
        return ts or datetime.max.replace(tzinfo=timezone.utc)
    return sorted(events, key=sort_key)


def find_pivot_point(events: list[dict]) -> str | None:
    """Find the earliest SUSPICIOUS or MALICIOUS event timestamp."""
    for ev in events:
        if ev.get("classification") in ("SUSPICIOUS", "MALICIOUS"):
            return ev.get("timestamp")
    return None


def flag_rapid_successions(events: list[dict], threshold_hours: int = 48) -> list[dict]:
    """
    Flag release events that have no preceding merged PR within threshold_hours.
    This helps detect releases bypassing review.
    """
    from datetime import timedelta

    release_events = [e for e in events if e["event_type"] == "release"]
    pr_merge_events = [e for e in events if e["event_type"] == "pr_merged"]

    for release in release_events:
        rel_ts = parse_iso(release.get("timestamp"))
        if not rel_ts:
            continue
        # Look for PR merged within threshold_hours before this release
        window_start = rel_ts - timedelta(hours=threshold_hours)
        preceding_prs = [
            pr for pr in pr_merge_events
            if (parse_iso(pr.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc))
            >= window_start
            and (parse_iso(pr.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc))
            <= rel_ts
        ]
        if not preceding_prs:
            release["classification"] = "SUSPICIOUS"
            release["summary"] += " [No PR merged in preceding 48h]"
            if "ioc_refs" not in release:
                release["ioc_refs"] = []
            release["ioc_refs"].append("no-associated-pr")

    return events


def build_attack_duration(events: list[dict], pivot: str | None) -> int | None:
    """Calculate attack duration in hours from pivot to last MALICIOUS/SUSPICIOUS event."""
    if not pivot:
        return None
    pivot_dt = parse_iso(pivot)
    if not pivot_dt:
        return None

    last_bad = None
    for ev in events:
        if ev.get("classification") in ("SUSPICIOUS", "MALICIOUS"):
            ev_dt = parse_iso(ev.get("timestamp"))
            if ev_dt and ev_dt >= pivot_dt:
                last_bad = ev_dt

    if not last_bad:
        return 0
    return int((last_bad - pivot_dt).total_seconds() / 3600)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="GRIMSEC OSS Forensics — Timeline generator"
    )
    parser.add_argument("--evidence-dir", default="forensics/evidence")
    parser.add_argument("--ioc-candidates", default="forensics/ioc-candidates.json")
    parser.add_argument("--output-dir", default="forensics")
    parser.add_argument("--repo", help="owner/repo (auto-detected from manifest if omitted)")
    args = parser.parse_args()

    evidence_dir = Path(args.evidence_dir)
    out_dir = Path(args.output_dir)

    # Load manifest for repo info
    manifest_path = evidence_dir / "collection-manifest.json"
    repo = args.repo
    if not repo and manifest_path.exists():
        manifest = load_json(manifest_path)
        repo = manifest.get("repo", "unknown/unknown")
    elif not repo:
        repo = "unknown/unknown"

    owner, repo_name = repo.split("/", 1) if "/" in repo else ("unknown", repo)
    log(f"Generating timeline for {owner}/{repo_name}")

    # Build IOC SHA map: sha -> [ioc_ids]
    ioc_sha_map: dict[str, list[str]] = defaultdict(list)
    ioc_candidates_path = Path(args.ioc_candidates)
    if ioc_candidates_path.exists():
        ioc_data = load_json(ioc_candidates_path)
        for idx, ioc in enumerate(ioc_data.get("ioc_candidates", [])):
            sha = ioc.get("commit_sha", "")
            if sha:
                ioc_sha_map[sha].append(f"IOC-GIT-{idx+1:03d}")

    # Load evidence files
    all_events = []

    # GitHub API data
    gh_api_path = evidence_dir / f"github-api-{owner}-{repo_name}.json"
    if gh_api_path.exists():
        log(f"Loading GitHub API data: {gh_api_path}")
        github_data = load_json(gh_api_path)
        all_events.extend(events_from_git_api(github_data, dict(ioc_sha_map)))
        all_events.extend(events_from_releases(github_data))
        all_events.extend(events_from_pull_requests(github_data))
        all_events.extend(events_from_collaborators(github_data))
    else:
        log(f"  Warning: {gh_api_path} not found")

    # GH Archive events
    gh_archive_path = evidence_dir / "gh-archive-events.json"
    if gh_archive_path.exists():
        log(f"Loading GH Archive events: {gh_archive_path}")
        archive_events = load_json(gh_archive_path)
        if isinstance(archive_events, list):
            all_events.extend(events_from_gh_archive(archive_events))

    # npm registry
    for npm_path in evidence_dir.glob("registry-npm-*.json"):
        log(f"Loading npm registry: {npm_path}")
        npm_data = load_json(npm_path)
        if not isinstance(npm_data, dict):
            continue
        all_events.extend(events_from_npm_registry(npm_data))

    # PyPI registry
    for pypi_path in evidence_dir.glob("registry-pypi-*.json"):
        log(f"Loading PyPI registry: {pypi_path}")
        pypi_data = load_json(pypi_path)
        if not isinstance(pypi_data, dict):
            continue
        all_events.extend(events_from_pypi_registry(pypi_data))

    log(f"Total raw events collected: {len(all_events)}")

    # Deduplicate and sort
    all_events = deduplicate_events(all_events)
    all_events = sort_events(all_events)
    log(f"After deduplication: {len(all_events)} events")

    # Post-processing: flag releases without PRs
    all_events = flag_rapid_successions(all_events)

    # Find pivot point
    pivot = find_pivot_point(all_events)
    if pivot:
        log(f"Pivot point (earliest suspicious event): {pivot}")
    else:
        log("No suspicious/malicious events detected in timeline")

    # Attack duration
    duration = build_attack_duration(all_events, pivot)

    # Statistics
    classification_counts = defaultdict(int)
    event_type_counts = defaultdict(int)
    for ev in all_events:
        classification_counts[ev.get("classification", "UNKNOWN")] += 1
        event_type_counts[ev.get("event_type", "unknown")] += 1

    timeline = {
        "repo": f"{owner}/{repo_name}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_events": len(all_events),
        "pivot_point": pivot,
        "attack_duration_hours": duration,
        "classification_summary": dict(classification_counts),
        "event_type_summary": dict(event_type_counts),
        "timeline": all_events,
    }

    save_json(timeline, out_dir / "timeline.json")
    log("Timeline generation complete.")

    print(json.dumps({
        "total_events": len(all_events),
        "pivot_point": pivot,
        "attack_duration_hours": duration,
        "classification_summary": dict(classification_counts),
        "output": str(out_dir / "timeline.json"),
    }, indent=2))


if __name__ == "__main__":
    main()
