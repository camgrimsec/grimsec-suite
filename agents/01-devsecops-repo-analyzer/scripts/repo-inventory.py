#!/usr/bin/env python3
"""
repo-inventory.py — Stage 1 of the DevSecOps Repo Analyzer pipeline.
Produces a comprehensive inventory of a cloned repository.

Usage:
    python3 repo-inventory.py <repo-path> --output <output-path>
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Language detection by file extension
LANG_MAP = {
    ".py": "Python", ".pyx": "Python", ".pyi": "Python",
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript",
    ".go": "Go",
    ".rb": "Ruby", ".erb": "Ruby",
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin",
    ".rs": "Rust",
    ".c": "C", ".h": "C",
    ".cpp": "C++", ".cxx": "C++", ".cc": "C++", ".hpp": "C++",
    ".cs": "C#",
    ".php": "PHP",
    ".swift": "Swift",
    ".scala": "Scala",
    ".ex": "Elixir", ".exs": "Elixir",
    ".erl": "Erlang", ".hrl": "Erlang",
    ".lua": "Lua",
    ".r": "R", ".R": "R",
    ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
    ".sql": "SQL",
    ".html": "HTML", ".htm": "HTML",
    ".css": "CSS", ".scss": "SCSS", ".sass": "SASS", ".less": "LESS",
    ".vue": "Vue",
    ".svelte": "Svelte",
}

# Package manager detection
PACKAGE_MANAGERS = {
    "package.json": {"manager": "npm/yarn/pnpm", "language": "JavaScript/TypeScript"},
    "package-lock.json": {"manager": "npm", "language": "JavaScript/TypeScript"},
    "yarn.lock": {"manager": "yarn", "language": "JavaScript/TypeScript"},
    "pnpm-lock.yaml": {"manager": "pnpm", "language": "JavaScript/TypeScript"},
    "requirements.txt": {"manager": "pip", "language": "Python"},
    "Pipfile": {"manager": "pipenv", "language": "Python"},
    "Pipfile.lock": {"manager": "pipenv", "language": "Python"},
    "pyproject.toml": {"manager": "poetry/pip", "language": "Python"},
    "poetry.lock": {"manager": "poetry", "language": "Python"},
    "setup.py": {"manager": "setuptools", "language": "Python"},
    "setup.cfg": {"manager": "setuptools", "language": "Python"},
    "Gemfile": {"manager": "bundler", "language": "Ruby"},
    "Gemfile.lock": {"manager": "bundler", "language": "Ruby"},
    "go.mod": {"manager": "go modules", "language": "Go"},
    "go.sum": {"manager": "go modules", "language": "Go"},
    "Cargo.toml": {"manager": "cargo", "language": "Rust"},
    "Cargo.lock": {"manager": "cargo", "language": "Rust"},
    "pom.xml": {"manager": "maven", "language": "Java"},
    "build.gradle": {"manager": "gradle", "language": "Java/Kotlin"},
    "build.gradle.kts": {"manager": "gradle", "language": "Kotlin"},
    "composer.json": {"manager": "composer", "language": "PHP"},
    "mix.exs": {"manager": "hex", "language": "Elixir"},
    "Makefile": {"manager": "make", "language": "Multiple"},
}

# Infrastructure file detection
INFRA_PATTERNS = {
    "Dockerfile": "Docker",
    "docker-compose.yml": "Docker Compose",
    "docker-compose.yaml": "Docker Compose",
    ".dockerignore": "Docker",
    "*.tf": "Terraform",
    "*.tfvars": "Terraform",
    "terraform.tfstate": "Terraform",
    "*.yaml": None,  # Need to check content for K8s
    "*.yml": None,
    "helmfile.yaml": "Helm",
    "Chart.yaml": "Helm",
    ".github/workflows/*.yml": "GitHub Actions",
    ".github/workflows/*.yaml": "GitHub Actions",
    ".gitlab-ci.yml": "GitLab CI",
    "Jenkinsfile": "Jenkins",
    ".circleci/config.yml": "CircleCI",
    ".travis.yml": "Travis CI",
    "cloudbuild.yaml": "Google Cloud Build",
    "serverless.yml": "Serverless Framework",
    "serverless.yaml": "Serverless Framework",
    "vercel.json": "Vercel",
    "netlify.toml": "Netlify",
    "fly.toml": "Fly.io",
    "render.yaml": "Render",
    "railway.json": "Railway",
    "Procfile": "Heroku",
    "app.yaml": "Google App Engine",
    "pulumi.yaml": "Pulumi",
    "cdk.json": "AWS CDK",
    "sam.yaml": "AWS SAM",
    "template.yaml": "AWS SAM/CloudFormation",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".next", ".nuxt", "dist",
    "build", "target", "vendor", ".venv", "venv", "env", ".env",
    ".tox", ".mypy_cache", ".pytest_cache", "coverage", ".turbo",
    ".cache", "tmp", ".tmp", "out", ".out",
}


def count_lines(filepath: str) -> int:
    """Count non-empty lines in a file."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for line in f if line.strip())
    except (OSError, UnicodeDecodeError):
        return 0


def extract_readme(repo_path: str) -> str:
    """Extract first 500 chars of README."""
    for name in ["README.md", "readme.md", "README.rst", "README.txt", "README"]:
        readme_path = os.path.join(repo_path, name)
        if os.path.isfile(readme_path):
            try:
                with open(readme_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(2000)
                    # Strip markdown headers and links for a cleaner summary
                    content = re.sub(r"#+\s*", "", content)
                    content = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", content)
                    content = re.sub(r"!\[([^\]]*)\]\([^)]+\)", "", content)
                    content = content.strip()
                    return content[:500] + ("..." if len(content) > 500 else "")
            except (OSError, UnicodeDecodeError):
                pass
    return ""


def detect_frameworks(repo_path: str, languages: dict) -> list:
    """Detect frameworks based on dependency files and imports."""
    frameworks = []

    # Check package.json for JS/TS frameworks
    pkg_json_path = os.path.join(repo_path, "package.json")
    if os.path.isfile(pkg_json_path):
        try:
            with open(pkg_json_path, "r") as f:
                pkg = json.load(f)
            all_deps = {}
            all_deps.update(pkg.get("dependencies", {}))
            all_deps.update(pkg.get("devDependencies", {}))
            framework_map = {
                "next": "Next.js", "react": "React", "vue": "Vue.js",
                "@angular/core": "Angular", "express": "Express.js",
                "fastify": "Fastify", "koa": "Koa", "hono": "Hono",
                "svelte": "Svelte", "nuxt": "Nuxt.js", "remix": "Remix",
                "electron": "Electron", "nestjs": "NestJS", "@nestjs/core": "NestJS",
                "prisma": "Prisma", "@prisma/client": "Prisma",
                "drizzle-orm": "Drizzle", "typeorm": "TypeORM",
                "tailwindcss": "Tailwind CSS", "styled-components": "Styled Components",
            }
            for dep, name in framework_map.items():
                if dep in all_deps:
                    frameworks.append(name)
        except (json.JSONDecodeError, OSError):
            pass

    # Check pyproject.toml / requirements.txt for Python frameworks
    for dep_file in ["pyproject.toml", "requirements.txt", "setup.py"]:
        dep_path = os.path.join(repo_path, dep_file)
        if os.path.isfile(dep_path):
            try:
                with open(dep_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().lower()
                py_frameworks = {
                    "django": "Django", "flask": "Flask", "fastapi": "FastAPI",
                    "starlette": "Starlette", "tornado": "Tornado",
                    "celery": "Celery", "sqlalchemy": "SQLAlchemy",
                    "pydantic": "Pydantic", "pytest": "pytest",
                    "streamlit": "Streamlit", "gradio": "Gradio",
                }
                for dep, name in py_frameworks.items():
                    if dep in content and name not in frameworks:
                        frameworks.append(name)
            except (OSError, UnicodeDecodeError):
                pass

    # Check go.mod for Go frameworks
    go_mod_path = os.path.join(repo_path, "go.mod")
    if os.path.isfile(go_mod_path):
        try:
            with open(go_mod_path, "r") as f:
                content = f.read()
            go_frameworks = {
                "gin-gonic/gin": "Gin", "labstack/echo": "Echo",
                "gofiber/fiber": "Fiber", "gorilla/mux": "Gorilla Mux",
                "go-chi/chi": "Chi",
            }
            for dep, name in go_frameworks.items():
                if dep in content:
                    frameworks.append(name)
        except (OSError, UnicodeDecodeError):
            pass

    # Check Gemfile for Ruby frameworks
    gemfile_path = os.path.join(repo_path, "Gemfile")
    if os.path.isfile(gemfile_path):
        try:
            with open(gemfile_path, "r") as f:
                content = f.read().lower()
            if "rails" in content:
                frameworks.append("Ruby on Rails")
            if "sinatra" in content:
                frameworks.append("Sinatra")
        except (OSError, UnicodeDecodeError):
            pass

    return list(set(frameworks))


def inventory_repo(repo_path: str) -> dict:
    """Build a complete inventory of the repository."""
    repo_path = os.path.abspath(repo_path)
    if not os.path.isdir(repo_path):
        print(f"Error: {repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    # Walk the repo
    lang_files = defaultdict(list)
    lang_loc = Counter()
    total_files = 0
    total_loc = 0
    dir_sizes = Counter()
    dep_files_found = []
    infra_files_found = []

    for root, dirs, files in os.walk(repo_path):
        # Skip ignored directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        rel_root = os.path.relpath(root, repo_path)

        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, repo_path)
            total_files += 1

            ext = os.path.splitext(filename)[1].lower()
            lang = LANG_MAP.get(ext)

            if lang:
                loc = count_lines(filepath)
                lang_files[lang].append(rel_path)
                lang_loc[lang] += loc
                total_loc += loc

                # Track directory sizes (top-level)
                top_dir = rel_path.split(os.sep)[0] if os.sep in rel_path else "."
                dir_sizes[top_dir] += loc

            # Check for dependency files
            if filename in PACKAGE_MANAGERS:
                dep_files_found.append({
                    "file": rel_path,
                    **PACKAGE_MANAGERS[filename]
                })

            # Check for infrastructure files
            if filename in INFRA_PATTERNS and INFRA_PATTERNS[filename]:
                infra_files_found.append({
                    "file": rel_path,
                    "type": INFRA_PATTERNS[filename]
                })
            elif filename.endswith((".yml", ".yaml")):
                # Check for GitHub Actions
                if ".github/workflows" in rel_path:
                    infra_files_found.append({
                        "file": rel_path,
                        "type": "GitHub Actions"
                    })
                # Check for K8s manifests
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        first_lines = f.read(500)
                    if "apiVersion:" in first_lines and "kind:" in first_lines:
                        infra_files_found.append({
                            "file": rel_path,
                            "type": "Kubernetes"
                        })
                except (OSError, UnicodeDecodeError):
                    pass
            elif filename.endswith(".tf"):
                infra_files_found.append({
                    "file": rel_path,
                    "type": "Terraform"
                })

    # Build language summary
    languages = {}
    for lang, count in lang_loc.most_common():
        languages[lang] = {
            "files": len(lang_files[lang]),
            "lines_of_code": count,
            "percentage": round(count / total_loc * 100, 1) if total_loc > 0 else 0
        }

    # Detect frameworks
    frameworks = detect_frameworks(repo_path, languages)

    # Get README
    readme_summary = extract_readme(repo_path)

    # Get git info
    git_info = {}
    try:
        git_info["last_commit"] = subprocess.check_output(
            ["git", "-C", repo_path, "log", "-1", "--format=%H|%s|%ai"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        parts = git_info["last_commit"].split("|", 2)
        if len(parts) == 3:
            git_info = {
                "last_commit_hash": parts[0][:12],
                "last_commit_message": parts[1],
                "last_commit_date": parts[2],
            }
        git_info["default_branch"] = subprocess.check_output(
            ["git", "-C", repo_path, "rev-parse", "--abbrev-ref", "HEAD"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Top directories by LOC
    top_dirs = [
        {"directory": d, "lines_of_code": c}
        for d, c in dir_sizes.most_common(10)
    ]

    # Deduplicate infra files by type
    infra_types = list(set(f["type"] for f in infra_files_found))

    inventory = {
        "repo_path": repo_path,
        "git": git_info,
        "readme_summary": readme_summary,
        "metrics": {
            "total_files": total_files,
            "total_lines_of_code": total_loc,
            "language_count": len(languages),
        },
        "languages": languages,
        "frameworks": frameworks,
        "package_managers": dep_files_found,
        "infrastructure": {
            "types_detected": infra_types,
            "files": infra_files_found,
        },
        "top_directories_by_loc": top_dirs,
    }

    return inventory


def main():
    parser = argparse.ArgumentParser(description="Inventory a cloned repository")
    parser.add_argument("repo_path", help="Path to the cloned repository")
    parser.add_argument("--output", "-o", required=True, help="Output JSON file path")
    args = parser.parse_args()

    print(f"Inventorying repository: {args.repo_path}")
    inventory = inventory_repo(args.repo_path)

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(inventory, f, indent=2)

    # Print summary
    print(f"\n=== Repository Inventory Summary ===")
    print(f"Total files: {inventory['metrics']['total_files']}")
    print(f"Total LOC:   {inventory['metrics']['total_lines_of_code']:,}")
    print(f"Languages:   {', '.join(inventory['languages'].keys())}")
    print(f"Frameworks:  {', '.join(inventory['frameworks']) if inventory['frameworks'] else 'None detected'}")
    print(f"Pkg Managers: {', '.join(set(d['manager'] for d in inventory['package_managers']))}")
    print(f"Infra:       {', '.join(inventory['infrastructure']['types_detected']) if inventory['infrastructure']['types_detected'] else 'None detected'}")
    print(f"\nInventory saved to: {args.output}")


if __name__ == "__main__":
    main()
