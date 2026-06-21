#!/usr/bin/env python3
"""
Generates a structured, deduplicated changelog from git commit history.

- Reads commits between FROM_TAG and HEAD (or all commits if no tag)
- Filters noise: lazy commits, merge commits, version bumps, bot commits
- Groups by conventional commit type with friendly emoji headers
- Deduplicates: exact + near-duplicate collapsing
- Scope-aware grouping: scope overrides type bucket
- Breaking changes bubble to the top in a CAUTION callout
- Collapses large categories with expandable <details> block
- Outputs clean GitHub-flavored Markdown

Usage:
    python generate_changelog.py [--from-tag TAG] [--total-commits N] [--repo owner/repo]
"""

import argparse
import re
import subprocess

# ---------------------------------------------------------------------------
# Noise patterns — commits matching ANY are silently dropped
# ---------------------------------------------------------------------------
NOISE_PATTERNS = [
    r"^\s*$",
    r"^(Update|Aktualisier[et]?|Add|Adds|Adde|Delete|Deletes|Remove|Removes|Rename|Renames|Move|Moves|Fix|Edit|Change|Modify)\s+[\w\-\.\/]+\.\w{1,10}\s*$",
    r"^Merge (pull request|branch|remote-tracking branch)\b",
    r"^Merge from\b",
    r"^(chore|build)(\([^)]*\))?:\s*(bump|release|version)\b",
    r"^(bump|release)(\s+version)?\s+v?\d",
    r"^v?\d+\.\d+\.\d+\s*$",
    r"^\[skip[- ]ci\]",
    r"^chore: regenerate (manifest|connections|changelog)\b",
    r"^chore: update (project_manifest|project_connections|contributors)\b",
    r"^(auto.?generated?|automated?|bot:)\b",
    r'^Revert "Revert',
    r"^Initial commit\s*$",
    r"^WIP\b",
    r"^wip\b",
    r"^.{1,3}$",
    r"\[skip[- ]ci\]\s*$",
]
_NOISE_RE = [re.compile(p, re.IGNORECASE) for p in NOISE_PATTERNS]

# ---------------------------------------------------------------------------
# Category order & display labels
# ---------------------------------------------------------------------------
CATEGORY_ORDER = [
    "breaking", "feat", "fix", "security", "perf",
    "refactor", "api", "db", "ui", "docs", "test", "ci", "chore", "other",
]
CATEGORY_EMOJI = {
    "breaking":  "💥 Breaking Changes",
    "feat":      "✨ New Features",
    "fix":       "🐛 Bug Fixes",
    "security":  "🔒 Security",
    "perf":      "⚡ Performance",
    "refactor":  "♻️ Code Improvements",
    "api":       "🔌 API Changes",
    "db":        "🗄️ Database",
    "ui":        "🎨 UI / UX",
    "docs":      "📚 Documentation",
    "test":      "🧪 Tests",
    "ci":        "🔄 CI / CD",
    "chore":     "🔧 Maintenance",
    "other":     "📦 Other Changes",
}

# Conventional commit type → bucket
TYPE_MAP = {
    "feat": "feat", "feature": "feat",
    "fix": "fix", "bugfix": "fix", "hotfix": "fix",
    "security": "security", "sec": "security",
    "perf": "perf", "optim": "perf",
    "refactor": "refactor", "refact": "refactor",
    "api": "api",
    "db": "db", "migration": "db", "migrate": "db", "schema": "db",
    "ui": "ui", "style": "ui", "ux": "ui",
    "docs": "docs", "doc": "docs",
    "test": "test", "tests": "test",
    "ci": "ci", "cd": "ci", "build": "ci",
    "chore": "chore", "maint": "chore", "infra": "chore",
    "deps": "chore", "dep": "chore", "bump": "chore",
    "revert": "fix",
}

# Scope overrides — beat the type map
SCOPE_MAP = {
    "api": "api", "endpoint": "api", "router": "api", "route": "api",
    "db": "db", "database": "db", "migration": "db", "schema": "db", "model": "db",
    "ui": "ui", "frontend": "ui", "fe": "ui", "component": "ui",
    "modal": "ui", "dashboard": "ui",
    "security": "security", "auth": "security", "authz": "security",
    "authn": "security", "jwt": "security", "rbac": "security",
    "ci": "ci", "cd": "ci", "workflow": "ci",
    "docker": "ci", "dockerfile": "ci", "actions": "ci",
}

MAX_PER_SECTION = 15
NEVER_COLLAPSE = {"breaking", "security"}

_CONV_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*)(\([^)]*\))?(!)?\:\s*(.+)$")
_NORM_STRIP_TYPE = re.compile(
    r"^(feat|fix|docs|style|refactor|perf|test|chore|ci|security|build|api|db|ui|ux|revert)(\([^)]*\))?(!)?\:\s*",
    re.IGNORECASE,
)
_NORM_PUNCT = re.compile(r"[.!?,;:\"'`]")
_NORM_ARTICLES = re.compile(r"\b(the|a|an|for|of|in|to|with|from|on|at|by)\b")
_NORM_SPACES = re.compile(r"\s+")


def norm_key(msg: str) -> str:
    n = msg.lower()
    n = _NORM_STRIP_TYPE.sub("", n)
    n = _NORM_PUNCT.sub("", n)
    n = _NORM_ARTICLES.sub("", n)
    n = _NORM_SPACES.sub(" ", n)
    return n.strip()


def is_noise(msg: str) -> bool:
    return any(p.search(msg) for p in _NOISE_RE)


def keyword_bucket(msg: str) -> str:
    m = msg.lower()
    if re.search(r"\b(general[\s_]fix|small[\s_]fix|bug[\s_]fix|fix(es|ed)?\b|fix\s+\w)", m):
        return "fix"
    if re.search(r"\b(ci\b|linter?|pipeline|workflow|github[\s_]action|changelog|dockerfile?|container)\b", m):
        return "ci"
    if re.search(r"\b(update[\s_]depend|bump[\s_]depend|renovate|dependency[\s_]update|upgrade[\s_]dep)\b", m):
        return "chore"
    if re.search(r"\b(add(ed|s)?[\s_]+(missing[\s_]+)?(feature|support|ability)|new[\s_]feature)\b", m):
        return "feat"
    if re.search(r"\b(security|vulnerability|cve|auth(en|oriz))\b", m):
        return "security"
    if re.search(r"\b(perf(ormance)?|speed|faster|optim|latency|throughput)\b", m):
        return "perf"
    if re.search(r"\b(refactor(ing)?|restructur|rewrite|clean.?up|improve)\b", m):
        return "refactor"
    if re.search(r"\b(doc(s|ument(ation)?)?|readme|wiki|guide)\b", m):
        return "docs"
    if re.search(r"\b(test(s|ing)?|spec|unit[\s_]test|e2e)\b", m):
        return "test"
    if re.search(r"\b(ui\b|ux\b|frontend|layout|theme|design|modal|component|dashboard)\b", m):
        return "ui"
    if re.search(r"\b(api\b|endpoint|route|router|swagger|openapi)\b", m):
        return "api"
    if re.search(r"\b(db\b|database|migration|schema|model|sql)\b", m):
        return "db"
    if re.search(r"\b(chore|maint(enance)?|housekeep|dependen|package|infra)\b", m):
        return "chore"
    return "other"


def format_item(display: str, hashes: list, repo: str) -> str:
    if hashes:
        if repo:
            links = [f"[{h}](https://github.com/{repo}/commit/{h})" for h in hashes]
        else:
            links = [f"`{h}`" for h in hashes]
        return f"{display} ({', '.join(links)})"
    return display


def get_commits(from_tag: str) -> list[tuple[str, str]]:
    cmd = ["git", "log", "--pretty=format:%h %s"]
    if from_tag:
        cmd.append(f"{from_tag}..HEAD")
    else:
        cmd += ["--max-count=2000"]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except subprocess.CalledProcessError:
        return []
    result = []
    for line in out.splitlines():
        m = re.match(r"^([0-9a-fA-F]+)\s+(.*)$", line)
        if m:
            result.append((m.group(1), m.group(2).strip()))
        elif line.strip():
            result.append(("", line.strip()))
    return result


def build_changelog(from_tag: str, total_commits: int, repo: str) -> str:
    commits = get_commits(from_tag)
    total_raw = total_commits if total_commits > 0 else len(commits)

    buckets: dict[str, list] = {k: [] for k in CATEGORY_ORDER}
    seen: dict[str, dict] = {}

    for hash_, msg in commits:
        if not msg or is_noise(msg):
            continue

        bucket = "other"
        display = msg
        is_break = False

        m = _CONV_RE.match(msg)
        if m:
            raw_type  = m.group(1).lower()
            raw_scope = (m.group(2) or "").strip("()").lower().strip()
            is_break  = m.group(3) == "!"
            desc      = m.group(4).strip()

            if raw_scope and raw_scope in SCOPE_MAP:
                bucket = SCOPE_MAP[raw_scope]
            elif raw_type in TYPE_MAP:
                bucket = TYPE_MAP[raw_type]

            desc_cap = desc[0].upper() + desc[1:] if desc else desc
            display = f"**{raw_scope}:** {desc_cap}" if raw_scope else desc_cap
        else:
            display = msg[0].upper() + msg[1:] if msg else msg
            bucket  = keyword_bucket(msg)

        nk = norm_key(display)

        # Breaking changes → also add to breaking bucket
        if is_break:
            break_display = f"**{display}**"
            bk = f"breaking:{nk}"
            if bk in seen:
                if hash_ and hash_ not in seen[bk]["hashes"]:
                    seen[bk]["hashes"].append(hash_)
            else:
                item = {"display": break_display, "hashes": [hash_] if hash_ else []}
                seen[bk] = item
                buckets["breaking"].append(item)

        # Dedup
        if nk in seen:
            if hash_ and hash_ not in seen[nk]["hashes"]:
                seen[nk]["hashes"].append(hash_)
            continue

        item = {"display": display, "hashes": [hash_] if hash_ else []}
        seen[nk] = item
        buckets[bucket].append(item)

    # ---------------------------------------------------------------------------
    # Build markdown output
    # ---------------------------------------------------------------------------
    out: list[str] = []
    has_any = False
    filtered_count = sum(len(v) for k, v in buckets.items() if k != "breaking")
    filtered_count += len(buckets["breaking"])

    # Breaking changes callout
    if buckets["breaking"]:
        has_any = True
        out.append("> [!CAUTION]")
        out.append("> **This release contains breaking changes. Please review before updating.**")
        out.append(">")
        for item in buckets["breaking"]:
            line = format_item(item["display"], item["hashes"], repo)
            out.append(f"> - {line}")
        out.append("")

    # Per-category sections
    for key in CATEGORY_ORDER:
        if key == "breaking":
            continue
        bucket = buckets[key]
        if not bucket:
            continue
        has_any = True
        out.append(f"### {CATEGORY_EMOJI[key]}")
        out.append("")

        collapse = len(bucket) > MAX_PER_SECTION and key not in NEVER_COLLAPSE
        if collapse:
            for item in bucket[:MAX_PER_SECTION]:
                out.append(f"- {format_item(item['display'], item['hashes'], repo)}")
            remaining = len(bucket) - MAX_PER_SECTION
            out.append("")
            out.append("<details>")
            out.append(f"<summary>Show {remaining} more changes…</summary>")
            out.append("")
            for item in bucket[MAX_PER_SECTION:]:
                out.append(f"- {format_item(item['display'], item['hashes'], repo)}")
            out.append("")
            out.append("</details>")
        else:
            for item in bucket:
                out.append(f"- {format_item(item['display'], item['hashes'], repo)}")
        out.append("")

    if not has_any:
        out.append("> *No categorised changes found in this release.*")
        out.append("> Most commits were maintenance, dependency updates, or automated changes.")
        out.append("")

    # Footer
    range_str = f"{from_tag}..HEAD" if from_tag else "all history"
    out.append("---")
    if total_raw > 0:
        out.append(f"*{filtered_count} significant changes from {total_raw} total commits since `{from_tag}`.*")
    else:
        out.append(f"*Changelog generated from `{range_str}`.*")

    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description="Generate ShieldDNS changelog from git history.")
    parser.add_argument("--from-tag", default="", help="Git ref to start log from")
    parser.add_argument("--total-commits", type=int, default=0, help="Raw commit count (passed by caller)")
    parser.add_argument("--repo", default="", help="GitHub repo (owner/name) for commit links")
    args = parser.parse_args()

    print(build_changelog(args.from_tag, args.total_commits, args.repo))


if __name__ == "__main__":
    main()
