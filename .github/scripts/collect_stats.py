"""
collect_stats.py — ShieldDNS project statistics collector.
Creates project_stats.json and contributors.json in admin/www/admin/assets/ at build time.
"""

import argparse
import datetime
import json
import os
import re
import sys

# ── Configuration ────────────────────────────────────────────────────────────

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EXTENSIONS = {'.go', '.js', '.html', '.css', '.ps1', '.sh', '.yml', '.yaml', '.md', '.json'}

EXCLUDE_DIRS = {
    'node_modules', '.git', 'site', '.pytest_cache', '.gemini', '.idea',
    '.vscode', 'venv', 'env', 'dist', 'build', '.mypy_cache', '__pycache__',
    'static', '.ruff_cache', 'test-results', 'test_ssl', 'ssl', 'data'
}

OUTPUT_JSON = os.path.join(PROJECT_ROOT, 'admin', 'www', 'admin', 'assets', 'project_stats.json')

# ── Core Collection Logic ────────────────────────────────────────────────────

def is_irrelevant_file(filename: str) -> bool:
    """Check if the file is a temporary file, placeholder, dummy, mock, or backup."""
    f_lower = filename.lower()
    return any(x in f_lower for x in ('temp', 'tmp', 'placeholder', 'dummy', 'mock', 'backup')) or f_lower.endswith('.tmp') or f_lower.startswith('~') or f_lower.startswith('._')


def count_clean_lines(fp) -> int:
    """Count lines of code excluding empty/blank lines."""
    lines_count = 0
    for line in fp:
        if line.strip():
            lines_count += 1
    return lines_count


def get_stats() -> dict:
    """Collect codebase stats for Backend, Frontend, and Other."""
    bf, bl = 0, 0
    ff, fl = 0, 0
    of, ol = 0, 0

    # 1. Walk the whole repository
    for root, dirs, files in os.walk(PROJECT_ROOT):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        
        # Determine logical layer of the current path
        rel_path = os.path.relpath(root, PROJECT_ROOT)
        
        is_frontend = rel_path.startswith('admin' + os.sep + 'www') or rel_path == 'admin' + os.sep + 'www'
        is_backend = (rel_path.startswith('admin') or rel_path == 'admin') and not is_frontend

        for f in files:
            if is_irrelevant_file(f):
                continue
            ext = os.path.splitext(f)[1]
            if ext not in EXTENSIONS and f not in ('Dockerfile', 'run.sh'):
                continue

            fpath = os.path.join(root, f)
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as fp:
                    lines = count_clean_lines(fp)
            except OSError:
                continue

            if is_backend and ext == '.go':
                bf += 1
                bl += lines
            elif is_frontend and ext in ('.html', '.css', '.js', '.json', '.svg'):
                ff += 1
                fl += lines
            else:
                of += 1
                ol += lines

    return {
        'backend':  {'files': bf, 'lines': bl},
        'frontend': {'files': ff, 'lines': fl},
        'other':    {'files': of, 'lines': ol},
        'total':    {'files': bf + ff + of, 'lines': bl + fl + ol},
    }


def get_test_stats() -> dict:
    """Return test stats for Go backend and JS frontend tests."""
    btf, btc = 0, 0
    ftf, ftc = 0, 0

    # Backend Go tests (*_test.go)
    admin_dir = os.path.join(PROJECT_ROOT, 'admin')
    if os.path.isdir(admin_dir):
        for f in os.listdir(admin_dir):
            if f.endswith('_test.go'):
                btf += 1
                try:
                    content = open(os.path.join(admin_dir, f), encoding='utf-8', errors='ignore').read()
                    btc += len(re.findall(r'^\s*func\s+Test[A-Z0-9_]', content, re.MULTILINE))
                except OSError:
                    pass

    # Frontend tests (*.spec.js or *_test.js)
    frontend_dir = os.path.join(PROJECT_ROOT, 'admin', 'www', 'admin')
    if os.path.isdir(frontend_dir):
        for root, dirs, files in os.walk(frontend_dir):
            for f in files:
                if f.endswith('.spec.js') or f.endswith('_test.js') or f.endswith('layout_test.js') or f.endswith('mobile_test.js'):
                    ftf += 1
                    try:
                        content = open(os.path.join(root, f), encoding='utf-8', errors='ignore').read()
                        ftc += len(re.findall(r'^\s*(?:test|it|describe)\(', content, re.MULTILINE))
                    except OSError:
                        pass

    return {
        'backend':  {'files': btf, 'tests': btc},
        'frontend': {'files': ftf, 'tests': ftc},
        'total':    {'files': btf + ftf, 'tests': btc + ftc},
    }


def get_github_repo_slug() -> str:
    try:
        import subprocess
        remote_url = subprocess.check_output(
            ["git", "config", "--get", "remote.origin.url"],
            cwd=PROJECT_ROOT,
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()
        match = re.search(r'github\.com[:/]([^/]+)/([^/.]+)', remote_url)
        if match:
            return f"{match.group(1)}/{match.group(2)}"
    except Exception:
        pass
    return "FaserF/ShieldDNS"


def resolve_github_user_dynamic(name: str, email: str, sha: str, repo_slug: str) -> tuple[str, str, bool]:
    name_lower = name.lower()
    email_lower = email.lower()
    
    noreply_match = re.match(r'^(?:\d+\+)?([^@]+)@users\.noreply\.github\.com$', email_lower)
    if noreply_match:
        username = noreply_match.group(1)
        is_bot = "[bot]" in username or "bot" in name_lower
        clean_username = username.replace("[bot]", "")
        if is_bot:
            return username, f"https://github.com/apps/{clean_username}", True
        else:
            return username, f"https://github.com/{username}", False
            
    bot_match = re.match(r'^([^\[]+)\[bot\]$', name)
    if bot_match or "bot" in name_lower or "bot" in email_lower:
        clean_name = bot_match.group(1).strip() if bot_match else name.replace("[bot]", "").strip()
        app_slug = clean_name.lower().replace(" ", "-")
        return f"{clean_name}[bot]", f"https://github.com/apps/{app_slug}", True

    try:
        import urllib.request
        url = f"https://api.github.com/repos/{repo_slug}/commits/{sha}"
        req = urllib.request.Request(url, headers={"User-Agent": "ShieldDNS-Release-Workflow"})
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            req.add_header("Authorization", f"token {token}")
        with urllib.request.urlopen(req, timeout=3) as response:
            res_data = json.loads(response.read().decode())
            author_info = res_data.get("author")
            if author_info and author_info.get("login"):
                username = author_info["login"]
                is_bot = author_info.get("type") == "Bot" or "bot" in username.lower()
                profile_url = f"https://github.com/apps/{username}" if is_bot else f"https://github.com/{username}"
                return username, profile_url, is_bot
    except Exception:
        pass

    username = name.replace(" ", "")
    profile_url = f"https://github.com/{username}"
    return username, profile_url, False


def collect_contributors() -> list[dict]:
    assets_dir = os.path.dirname(OUTPUT_JSON)
    contributors_path = os.path.join(assets_dir, 'contributors.json')
    fallback_path = os.path.join(assets_dir, 'contributors_fallback.json')

    CONSOLIDATE_MAP = {
        "faserf": "FaserF",
        "fabianseitz": "FaserF",
        "seitzserveradmin": "FaserF",
        "github actions bot[bot]": "github-actions[bot]",
        "github-actions[bot]": "github-actions[bot]",
    }
    DISPLAY_NAME_MAP = {
        "FaserF": "Fabian Seitz",
        "github-actions[bot]": "github-actions[bot]",
    }

    try:
        import subprocess
        is_shallow = subprocess.check_output(
            ["git", "rev-parse", "--is-shallow-repository"],
            cwd=PROJECT_ROOT,
            stderr=subprocess.DEVNULL,
            text=True
        ).strip() == "true"

        git_log = subprocess.check_output(
            ["git", "log", "--format=%an|%ae|%aI|%H"],
            cwd=PROJECT_ROOT,
            stderr=subprocess.DEVNULL,
            text=True
        )
    except Exception:
        if os.path.exists(fallback_path):
            try:
                with open(fallback_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return None

    fallback_total_commits = 0
    fallback_data = None
    if os.path.exists(fallback_path):
        try:
            with open(fallback_path, 'r', encoding='utf-8') as f:
                fallback_data = json.load(f)
                fallback_total_commits = sum(c.get("commit_count", 0) for c in fallback_data)
        except Exception:
            pass

    parsed_total_commits = len(git_log.strip().split('\n')) if git_log else 0
    if is_shallow or (fallback_total_commits > 0 and parsed_total_commits < (fallback_total_commits * 0.9)):
        if fallback_data is not None:
            consolidated = {}
            for item in fallback_data:
                uname = item.get("username", "")
                uname_lower = uname.lower()
                if uname_lower in CONSOLIDATE_MAP:
                    uname = CONSOLIDATE_MAP[uname_lower]
                
                if uname in consolidated:
                    existing = consolidated[uname]
                    existing["commit_count"] += item.get("commit_count", 0)
                    if item.get("last_commit_date", "") > existing.get("last_commit_date", ""):
                        existing["last_commit_date"] = item.get("last_commit_date", "")
                else:
                    item_copy = dict(item)
                    item_copy["username"] = uname
                    if uname_lower in CONSOLIDATE_MAP:
                        item_copy["profile_url"] = f"https://github.com/{uname}"
                        item_copy["name"] = DISPLAY_NAME_MAP.get(uname, item.get("name"))
                    consolidated[uname] = item_copy
            return sorted(consolidated.values(), key=lambda x: x.get("commit_count", 0), reverse=True)

    email_to_user_cache = {}
    if fallback_data is not None:
        for item in fallback_data:
            if "email" in item and "username" in item:
                email_to_user_cache[item["email"].lower()] = (
                    item["username"],
                    item["profile_url"],
                    item.get("is_bot", False)
                )

    repo_slug = get_github_repo_slug()
    email_groups = {}
    
    for line in git_log.strip().split('\n'):
        if not line:
            continue
        parts = line.split('|', 3)
        if len(parts) < 4:
            continue
        name, email, date_str, sha = parts
        name = name.strip()
        email = email.strip().lower()
        date_formatted = date_str.split('T')[0]
        
        if email not in email_groups:
            email_groups[email] = {
                "name": name,
                "email": email,
                "commit_count": 0,
                "last_commit_date": date_formatted,
                "sha": sha
            }
        else:
            if date_formatted > email_groups[email]["last_commit_date"]:
                email_groups[email]["last_commit_date"] = date_formatted
                email_groups[email]["name"] = name
                email_groups[email]["sha"] = sha
        
        email_groups[email]["commit_count"] += 1

    username_groups = {}
    for email, info in email_groups.items():
        if email in email_to_user_cache:
            username, profile_url, is_bot = email_to_user_cache[email]
        else:
            username, profile_url, is_bot = resolve_github_user_dynamic(
                info["name"], email, info["sha"], repo_slug
            )
            email_to_user_cache[email] = (username, profile_url, is_bot)
            
        username_lower = username.lower()
        if username_lower in CONSOLIDATE_MAP:
            username = CONSOLIDATE_MAP[username_lower]
            profile_url = f"https://github.com/{username}"
            
        display_name = DISPLAY_NAME_MAP.get(username, info["name"])
        
        if username not in username_groups:
            username_groups[username] = {
                "username": username,
                "name": display_name,
                "email": email,
                "commit_count": info["commit_count"],
                "last_commit_date": info["last_commit_date"],
                "profile_url": profile_url,
                "is_bot": is_bot
            }
        else:
            existing = username_groups[username]
            existing["commit_count"] += info["commit_count"]
            if info["last_commit_date"] > existing["last_commit_date"]:
                existing["last_commit_date"] = info["last_commit_date"]
                existing["name"] = display_name
                existing["email"] = email

    sorted_contributors = sorted(
        username_groups.values(),
        key=lambda x: x["commit_count"],
        reverse=True
    )
    return sorted_contributors


def check_contributors_changed(old_list: list[dict], new_list: list[dict]) -> bool:
    if len(old_list) != len(new_list):
        return True
    
    old_map = {item["username"]: item for item in old_list}
    new_map = {item["username"]: item for item in new_list}
    
    if set(old_map.keys()) != set(new_map.keys()):
        return True
        
    for username, new_item in new_map.items():
        old_item = old_map[username]
        for key in ["name", "email", "profile_url", "is_bot"]:
            if old_item.get(key) != new_item.get(key):
                return True
                
    commit_diffs = {}
    for username, new_item in new_map.items():
        old_item = old_map[username]
        old_count = old_item.get("commit_count", 0)
        new_count = new_item.get("commit_count", 0)
        if old_count != new_count:
            commit_diffs[username] = abs(new_count - old_count)
            
    if len(commit_diffs) == 1:
        diff = list(commit_diffs.values())[0]
        return diff >= 50
    elif len(commit_diffs) > 1:
        return True
        
    return False


def collect() -> dict:
    code_stats = get_stats()
    test_stats = get_test_stats()

    # Read current version from VERSION file or fall back to admin/main.go
    version = 'unknown'
    version_path = os.path.join(PROJECT_ROOT, 'VERSION')
    if os.path.exists(version_path):
        try:
            version = open(version_path, encoding='utf-8').read().strip()
        except OSError:
            pass
    else:
        # Fall back to main.go parsing
        try:
            with open(os.path.join(PROJECT_ROOT, 'admin', 'main.go'), 'r', encoding='utf-8') as f:
                content = f.read()
                match = re.search(r'Version\s*=\s*"v?([^"]+)"', content)
                if match:
                    version = match.group(1)
        except Exception:
            pass

    # Read current Git commit hash
    commit_id = 'unknown'
    try:
        import subprocess
        git_hash = subprocess.check_output(
            ['git', 'rev-parse', '--short', 'HEAD'],
            cwd=PROJECT_ROOT,
            stderr=subprocess.DEVNULL
        )
        commit_id = git_hash.decode('utf-8').strip()
    except Exception:
        env_commit = os.environ.get('GIT_COMMIT')
        if env_commit:
            commit_id = env_commit[:7]

    timestamp = datetime.datetime.now(tz=datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    return {
        'version': version,
        'commit_id': commit_id,
        'generated_at': timestamp,
        'code': code_stats,
        'tests': test_stats,
    }


def write_json(stats: dict, path: str = OUTPUT_JSON) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    # Save Stats
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)
    print(f'[collect_stats] Stats JSON written to {path}', file=sys.stderr)
    
    # Save Contributors
    assets_dir = os.path.dirname(path)
    contributors_path = os.path.join(assets_dir, 'contributors.json')
    fallback_path = os.path.join(assets_dir, 'contributors_fallback.json')
    
    contribs = collect_contributors()
    if contribs is not None:
        with open(contributors_path, 'w', encoding='utf-8') as f:
            json.dump(contribs, f, indent=2)
        print(f'[collect_stats] Contributors JSON written to {contributors_path}', file=sys.stderr)
        
        # Save fallback cache if inside git repo
        try:
            import subprocess
            subprocess.check_output(["git", "rev-parse", "--is-inside-work-tree"], stderr=subprocess.DEVNULL)
            
            should_write_fallback = True
            if os.path.exists(fallback_path):
                try:
                    with open(fallback_path, 'r', encoding='utf-8') as f:
                        old_fallback = json.load(f)
                    should_write_fallback = check_contributors_changed(old_fallback, contribs)
                except Exception:
                    pass
                    
            if should_write_fallback:
                with open(fallback_path, 'w', encoding='utf-8') as f:
                    json.dump(contribs, f, indent=2)
                print(f'[collect_stats] Contributors fallback JSON updated at {fallback_path}', file=sys.stderr)
        except Exception:
            pass
    else:
        if not os.path.exists(contributors_path):
            fallback_contribs = [{
                "username": "FaserF",
                "name": "Fabian Seitz",
                "email": "fabian.seitz@pari.com",
                "commit_count": 0,
                "last_commit_date": datetime.datetime.now().strftime('%Y-%m-%d'),
                "profile_url": "https://github.com/FaserF",
                "is_bot": False
            }]
            with open(contributors_path, 'w', encoding='utf-8') as f:
                json.dump(fallback_contribs, f, indent=2)
            print(f'[collect_stats] Fallback Contributors JSON written to {contributors_path}', file=sys.stderr)


if __name__ == '__main__':
    stats = collect()
    write_json(stats)
