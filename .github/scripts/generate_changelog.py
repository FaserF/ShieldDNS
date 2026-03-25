import os
import subprocess
import re
import sys

def get_changelog(from_tag=None):
    repo_url = f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', 'FaserF/ShieldDNS')}"
    
    if from_tag:
        cmd = ["git", "log", f"{from_tag}..HEAD", "--pretty=format:%H|%h|%s", "--", "."]
    else:
        cmd = ["git", "log", "--pretty=format:%H|%h|%s", "--", "."]
        
    try:
        commits = subprocess.check_output(cmd, text=True).strip().split("\n")
    except Exception as e:
        print(f"Error getting commits: {e}")
        commits = []
    
    cats = {
        "✨ Features": [],
        "🐛 Bug Fixes": [],
        "📦 Dependencies": [],
        "🔧 Maintenance & CI": [],
        "📝 Documentation": [],
        "🧪 Tests": [],
        "🚀 Other": []
    }
    
    for line in commits:
        if not line or "|" not in line: continue
        fh, sh, sub = line.split("|", 2)
        sl = sub.lower()
        
        if any(x in sl for x in ["chore: release", "chore: bump", "merge ", "[skip ci]"]):
            continue
        
        # Pull request link
        sub = re.sub(r"\(#(\d+)\)", rf"([#\1]({repo_url}/pull/\1))", sub)
        entry = f"- {sub} ([{sh}]({repo_url}/commit/{fh}))"
        
        if re.match(r"^(feat|add|new)", sl): cats["✨ Features"].append(entry)
        elif re.match(r"^(fix|bug|patch|fixed|fixes)", sl): cats["🐛 Bug Fixes"].append(entry)
        elif re.match(r"^(deps|dep|update|bump|renovate|⬆️)", sl): cats["📦 Dependencies"].append(entry)
        elif re.match(r"^(chore|ci|workflow|config|ruff)", sl): cats["🔧 Maintenance & CI"].append(entry)
        elif re.match(r"^(docs|documentation)", sl): cats["📝 Documentation"].append(entry)
        elif re.match(r"^(test|pytest)", sl): cats["🧪 Tests"].append(entry)
        else: cats["🚀 Other"].append(entry)
    
    changelog = "## Changelog\n\n"
    has_content = False
    
    for title in ["✨ Features", "🐛 Bug Fixes", "📦 Dependencies", "🔧 Maintenance & CI", "📝 Documentation", "🧪 Tests", "🚀 Other"]:
        items = cats[title]
        if items:
            changelog += f"### {title}\n"
            for item in items:
                changelog += f"{item}\n"
            changelog += "\n"
            has_content = True
    
    if not has_content:
        changelog += "No significant changes in this release.\n\n"
    
    # Add Docker Image Info
    image_name = os.environ.get("IMAGE_NAME", "faserf/shielddns")
    changelog += f"## Docker Image\n"
    changelog += f"The official Docker image is available at: `ghcr.io/{image_name}:latest` and `ghcr.io/{image_name}:VERSION`\n"
    
    return changelog

if __name__ == "__main__":
    from_tag = sys.argv[1] if len(sys.argv) > 1 else None
    if from_tag == "None" or from_tag == "":
        from_tag = None
        
    content = get_changelog(from_tag)
    with open("CHANGELOG_BODY.md", "w", encoding="utf-8") as f:
        f.write(content)
