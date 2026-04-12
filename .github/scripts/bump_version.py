import re
import subprocess
import sys
import os

def get_latest_tag():
    try:
        result = subprocess.run(
            ["git", "tag", "--list", "--sort=-v:refname"],
            capture_output=True,
            text=True,
            check=True,
        )
        tags = result.stdout.strip().split("\n")
        # Filter for version-like tags
        version_tags = [t for t in tags if re.match(r'^v?\d+\.\d+\.\d+', t)]
        return version_tags[0] if version_tags else None
    except Exception:
        return None


def parse_version(v_str):
    if not v_str:
        return 0, 0, 0
    v_str = v_str.lstrip("v")
    core = v_str.split("-")[0]
    parts = list(map(int, core.split(".")))
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


def bump_version(current, bump_type, suffix=""):
    if not current:
        return "1.0.0" + suffix

    major, minor, patch = parse_version(current)

    if bump_type == "major":
        new = (major + 1, 0, 0)
    elif bump_type == "minor":
        new = (major, minor + 1, 0)
    else:  # patch
        new = (major, minor, patch + 1)

    return f"{new[0]}.{new[1]}.{new[2]}{suffix}"


def update_source_code(new_version):
    file_path = "admin/main.go"
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Normalize version: ensure it has the 'v' prefix for the Go constant
    if not new_version.startswith("v"):
        v_version = f"v{new_version}"
    else:
        v_version = new_version

    # Match Version = "vX.Y.Z-dev" or similar
    if re.search(r'Version\s*=\s*"[^"]+"', content):
        new_content = re.sub(
            r'Version\s*=\s*"[^"]+"',
            f'Version        = "{v_version}"',
            content,
            count=1
        )
    else:
        # If not found, append it before func main()
        if "func main()" in content:
            new_content = content.replace("func main()", f'const Version = "{v_version}"\n\nfunc main()')
        else:
            new_content = content + f'\nconst Version = "{v_version}"\n'

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(new_content)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: bump_version.py <major|minor|patch> [suffix]")
        sys.exit(1)

    bump_type = sys.argv[1].lower()
    suffix = sys.argv[2] if len(sys.argv) > 2 else ""
    
    latest_tag = get_latest_tag()
    
    # If no tag is found, fallback to the version in the source code
    if not latest_tag:
        try:
            with open("admin/main.go", "r", encoding="utf-8") as f:
                core_content = f.read()
                match = re.search(r'Version\s*=\s*"v?([^"]+)"', core_content)
                if match:
                    latest_tag = match.group(1)
        except Exception:
            pass

    new_v = bump_version(latest_tag, bump_type, suffix)

    update_source_code(new_v)
    print(new_v)
