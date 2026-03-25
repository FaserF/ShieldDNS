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


def bump_version(current, bump_type):
    if not current:
        return "1.0.0"

    major, minor, patch = parse_version(current)

    if bump_type == "major":
        new = (major + 1, 0, 0)
    elif bump_type == "minor":
        new = (major, minor + 1, 0)
    else:  # patch
        new = (major, minor, patch + 1)

    return f"{new[0]}.{new[1]}.{new[2]}"


def update_source_code(new_version):
    file_path = "admin/main.go"
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Match Version = "vX.Y.Z-dev" or similar
    new_content = re.sub(
        r'Version\s*=\s*"[^"]+"',
        f'Version        = "v{new_version}"',
        content,
        count=1
    )

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(new_content)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)

    bump_type = sys.argv[1].lower()
    latest_tag = get_latest_tag()
    new_v = bump_version(latest_tag, bump_type)

    update_source_code(new_v)
    
    # Still write VERSION.txt for the CI to easily consume the version string
    with open("VERSION.txt", "w") as f:
        f.write(new_v)
    
    print(new_v)
