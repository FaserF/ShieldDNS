import datetime
import json
import os
import re

# Configuration
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MANIFEST_PATH = os.path.join(PROJECT_ROOT, "project_manifest.json")
CONNECTIONS_PATH = os.path.join(PROJECT_ROOT, "project_connections.json")

IGNORE_DIRS = {
    ".git", "__pycache__", "node_modules", "dist", "build", "coverage",
    ".pytest_cache", ".idea", ".vscode", "venv", "env", ".mypy_cache", ".ruff_cache",
    ".system_generated", "scratch", "docs", ".github"
}
IGNORE_FILES = {"project_manifest.json", "project_connections.json", "app.db", "queries.db", "server.exe"}

ALLOWED_EXTENSIONS = {
    ".go", ".js", ".html", ".css", ".sh", ".yml", ".yaml", ".md", ".json"
}


def get_file_content(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except:
            return ""
    return ""


def generate_file_tree(startpath):
    tree = {}
    for root, dirs, files in os.walk(startpath):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
        rel_path = os.path.relpath(root, startpath)
        rel_path_key = rel_path.replace(os.sep, "/")

        valid_files = []
        for f in files:
            if f in IGNORE_FILES or f.startswith("."):
                continue
            ext = os.path.splitext(f)[1].lower()
            if ext in ALLOWED_EXTENSIONS or f in {"Dockerfile", "LICENSE"}:
                valid_files.append(f)

        if valid_files:
            tree[rel_path_key] = sorted(valid_files)
    return tree


def parse_go_endpoints():
    endpoints = []
    main_go_path = os.path.join(PROJECT_ROOT, "admin", "main.go")
    if os.path.exists(main_go_path):
        content = get_file_content(main_go_path)
        # Match mux.HandleFunc("/api/...", handle...) or mux.Handle("/api/...", ...)
        matches = re.findall(r'mux\.(HandleFunc|Handle)\(\s*"([^"]+)",\s*(?:authMiddleware\()?([a-zA-Z0-9_\.\(\)\s\*]+)\)?\s*\)', content)
        for handle_type, route, handler in matches:
            handler = handler.replace("http.HandlerFunc(", "").replace(")", "").strip()
            endpoints.append({
                "route": route,
                "handler": handler,
                "auth_required": "authMiddleware" in handler or "authMiddleware" in content.split(route)[0].split("\n")[-1]
            })
    return endpoints


def parse_frontend_views():
    views = []
    index_html_path = os.path.join(PROJECT_ROOT, "admin", "www", "admin", "index.html")
    if os.path.exists(index_html_path):
        content = get_file_content(index_html_path)
        # Find all <section id="..." class="view ...">
        matches = re.findall(r'<section\s+[^>]*id="([^"]+)"\s+[^>]*class="[^"]*view[^"]*"', content)
        for view_id in matches:
            views.append(view_id)
    return sorted(list(set(views)))


def parse_js_api_endpoints():
    endpoints = []
    api_js_path = os.path.join(PROJECT_ROOT, "admin", "www", "admin", "js", "services", "api.js")
    if os.path.exists(api_js_path):
        content = get_file_content(api_js_path)
        # Match name: basePath + '/api/...'
        matches = re.findall(r'([a-zA-Z0-9_]+)\s*:\s*basePath\s*\+\s*[\'"]([^\'\"]+)[\'"]', content)
        for name, route in matches:
            endpoints.append({
                "name": name,
                "route": "/api" + route
            })
    return endpoints


def get_env_vars():
    # Read environment variables commonly used or documented in README.md
    vars = ["ADMIN_PORT", "INGRESS_PORT", "CERT_FILE", "KEY_FILE", "INTERNAL_DOH_PORT", "DEBUG"]
    readme_path = os.path.join(PROJECT_ROOT, "README.md")
    if os.path.exists(readme_path):
        readme = get_file_content(readme_path)
        found = re.findall(r'`([A-Z][A-Z0-9_]+)`', readme)
        vars.extend(found)
    return sorted(list(set(vars)))


def generate_connections():
    print("Generating connections map...")
    
    # Define connection mapping keywords for ShieldDNS
    features = {
        "dns_core": {
            "purpose": "Core DNS engine, Corefile updating, DoH internal proxies, query logging, and dashboard statistics.",
            "backend_files": ["admin/dns.go", "admin/metrics.go", "admin/presets_list.go", "admin/api_stats.go"],
            "frontend_views": ["dashboard", "queries", "analytics"],
            "frontend_js": ["admin/www/admin/js/ui/charts.js", "admin/www/admin/js/ui/scroller.js", "admin/www/admin/js/ui/renderers.js"]
        },
        "mfa_security": {
            "purpose": "Multi-Factor Authentication including local password verification, TOTP configurations, and WebAuthn security keys.",
            "backend_files": ["admin/auth.go", "admin/api_mfa.go"],
            "frontend_views": ["settings"],
            "frontend_js": ["admin/www/admin/js/core/auth.js"]
        },
        "presets_rules": {
            "purpose": "Client-specific presets lists, domain rules block/allow, high-risk country list toggles, and customized DNS filters.",
            "backend_files": ["admin/api_rules.go", "admin/presets_list.go"],
            "frontend_views": ["lists"],
            "frontend_js": ["admin/www/admin/js/ui/events.js"]
        },
        "system_diagnostics": {
            "purpose": "System diagnostics, health checks, live terminal log streaming, backup and restore utilities, and upstream server verification.",
            "backend_files": ["admin/api_system.go", "admin/crypto_backup.go", "admin/watchdog.go", "admin/versions.go"],
            "frontend_views": ["system-logs", "diagnostics", "settings"],
            "frontend_js": ["admin/www/admin/js/core/navigation.js", "admin/www/admin/js/services/fetch.js"]
        },
        "geo_block": {
            "purpose": "MaxMind GeoIP integration, local country lookup, and server-side country blocking controls.",
            "backend_files": ["admin/geo.go", "admin/malicious.go"],
            "frontend_views": ["settings"],
            "frontend_js": ["admin/www/admin/js/ui/events.js"]
        }
    }

    connections_data = {
        "project": "ShieldDNS",
        "description": "Component connections map linking UI views, JS events, and Go controllers.",
        "timestamp": datetime.datetime.now().isoformat(),
        "connections": features
    }

    with open(CONNECTIONS_PATH, "w", encoding="utf-8") as f:
        json.dump(connections_data, f, indent=2)
    print(f"Connections map written to {CONNECTIONS_PATH}")


def generate_manifest():
    print("Generating project manifest...")
    go_endpoints = parse_go_endpoints()
    views = parse_frontend_views()
    js_endpoints = parse_js_api_endpoints()

    manifest = {
        "project": "ShieldDNS",
        "purpose": "High-performance DNS appliance and security gateway with integrated web administration panel.",
        "connections_map_reference": "project_connections.json (defines component linking for UI and backend files)",
        "timestamp": datetime.datetime.now().isoformat(),
        "stack": {
            "backend": "Go (embedded FS assets), SQLite (query database), CoreDNS (DNS server)",
            "frontend": "Vanilla HTML5, CSS3 (variables & flex/grid layout), Vanilla JS (ES6 modules)",
            "proxy": "DNS-over-HTTPS proxy to internal CoreDNS engine"
        },
        "env_required": get_env_vars(),
        "rbac_controls": ["Admin password hash verification", "CSRF token protection via X-Shield-Request"],
        "integrated_systems": ["CoreDNS", "MaxMind GeoIP database", "WebAuthn / TOTP MFA"],
        "ai_instructions": {
            "code_style": [
                "Strict adherence to Go idioms, slog for backend logging",
                "Responsive CSS without framework dependencies (Vanilla Flexbox and Grid)",
                "Vanilla JS ES6 import/export modules for core, services, and ui components",
                "Preserve HTML structures and unique DOM IDs"
            ],
            "development_rules": [
                "All backend route updates in main.go must align with js/services/api.js endpoints",
                "Embedded assets (go:embed) require compiling the binary to test changes",
                "Keep functions and classes concise and perform regular lint checks via jshint"
            ]
        },
        "commands": {
            "run_go_backend": "go run admin/main.go (runs administrative server locally)",
            "build_go_binary": "go build -o shielddns-admin ./admin (compiles with assets embedded)",
            "run_tests": "go test ./admin/... (runs unit tests)"
        },
        "architecture": {
            "backend_go_endpoints": [f"{e['route']} -> {e['handler']}() [Auth: {e['auth_required']}]" for e in go_endpoints],
            "frontend_views": views,
            "frontend_js_endpoints": js_endpoints
        },
        "file_tree": generate_file_tree(PROJECT_ROOT)
    }

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Manifest written to {MANIFEST_PATH}")


if __name__ == "__main__":
    generate_manifest()
    generate_connections()
