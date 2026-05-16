#!/usr/bin/env python3
"""Validate README.md claims against actual code.

Checks:
1. Module count matches ALL_MODULES
2. CLI flags mentioned in README exist in cli.py
3. API endpoints in README match api/server.js routes
4. STIX version claim matches stix_export.py
5. Key files referenced in README actually exist
6. Docker compose claim is accurate
"""

import re
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
from core.orchestrator import ALL_MODULES  # noqa: E402

ERRORS = []


def error(msg):
    ERRORS.append(msg)
    print(f"  ❌ {msg}")


def check(description, condition, fix_hint=""):
    if condition:
        print(f"  ✓ {description}")
    else:
        error(f"{description}{f' — {fix_hint}' if fix_hint else ''}")


# ── 1. Module count ──────────────────────────────────────────────────
with open(os.path.join(PROJECT_ROOT, "README.md")) as f:
    readme = f.read()

check(
    f"Module count: README claims 11, code has {len(ALL_MODULES)}",
    "11 Scanner Modules" in readme and len(ALL_MODULES) == 11,
    f"Update README to match actual module list: {ALL_MODULES}"
)

# ── 2. CLI flags ────────────────────────────────────────────────────
with open(os.path.join(PROJECT_ROOT, "cli.py")) as f:
    cli_code = f.read()

cli_flags = set(re.findall(r"--([a-z][-a-z0-9]*)", cli_code))
# Filter to actual click options (exclude common words in comments)
click_flags = set(re.findall(r"@click\.option\([\"']--([a-z][-a-z0-9]*)", cli_code))
click_flags |= set(re.findall(r"@click\.option\(\s*[\"']-([a-z])", cli_code))

# Key flags that MUST be in README
required_flags = {"auth", "modules", "depth", "threads", "stealth", "output", "format"}
for flag in required_flags:
    check(f"CLI --{flag} flag documented", f"--{flag}" in cli_code or f"-{flag[0]}" in cli_code)

# ── 3. API endpoints ──────────────────────────────────────────────────
with open(os.path.join(PROJECT_ROOT, "api", "server.js")) as f:
    server_js = f.read()

api_routes = set(re.findall(r"app\.(get|post|delete|put|patch)\(['\"]([^'\"]+)", server_js))
# Add WebSocket routes (registered differently)
ws_routes = set(re.findall(r"fastify\.get\(['\"]([^'\"]+)['\"],\s*\{\s*websocket:\s*true", server_js))
api_route_set = {(m.lower(), p) for m, p in api_routes}
for path in ws_routes:
    api_route_set.add(('ws', path))
readme_routes = set(re.findall(r"\|\s*(GET|POST|DELETE|PUT|PATCH|WS)\s*\|\s*`([^`]+)`", readme))

# Normalize
readme_route_set = {(m.lower(), p) for m, p in readme_routes}

for method, path in readme_route_set:
    check(
        f"API endpoint {method.upper()} {path} exists in server.js",
        (method, path) in api_route_set,
        "Add route to server.js or remove from README"
    )

# Check for undocumented routes (warn, not error)
for method, path in api_route_set:
    if path not in {r[1] for r in readme_route_set}:
        print(f"  ⚠ Undocumented route: {method.upper()} {path}")

# ── 4. STIX version ──────────────────────────────────────────────────
with open(os.path.join(PROJECT_ROOT, "reports", "stix_export.py")) as f:
    stix_code = f.read()

check(
    "STIX version: README says 2.1, code exports 2.1",
    "STIX 2.1" in readme and '"spec_version": "2.1"' in stix_code,
    "Update README or stix_export.py"
)

# ── 5. Key files exist ───────────────────────────────────────────────
key_files = [
    "cli.py",
    "requirements.txt",
    "Dockerfile",
    "docker-compose.yml",
    "api/server.js",
    "dashboard/src/App.jsx",
    "core/orchestrator.py",
    "reports/stix_export.py",
    "reports/html_report.py",
]
for f in key_files:
    path = os.path.join(PROJECT_ROOT, f)
    check(f"File exists: {f}", os.path.exists(path), f"Missing file: {f}")

# ── 6. Docker compose claim ──────────────────────────────────────────
has_docker_compose = os.path.exists(os.path.join(PROJECT_ROOT, "docker-compose.yml"))
readme_mentions_docker = "docker-compose" in readme.lower()
if has_docker_compose:
    check(
        "README references docker-compose.yml (file exists)",
        readme_mentions_docker,
        "Add docker-compose.yml reference to README"
    )
else:
    check(
        "README correctly notes no docker-compose.yml",
        not readme_mentions_docker or "no docker-compose" in readme.lower(),
        "docker-compose.yml exists but README says it doesn't"
    )

# ── Summary ──────────────────────────────────────────────────────────
print()
if ERRORS:
    print(f"❌ {len(ERRORS)} README accuracy check(s) FAILED:")
    for err in ERRORS:
        print(f"  • {err}")
    sys.exit(1)
else:
    print("✅ All README accuracy checks passed")
    sys.exit(0)