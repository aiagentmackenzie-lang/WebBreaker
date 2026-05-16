# Changelog

All notable changes to WebBreaker are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0/).

## [1.1.0] — 2026-05-16

### Added — Phase 5: Polish & Release

- **STIX 2.1 compliance** — Full STIX 2.1 spec adherence:
  - UUIDv5 deterministic IDs using STIX namespace (replaces arbitrary string IDs)
  - `created_by_ref` on all SDOs referencing the WebBreaker identity
  - `valid_until` on indicators (30-day default, STIX 2.1 requirement)
  - `kill_chain_phases` on attack patterns (MITRE ATT&CK phases)
  - `pattern_version: "2.1"` on indicator objects
  - `sectors` field on identity object
  - `description` on relationship objects
  - `uses` relationships (attack pattern → vulnerability) in addition to `targets`
  - `confidence` integer (0–100) on vulnerability objects
  - MITRE ATT&CK and CAPEC URLs in external_references
  - Both Python (`reports/stix_export.py`) and Node.js API (`api/server.js`) updated
- **README accuracy CI** — `scripts/verify_readme.py` validates module count, CLI flags, API endpoints, key files, and docker-compose existence against actual code
- **GitHub Actions CI** — `.github/workflows/ci.yml` runs pytest, ruff, README verification, API startup, and Dashboard build on every push/PR
- **Comprehensive CLI `--help`** — All commands now include module descriptions, examples, and exit codes
- **CHANGELOG.md** — Version tracking from v1.1.0 onward

### Fixed — Lint Cleanup (26 issues)

- Removed 18 unused imports (`asyncio`, `hashlib`, `json`, `re`, `urlparse`, `urljoin`, `Optional`, `MARKER`)
- Removed 4 unused variable assignments (`poc`, `max_age_match`, `context`, `start`/`end`)
- Fixed 3 f-strings without placeholders
- Removed duplicate `from rich.console import Console` import in `core/dirbrute.py`
- Added `noqa: E402` for necessary post-`sys.path` import in `scripts/verify_readme.py`

### Changed

- Version bumped from 1.0.0 → 1.1.0
- README: updated docker-compose.yml reference, added `/health` API endpoint, added HTML/PDF export to tech stack
- STIX export test count: 11 → 28 tests (17 new STIX 2.1 compliance tests)
- Total test count: 182 → 201 (19 new tests: 17 STIX + 4 API)

---

## [1.0.0] — 2026-05-16

### Added — Phase 0: Hardening Foundations

- Token-bucket rate limiting with jitter (replaces asyncio.sleep + semaphore)
- URL scope enforcement (blocks out-of-scope requests and redirects)
- TLS verification ON by default (`--no-verify-tls` to disable)
- Proper error handling (httpx.TimeoutException separated from RequestError)
- ScanResult dataclass with timing, status, error tracking
- Fixed CSRF `_check_token_predictability` NameError
- Fixed XSS `scan_dom` stale severity variable

### Added — Phase 1: Scanner Reliability

- SQLi false positive reduction: canary injection, baseline comparison, boolean verification, 2-sample time baseline, confidence scoring, request/response logging
- XSS false positive reduction: context-aware reflection detection (html_tag, attribute, js, url, html_body, html_encoded), canary-based confirmation, context-specific severity
- CMDi false positive reduction: 2-sample baseline timing, baseline FP check for output markers, filter bypass baseline check
- Form detection hardening: forms without action, button elements, enctype, data-attrs

### Added — Phase 2: Missing Core Features

- Jinja2 HTML report generation with risk scoring
- WeasyPrint PDF report export
- CLI `report` command with `--format terminal|json|html|pdf|stix`
- Docker Compose configuration (API + Dashboard + SQLite volume)
- Integration test suite with deliberately-vulnerable Flask app (14 tests)
- Authentication support: Basic auth, form-based login, session refresh

### Added — Phase 3: API & Dashboard

- API key authentication (X-API-Key header, constant-time comparison)
- Input validation (URL, modules, severity, depth/threads bounds)
- Rate limiting (100 req/min per IP)
- CLI-to-API scan ID alignment
- Dashboard Reports page rewrite

### Security

- 37 bugs fixed in initial security audit (3 Critical, 7 High, 13 Medium, 10 Low, 4 Info)