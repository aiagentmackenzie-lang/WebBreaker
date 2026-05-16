# 🔥 WebBreaker Production Readiness Plan

**Author:** Agent Mackenzie (Lead Security Engineer)  
**Date:** 2026-05-16  
**Status:** Pending Approval  
**Post-Audit:** 37 bugs fixed (3 Critical, 7 High, 13 Medium, 10 Low, 4 Info) — commit `6d614db`

---

## Goal

Transform WebBreaker from a demo with scanner logic into a defensible, portfolio-grade security tool that works against real targets and survives professional scrutiny.

---

## Phase 0: Hardening Foundations (2-3 days) ✅ COMPLETE

Core infrastructure gaps that make everything downstream unreliable.

| # | Task | Why | Status | File(s) |
|---|------|-----|--------|---------|
| 0.1 | **Real rate limiting** — token bucket with jitter | ✅ Replaced asyncio.sleep+semaphore with TokenBucket class (rate + burst + random jitter). Async client uses acquire() per request. | ✅ Done | `core/http_client.py` |
| 0.2 | **Scope enforcement** — URL scope validation blocks out-of-scope requests | ✅ Added _in_scope() and _enforce_scope() to both HttpClient and SyncHttpClient. Blocks out-of-scope GET/POST/REQUEST. Warns on redirect landing outside scope. | ✅ Done | `core/http_client.py` |
| 0.3 | **Configurable TLS verification** — default verify=True, --no-verify-tls flag | ✅ ScanConfig.no_verify_tls defaults to False (verify ON). CLI flag --no-verify-tls. httpx.AsyncClient/SyncClient use verify=not config.no_verify_tls. | ✅ Done | `core/http_client.py`, `cli.py`, `core/config.py` |
| 0.4 | **Proper error handling** — catch TimeoutException, network errors | ✅ All get/post/request methods now catch httpx.TimeoutException separately from RequestError. Returns None with dim log message. | ✅ Done | `core/http_client.py` |
| 0.5 | **ScanResult dataclass** — unified result type with timing, status, errors | ✅ Added ScanResult with scan_id, target, status, timing, error/timeout/scope_blocked counts, errors list. | ✅ Done | `core/config.py` |

**Bonus fixes found during hardening:**
- CSRF `_check_token_predictability`: `issues` list was never initialized → NameError. Fixed.
- XSS `scan_dom`: external JS findings used stale `severity` variable from inline loop → wrong severity. Fixed with per-result calculation.

---

## Phase 1: Scanner Reliability (3-4 days) ✅ COMPLETE

Make the scanners actually work against real targets, not just localhost test cases.

| # | Task | Why | Status | File(s) |
|---|------|-----|--------|---------|
| 1.1 | **False positive reduction — SQLi** | ✅ Canary injection, baseline comparison, boolean verification, 2-sample time baseline, confidence scoring, request/response logging. | ✅ Done | `core/sqli.py` |
| 1.2 | **False positive reduction — XSS** | ✅ Context-aware reflection detection (html_tag, attribute, js, url, html_body, html_encoded), canary-based confirmation, context-specific severity and confidence. | ✅ Done | `core/xss.py` |
| 1.3 | **False positive reduction — CMDi** | ✅ 2-sample baseline timing, baseline FP check for output markers and error patterns, filter bypass baseline check, request/response logging. | ✅ Done | `core/cmdi.py` |
| 1.4 | **Confidence scoring** — derive from evidence, not hardcoded values | ✅ sqli: _derive_confidence() from canary + baseline delta + confirming count. xss: _derive_xss_confidence() from context type + canary. cmdi: explicit per-evidence confidence values. | ✅ Done | All scanners |
| 1.5 | **Request/response logging** — store full request and response in findings | ✅ All scanners now populate Finding.request and Finding.response with actual HTTP data. sqli has _build_request_info() helper. | ✅ Done | All scanners |
| 1.6 | **Form detection hardening** — handle forms without actions, multipart, button elements, data-attrs | ✅ Forms without action default to current URL. Button elements extracted. enctype and data_attrs captured. | ✅ Done | `core/recon.py` |

---

## Phase 2: Missing Core Features (3-4 days)

Features the README claims but don't exist, or features every pentest tool needs.

| # | Task | Why | File(s) |
|---|------|-----|---------|
| 2.1 | **HTML/PDF report generation** | README claimed "Professional Reports with WeasyPrint" but zero report generation code exists. Add Jinja2 HTML template + WeasyPrint PDF export. | New: `reports/html_report.py`, `reports/pdf_report.py`, `templates/` |
| 2.2 | **CLI `report` command — real output** | Current `report` command just prints a Rich table. Needs `--format json\|html\|pdf\|stix` with actual file output. | `cli.py` |
| 2.3 | **`docker-compose.yml`** | README mentioned it, doesn't exist. Create one wiring API + Dashboard + SQLite volume. | New: `docker-compose.yml` |
| 2.4 | **Integration test suite** — spin up a vulnerable test app | Current 45 unit tests mock everything. Need a Flask deliberately-vulnerable app that scanners can actually hit. | New: `tests/integration/`, `tests/vulnerable_app.py` |
| 2.5 | **Authentication support** — login forms, session tokens, Basic auth | Currently only supports `--auth-header` and `--cookie`. Need form-based login (POST username/password, extract session), Basic auth, session refresh. | New: `core/auth.py`, `core/config.py`, `core/http_client.py` |

---

## Phase 3: API & Dashboard (2-3 days)

The API and Dashboard exist but have real gaps for production use.

| # | Task | Why | File(s) |
|---|------|-----|---------|
| 3.1 | **API authentication** — add API key or JWT auth | Currently anyone who can reach port 3100 can start scans, delete data. Zero auth. | `api/server.js` |
| 3.2 | **API input validation** — validate target URLs, module names, scan params | `POST /scan` accepts any string as target. Need URL validation, module whitelist, depth/threads bounds. | `api/server.js` |
| 3.3 | **Rate limiting on API** — prevent scan spam | No rate limiting on the API. Someone could queue 1000 scans. | `api/server.js` |
| 3.4 | **CLI-to-API scan ID alignment** — spawned process creates a different scan ID than the API | `POST /scan` creates a scan ID, then spawns `python3 cli.py scan` which creates a DIFFERENT scan ID. They won't match. | `api/server.js` |
| 3.5 | **Dashboard Reports page** — wire it to the report API | `Reports.jsx` exists but renders nothing meaningful. | `dashboard/src/pages/Reports.jsx` |

---

## Phase 4: Portfolio Integration — Make It Real (2-3 days)

The bridges are stubs returning empty dicts. Make them actually call your portfolio tools.

| # | Task | Why | File(s) |
|---|------|-----|---------|
| 4.1 | **GHOSTWIRE bridge — real HTTP calls** | Should POST scan data to GHOSTWIRE's API for network-level correlation. | `integrations/bridges.py` |
| 4.2 | **DEADDROP bridge — real evidence export** | Should create a DEADDROP case and upload findings as evidence with hash chains. | `integrations/bridges.py` |
| 4.3 | **HONEYTRAP bridge — IOC feed** | Should POST IOCs to HONEYTRAP for honeypot rule generation. | `integrations/bridges.py` |
| 4.4 | **Integration health check** — add `--check-integrations` CLI flag | Verify target services are actually running before using integrations. | `cli.py`, `integrations/bridges.py` |

---

## Phase 5: Polish & Release (2-3 days)

| # | Task | Why | File(s) |
|---|------|-----|---------|
| 5.1 | **STIX 2.1 compliance** — add `created_by_ref`, proper `valid_until`, kill chain phases | Current STIX export is structurally incomplete. Needs proper STIX IDs (UUIDv5), relationship objects, required fields. | `api/server.js` |
| 5.2 | **README accuracy CI check** | Validate module list count, CLI flags, and API endpoints against actual code on every push. | `.github/workflows/ci.yml` |
| 5.3 | **`.github/workflows/ci.yml`** — add pytest + ruff + build | No CI exists. Add GitHub Actions that runs tests on every push. | New: `.github/workflows/ci.yml` |
| 5.4 | **Comprehensive CLI `--help`** — add examples, module descriptions, exit codes | Current `--help` is minimal. Add rich examples and explain what each module does. | `cli.py` |
| 5.5 | **Version bump + `CHANGELOG.md`** | Track versions properly. | `pyproject.toml`, `CHANGELOG.md` |

---

## Timeline

| Phase | Duration | Dependencies |
|--------|----------|-------------|
| Phase 0: Foundations | 2-3 days | None |
| Phase 1: Scanner Reliability | 3-4 days | Phase 0 |
| Phase 2: Missing Features | 3-4 days | Phase 0 |
| Phase 3: API & Dashboard | 2-3 days | Phase 0 |
| Phase 4: Integrations | 2-3 days | Phases 0-2 |
| Phase 5: Polish | 2-3 days | All above |

**Total: 12-20 days of focused work**

---

## Priority Call

If we had to pick **3 things only**:

1. **Phase 0.1 + 0.3** — Real rate limiting + TLS verification (without this, can't responsibly scan real targets)
2. **Phase 1.1-1.3** — False positive reduction (without this, findings aren't trustworthy)
3. **Phase 2.1** — Report generation (without this, can't deliver results to a client)

Everything else is incremental improvement. These three are the gap between "demo" and "tool."

---

## Approval

- [ ] Raphael approves Phase 0
- [ ] Raphael approves Phase 1
- [ ] Raphael approves Phase 2
- [ ] Raphael approves Phase 3
- [ ] Raphael approves Phase 4
- [ ] Raphael approves Phase 5