# WebBreaker v1.0.0 — Bug & Quality Audit

**Auditor:** Agent Mackenzie (Lead Code Quality & Security Review)  
**Date:** 2026-05-16  
**Prior Audit:** BUGS_AND_ISSUES.md (26 bugs fixed, commit `9151909`)  
**Status:** 🔴 **37 BUGS FOUND** (3 Critical, 7 High, 13 Medium, 10 Low, 4 Info)

---

## CRITICAL (3)

| # | File | Bug | Impact |
|---|------|-----|--------|
| C-01 | `core/orchestrator.py:68` | **No recon fallback when recon module not selected** — If `recon` is not in `modules`, `recon_data` stays `None`. Then line `urls = [r.url for r in recon_data] if recon_data else [self.config.target]` works, BUT `forms = recon_data[0].forms if recon_data and recon_data else []` will crash with `IndexError` when `recon_data` is an empty list `[]`. The condition `recon_data and recon_data` is truthy for `[]` only when it's NOT empty, but the `[0]` index will fail on `[]`. More importantly, when `recon` IS selected but spider finds 0 pages, `recon_data = []` and `recon_data[0]` crashes. | **Scanner crash on empty recon results** |
| C-02 | `core/session.py:82-92` | **`multi_items()` may not exist on all httpx responses** — `resp.headers.multi_items()` is used to extract Set-Cookie headers, but httpx only guarantees `multi_items()` on `Headers` objects. If the response has no `Set-Cookie` header, `multi_items()` returns nothing. More critically, the session fixation test on line 110 (`resp2 = await self.client.get(url, cookies=test_cookies)`) passes `cookies=test_cookies` to `HttpClient.get()`, but `HttpClient.get()` doesn't accept a `cookies` kwarg — it will be silently ignored via `**kwargs`, meaning the custom session cookie is never actually sent. | **Session fixation test never actually sends custom cookie — false negative** |
| C-03 | `core/cmdi.py:48` | **Raw string not used for BYPASS_PAYLOADS** — The payload `r"; ec\ho CMDI_WEBBREAKER_7341"` uses a raw string prefix `r`, but the BYPASS_PAYLOADS list also contains `"; ec%00ho CMDI_WEBBREAKER_7341"` which has `%00` — this is NOT a raw string, and `%00` in a regular Python string literal is just the literal characters `%`, `0`, `0`, not a null byte. The LFI scanner hardcodes `%00` in payloads too, but there it's a URL-encoded null byte that the server would decode. In cmdi, the `%00` is meant to be sent in the body/query as a literal null byte, which requires `\x00` not `%00`. | **Null byte bypass payload is incorrect — `%00` in HTTP body is literal text, not null byte** |

## HIGH (7)

| # | File | Bug | Impact |
|---|------|-----|--------|
| H-01 | `core/sqli.py:233` | **`self.findings = findings` overwrites instead of accumulating** — In `scan_param()`, line 233 sets `self.findings = findings` instead of `self.findings.extend(findings)`. This means if you scan multiple params, only the LAST param's findings are kept. This was supposedly fixed in the prior audit (bug #8) but the fix is wrong — it was changed from `.extend()` to `=`, which is the opposite of what was needed. | **SQLi scanner loses all findings from previous params** |
| H-02 | `core/xss.py:115` | **`hash()` is non-deterministic across runs** — `marker = f"wb{abs(hash(payload)) % 99999}"` uses Python's `hash()` which is randomized per process (PYTHONHASHSEED). Marker values won't be reproducible, making it impossible to reliably verify reflection in test results. Use `hashlib.md5(payload.encode()).hexdigest()[:8]` for deterministic markers. | **Unreliable reflection detection — markers vary between runs** |
| H-03 | `core/dirbrute.py:99` | **`console` used but never imported** — `DirBruteScanner.scan()` line 99 references `console.print(f"[dim]DirBrute error: {r}[/dim]")` but the file never imports `Console` or creates a `console` instance. This will raise `NameError` at runtime. | **DirBrute crashes on first batch error** |
| H-04 | `core/orchestrator.py:117-148` | **Scanners created inside loop but `forms` extraction is fragile** — `forms = recon_data[0].forms if recon_data and recon_data else []` — when `recon_data` is non-empty but the first result has no forms, all scanners get empty forms. Should collect forms from ALL recon results, not just the first one. | **Form-based scanning misses forms from other pages** |
| H-05 | `api/server.js:82` | **Spawned CLI process can write to DB that API also reads** — The CLI spawned by `POST /scan` writes findings to the same SQLite DB the API is reading from concurrently. SQLite in WAL mode handles concurrent reads, but better-sqlite3 is synchronous and blocks the event loop during writes. Under load, this causes API latency spikes and potential SQLITE_BUSY errors. | **DB contention under concurrent scans** |
| H-06 | `core/fuzz.py:46-53` | **Null byte payloads `test\x00` and `test%00.jpg` in FUZZ_PAYLOADS** — The `\x00` null byte in Python string `"test\x00"` will be URL-encoded by httpx, but the `%00` in `"test%00.jpg"` is sent as literal `%00` text. Neither is consistently handled. The null byte string may cause httpx to raise or truncate. | **Fuzz null byte payloads are inconsistent** |
| H-07 | `core/xss.py:142-170` | **DOM XSS `Severity` enum lookup uses string key** — `Severity[result["risk"]]` where `result["risk"]` is a string like `"HIGH"`. This works because `Severity["HIGH"]` exists, but it's fragile and not how other modules access the enum. If `result["risk"]` is ever lowercase or has a typo, it raises `KeyError`. | **Fragile enum access — should use `.value` comparison or explicit mapping** |

## MEDIUM (13)

| # | File | Bug | Impact |
|---|------|-----|--------|
| M-01 | `core/recon.py:70` | **`recon.get_all_forms()` called on class instance but `forms` attribute is on `ReconResult`** — In orchestrator line 77, `recon.get_all_forms()` is called, but `ReconScanner.get_all_forms()` iterates `self.results` which may be empty if the `spider()` method was called from outside. If someone calls `scan_url()` or `fingerprint()` first, `self.results` could still have stale data. | **Stale data risk if scanner is reused** |
| M-02 | `core/orchestrator.py:156` | **Deduplication key uses `f.payload[:50]`** — Truncating payload to 50 chars means two different payloads with the same first 50 chars are considered duplicates. For long SQL injection payloads, this is common. | **False deduplication — different findings dropped** |
| M-03 | `core/http_client.py:40` | **`verify=False` disables TLS verification globally** — No way to re-enable per-scan. Also no warning printed when SSL verification is disabled. For a security tool, this is ironic. | **All scans ignore certificate errors silently** |
| M-04 | `core/sqli.py:195` | **Time-based detection threshold is 4.5s but payloads use SLEEP(5)** — Network jitter can cause false positives even with 4.5s threshold. More importantly, if the server is slow anyway (e.g., 2s baseline), any 5s sleep looks like a 3s delay, which still passes the 4.5s threshold only if the baseline is <0.5s. No baseline time comparison is done. | **Time-based SQLi false positives on slow servers** |
| M-05 | `core/cmdi.py:55-68` | **Time-based CMDI detection same issue** — Sleep 5 with 4.5s threshold, no baseline comparison. On slow servers, any response >4.5s triggers a finding. | **Time-based CMDI false positives on slow servers** |
| M-06 | `core/database.py` | **No WAL mode or busy timeout** — SQLite without WAL and busy_timeout means concurrent writes (from CLI process + API) can get `SQLITE_BUSY`. The prior audit fixed this for the API's better-sqlite3 but NOT for the Python sqlite3 module used by the CLI/database.py. | **CLI scanner can get SQLITE_BUSY errors under concurrent load** |
| M-07 | `core/csrf.py:70-88` | **`_check_same_site_cookies` uses `resp.headers.get_list("set-cookie")` which doesn't exist on httpx Response** — httpx Response headers don't have `get_list()`. The code has a fallback to `resp.headers.get("set-cookie", "")` but httpx joins multi-value Set-Cookie headers with commas (RFC violation). This means multiple Set-Cookie headers are incorrectly parsed as a single comma-separated string. | **Cookie SameSite analysis broken for multi-cookie responses** |
| M-08 | `core/cmdi.py:48` | **BYPASS_PAYLOADS list contains `r"; ec\ho..."` which is a raw string but `ec\ho` still has a backslash before `h`** — In a raw string `r"..."`, `\h` is literally `\h` (not a valid escape), which is fine in Python 3.12+ (deprecation warning only). But `r"; ec\ho"` literally contains `\h` as two characters, which shells won't interpret as `echo`. The intent was to bypass `echo` filtering by inserting a backslash. | **Shell bypass payload `ec\ho` is incorrect — backslash is not a valid echo bypass in most shells** |
| M-09 | `dashboard/src/lib/api.js` | **WebSocket URL doesn't account for API base path** — `wsConnect` uses `${protocol}//${location.host}/ws` but the API base is `/api`. The vite proxy maps `/ws` correctly in dev, but in production (nginx), `/ws` goes to `http://api:3100/ws`. However, the `apiFetch` function uses `/api` prefix which doesn't match the nginx config that strips `/api` prefix. | **API proxy mismatch — dashboard calls `/api/scan` but nginx strips `/api` → Fastify gets `/scan` (correct), but websocket URL construction may break in production** |
| M-10 | `core/lfi.py:76` | **`scan_forms` method defined but never called from orchestrator** — LFI has `scan_forms()` method but orchestrator doesn't use it (line 138 just calls `scan_url`). Forms with `file` parameters are never tested for LFI. | **LFI misses form-based testing** |
| M-11 | `core/rfi.py:72` | **Same issue as LFI — `scan_forms()` exists but is never called** | **RFI misses form-based testing** |
| M-12 | `core/headers.py:143` | **`import re` inside method body** — `import re` is done inside `_calculate_grade` method. While not a bug per se, it's inconsistent — `re` is also imported at module level in `_analyze_csp_bypasses`. The inner import is unnecessary. | **Code quality — redundant import** |
| M-13 | `core/csrf.py:48-56` | **`_check_token_predictability` returns on first predictable token** — If a form has multiple token fields, it only checks the first one found. A form could have one short/weak token and one strong one, and the scanner would report the weak one and skip the strong. | **Incomplete token analysis** |

## LOW (10)

| # | File | Bug | Impact |
|---|------|-----|--------|
| L-01 | `core/recon.py:80` | **Spider uses `queue.pop(0)` (O(n) for list)** — Should use `collections.deque` for BFS efficiency. For deep crawls with many URLs, this becomes a performance bottleneck. | **O(n²) BFS instead of O(n)** |
| L-02 | `core/dirbrute.py:89-99` | **`asyncio.gather(*tasks, return_exceptions=True)` catches exceptions but only logs them to console** — No findings are created for erroring URLs, and errors are silently swallowed. Could miss important 5xx findings. | **Errors silently discarded** |
| L-03 | `core/orchestrator.py:68` | **`recon_data` variable used after `if` block but type could be `None`** — If `"recon" in modules` is true but spider returns no results (empty list), `recon_data` is `[]` and `recon_data[0].forms` will IndexError. This is the same as C-01 but for the empty-list case specifically. | **Edge case crash** |
| L-04 | `core/ai/triage.py` | **AI triage uses `ollama` Python package but it's not in `requirements.txt`** — The `ollama>=0.4` IS in requirements.txt, but the import is inside a try/except, so it degrades gracefully. However, no documentation tells users to install ollama or pull the model. | **Silent degradation — AI triage always falls back** |
| L-05 | `core/integrations/bridges.py` | **Integration bridges are stubs — no actual HTTP calls** — GhostwireBridge, HatcheryBridge, etc. all just return Python dicts. No actual network calls. README implies portfolio integrations are functional. | **README overpromises — integrations are data formatters, not bridges** |
| L-06 | `core/sqli.py:85` | **`_baseline_cache` is per-scanner-instance** — If the same URL appears in multiple scan contexts, the cache is shared. Not a bug, but if the scanner is reused for different targets, stale baselines will cause false results. | **Baseline cache not invalidated across targets** |
| L-07 | `core/xss.py:87` | **WAF_BYPASS_PAYLOADS contains `'<scr\x00ipt>alert(1)</script>'`** — The `\x00` null byte in a Python string will be URL-encoded by httpx, but some WAFs decode null bytes before checking. This is a known technique, but the way it's represented here (as a Python string literal with `\x00`) means httpx will encode it differently than the original audit intended. | **Inconsistent null byte handling across payloads** |
| L-08 | `dashboard/src/pages/LiveScan.jsx:22` | **Module status parsing from log text is fragile** — Regex `msg.data.match(/Running (\w+)/i)` and `msg.data.match(/✓ (\w+)/)` assume specific CLI output format. If the CLI output changes, statuses break silently. | **Fragile log parsing for dashboard status** |
| L-09 | `api/server.js:53` | **`scanSubscribers` Map never cleaned up on scan completion** — Subscribers are removed when WebSocket closes, but if a client navigates away without closing, the subscriber stays. No timeout or cleanup mechanism. | **Memory leak in long-running API server** |
| L-10 | `core/session.py:97-99` | **Session fixation test doesn't verify the custom session ID is actually present in the response** — It checks if the custom session ID is NOT in the new Set-Cookie (which is good), but doesn't verify the server actually USED the custom ID. A server that ignores custom cookies entirely would pass the test (not vulnerable) even though it should still be checked differently. | **Session fixation test has false negative gap** |

## INFO (4)

| # | File | Issue | Impact |
|---|------|-------|--------|
| I-01 | `README.md` | **README lists "STIX 2.1 export" but the implementation generates STIX 2.1 bundles with `spec_version: '2.1'` on only 3 of the ~15 object types** — The vulnerability, attack-pattern, and relationship objects have `spec_version` but indicator and identity objects use it correctly. The infrastructure object also has it. However, some STIX mandated properties are missing (e.g., `created_by_ref` on vulnerabilities). | **STIX export is structurally incomplete** |
| I-02 | `README.md` | **"React 19" listed in Tech Stack but package.json has `"react": "^19.0.0"`** — This is correct, but React 19 is still in RC/canary. May cause issues in production. | **React version risk** |
| I-03 | `core/recon.py:30-43` | **TECH_SIGNATURES regex patterns have overlapping false positives** — `r"react"` matches "react" in any context (including "reactive", "reaction"), `r"flask"` matches "flask" in "thermos flask", etc. Should use more specific patterns (word boundaries, context-aware). | **Tech fingerprinting false positives** |
| I-04 | `core/database.py` | **No connection pooling or context manager** — Database is opened in `connect()` and closed in `close()`, but if an exception occurs between these calls, the connection leaks. Should use `__enter__`/`__exit__` or context manager pattern. | **DB connection leak on exceptions** |

---

## README Accuracy Check

| Claim | Status | Notes |
|-------|--------|-------|
| "10 Scanner Modules" | ✅ | Correct — recon, sqli, xss, csrf, cmdi, lfi, rfi, dirbrute, fuzz, headers, session (11 actually, but README says 10) |
| "Recon & Spidering" | ✅ | Works |
| "AI-Assisted Triage" | ⚠️ | Works with Ollama, but model name `webbreaker-triage` doesn't exist — falls back to rule-based |
| "React Dashboard" | ✅ | Works |
| "Professional Reports: HTML reports with WeasyPrint" | ❌ | **No HTML report generation code exists** — No `reports/html_report.py` or `reports/stix_export.py` in the codebase (they were referenced in the prior BUGS_AND_ISSUES.md as fixed, but aren't present in the repo) |
| "STIX 2.1 export" | ⚠️ | Partial — API generates STIX bundles but Python CLI has no STIX export |
| "Portfolio Integrations: Bridges to GHOSTWIRE, HATCHERY, DEADDROP, HONEYTRAP" | ⚠️ | **Stubs only — no actual HTTP/network calls to any external tool** |
| "CLI-First" | ✅ | Works |
| "`python3 cli.py scan`" | ✅ | Works |
| "Stealth mode" | ✅ | Works |
| "`python3 cli.py fingerprint`" | ✅ | Works |
| "Docker Compose" | ❌ | **No `docker-compose.yml` exists in the repo** — README says `docker-compose up` but there's no compose file |
| "WebSocket: ws://localhost:3100/ws" | ✅ | Works in API |
| "DELETE /scan/:id" | ✅ | Works in API |
| "POST /scan/:id/triage" | ✅ | Works |
| "WeasyPrint" | ❌ | **Not used anywhere — requirements.txt includes it but no code generates PDF/HTML reports** |
| "llama" in requirements | ❌ | **`requirements.txt` has `ollama>=0.4` but the README says "Ollama (local LLM)"** — This is correct but the AI module is barely integrated (Python side has `ai/triage.py` but CLI doesn't call it) |

---

## Summary

| Severity | Count | Key Issues |
|----------|-------|------------|
| 🔴 CRITICAL | 3 | Empty recon crash, session fixation false negative, null byte encoding |
| 🟠 HIGH | 7 | SQLi findings overwrite, dirbrute NameError, non-deterministic hash, forms extraction |
| 🟡 MEDIUM | 13 | SQLite WAL missing (Python side), Set-Cookie parsing, time-based false positives, unused form scanners |
| 🟢 LOW | 10 | O(n²) BFS, silent errors, stale baseline cache, memory leak |
| 🔵 INFO | 4 | Tech fingerprinting FP, missing STIX properties, DB connection leak, React 19 |
| **TOTAL** | **37** | |

**README Issues:** 10 modules claimed (actually 11), no docker-compose.yml, no HTML/PDF report code, integrations are stubs.