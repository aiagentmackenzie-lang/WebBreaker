# 🔥 WebBreaker — Web Application Penetration Testing Toolkit

**Status:** SPEC — Pending Raphael's Review  
**Created:** April 17, 2026  
**Category:** Web App Pentesting  
**Priority:** P1 (Largest gap in security portfolio)

---

## 🎯 What Is WebBreaker?

An all-in-one web application penetration testing toolkit that combines reconnaissance, vulnerability scanning, exploitation, and reporting into a single CLI-first workflow. Designed for authorized security assessments — the tool a pentester reaches for first.

**Differentiator:** Unified toolkit with AI-assisted triage (Ollama), not 10 separate tools duct-taped together. Portfolio-grade: CLI + API + Dashboard, matching the standard set by DEADDROP/HATCHERY/GHOSTWIRE/HONEYTRAP.

---

## 📊 Competitive Landscape — What Exists on GitHub

### Heavyweights (We Study, Not Clone)

| Tool | Stars | What It Does | Our Take |
|------|-------|-------------|----------|
| **sqlmap** | 37K | The SQLi gold standard. 5 injection types, DB takeover, 6 detection techniques | Too focused — only SQLi. We build SQLi as a module, not the whole tool |
| **OWASP ZAP** | 15K | Full web scanner with GUI, API, proxy, automation | Java-heavy, bloated GUI. Our edge: Python CLI-first + AI triage + lighter weight |
| **XSStrike** | 14.9K | Most advanced XSS scanner. WAF detection, payload generation, crawler | XSS-only. We integrate XSS scanning as a module |
| **ffuf** | 15.8K | Fast web fuzzer in Go. Directory brute, parameter fuzzing | Go-based, fuzzing only. We include fuzzing as a module |
| **commix** | 5.7K | Command injection exploitation | Niche — we include command injection as a module |
| **Wapiti** | 1.7K | Python3 web vuln scanner. XSS, SQLi, CSRF, LFI, etc. | Closest competitor. No AI, no real-time dashboard, no spider |
| **V3n0M** | 1.6K | Python scanner for SQLi/XSS/LFI/RFI | Dated (Python 3.6), no dashboard, no modern features |
| **PEGASUS** | 6 | Python CLI pentest suite (SQLi, XSS, CSRF, dir brute, session, JS analysis) | Good feature list, very early. Activation code gated — odd choice |

### What's Missing in ALL of Them
- ❌ No AI-assisted triage or finding prioritization
- ❌ No unified workflow (you run 5 tools, manually correlate results)
- ❌ No real-time React dashboard
- ❌ No STIX 2.1 export for threat intel sharing
- ❌ No integration with other security tools (forensics, sandbox, etc.)
- ❌ No professional PDF/HTML reporting with evidence chains

**WebBreaker fills ALL of these gaps.**

---

## 🏗️ Architecture

```
WebBreaker/
├── core/                    # Scanner engines
│   ├── recon.py             # Recon & spidering
│   ├── sqli.py              # SQL injection module
│   ├── xss.py               # XSS detection module
│   ├── csrf.py              # CSRF detection & PoC builder
│   ├── cmdi.py              # Command injection module
│   ├── lfi.py               # Local file inclusion
│   ├── rfi.py               # Remote file inclusion
│   ├── dirbrute.py          # Directory & file brute forcing
│   ├── fuzz.py              # Parameter fuzzing engine
│   ├── headers.py           # Security header analysis
│   └── session.py           # Session & cookie analysis
├── ai/                      # AI-assisted features
│   ├── triage.py            # Ollama-powered finding prioritization
│   ├── payload_gen.py       # AI payload mutation & generation
│   └── report_ai.py         # AI executive summary generation
├── api/                     # Fastify REST API
│   ├── server.ts            # API server (10+ endpoints)
│   ├── routes/
│   └── websocket.ts         # Real-time scan updates
├── dashboard/               # React dashboard
│   ├── src/
│   │   ├── components/      # 12+ React components
│   │   ├── pages/           # 5 pages (Scan, Findings, Recon, Report, Config)
│   │   └── charts/          # D3 visualizations
│   └── ...
├── reports/                 # Report generation
│   ├── html_report.py       # HTML report with embedded evidence
│   ├── pdf_report.py        # WeasyPrint PDF generation
│   └── stix_export.py       # STIX 2.1 export
├── payloads/                # Payload wordlists
│   ├── sqli/
│   ├── xss/
│   ├── cmdi/
│   ├── lfi/
│   └── dirs/
├── integrations/            # Portfolio integrations
│   ├── ghostwire_bridge.py  # Send PCAP to GHOSTWIRE
│   ├── hatchery_bridge.py   # Send payloads to HATCHERY
│   └── deaddrop_bridge.py  # Export findings to DEADDROP
├── cli.py                   # Click CLI entry point
├── docker-compose.yml       # Full stack deployment
└── requirements.txt
```

---

## 🔧 Core Modules — Feature Breakdown

### Phase 1: Core Engine (CLI + Scanner Modules)

#### 1. Reconnaissance & Spidering
- **Target discovery:** DNS lookup, WHOIS, tech fingerprint (Wappalyzer-style)
- **Web spider:** Recursive crawling with configurable depth, scope rules
- **URL collection:** Extract forms, endpoints, parameters, JS files
- **Sitemap generation:** Visual map of discovered attack surface
- **Authentication support:** Basic, form-based, cookie-based, Bearer token

#### 2. SQL Injection (sqli)
- **Detection types:** Error-based, boolean-based, time-based, UNION-based, stacked queries, out-of-band
- **Injection points:** GET params, POST params, HTTP headers (Cookie, User-Agent, Referer, X-Forwarded-For)
- **Database support:** MySQL, PostgreSQL, MSSQL, Oracle, SQLite
- **Exploitation:** Data extraction, schema enumeration, file read/write (where authorized)
- **Anti-WAF:** Payload encoding, comment injection, case alternation, whitespace substitution
- **Payload count:** 200+ built-in payloads + custom payload support

#### 3. Cross-Site Scripting (xss)
- **Detection types:** Reflected, stored, DOM-based
- **Injection points:** URL params, form fields, HTTP headers
- **Payload generation:** Context-aware (HTML, JS, attribute, URL, CSS contexts)
- **WAF bypass:** Encoding variations, event handlers, tag mutation
- **Proof of concept:** Auto-generates PoC URLs and HTML files
- **Blind XSS:** Callback integration (via collaborator-style endpoint)

#### 4. CSRF Detection (csrf)
- **Token analysis:** Missing tokens, weak tokens, predictable tokens, token leakage
- **SameSite cookie check:** Lax/Strict/None classification
- **Origin/Referer validation:** Check bypass scenarios
- **PoC builder:** Auto-generates exploit HTML pages for confirmed findings

#### 5. Command Injection (cmdi)
- **Detection:** OS command injection (Linux + Windows)
- **Techniques:** Blind time-based, output-based, out-of-band (DNS)
- **Payload types:** Semicolon, pipe, backtick, $(), newline injection
- **Filter bypass:** Encoding, whitespace alternatives, command substitution

#### 6. File Inclusion (lfi / rfi)
- **LFI:** Path traversal (../), null byte, double encoding, PHP wrappers (php://filter, data://, expect://)
- **RFI:** Remote file inclusion detection with callback server
- **Log poisoning:** Via User-Agent, session files, /proc/self/environ

#### 7. Directory Brute Force (dirbrute)
- **Multi-threaded:** Configurable concurrency (default 50 threads)
- **Wordlists:** Built-in (common, api, backup, config) + custom
- **Smart filtering:** Filter by status code, content length, response time
- **Recursive:** Auto-detect and recurse into discovered directories
- **Extensions:** Fuzz file extensions (php, asp, js, env, bak, sql, zip, etc.)
- **Rate limiting:** Configurable requests/sec to avoid DoS

#### 8. Parameter Fuzzing (fuzz)
- **Fuzz locations:** URL params, POST body, JSON body, headers, cookies
- **Mutation strategies:** Overflow, format string, type juggling, null bytes
- **Response diffing:** Baseline comparison for anomaly detection
- **Custom payloads:** Load from file or generate algorithmically

#### 9. Security Headers (headers)
- **Check 25+ headers:** CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.
- **CSP analysis:** Parse and find bypass opportunities
- **Grade scoring:** A-F grade based on header presence and quality
- **Remediation:** Specific fix recommendations per finding

#### 10. Session Analysis (session)
- **Cookie security:** Secure, HttpOnly, SameSite, Path, Domain flags
- **Session fixation:** Test for session token rotation on login
- **Session hijacking:** Test cookie binding to IP/fingerprint
- **Token entropy:** Statistical analysis of session ID randomness

---

### Phase 2: API + AI Triage

#### Fastify API (TypeScript)
- `POST /scan` — Start new scan (returns scan ID)
- `GET /scan/:id` — Scan status & progress
- `GET /scan/:id/findings` — All findings with severity/filter
- `GET /scan/:id/recon` — Reconnaissance results
- `POST /scan/:id/report` — Generate report (HTML/PDF/STIX)
- `GET /scans` — List all scans
- `DELETE /scan/:id` — Delete scan & results
- `GET /dashboard/stats` — Aggregate statistics
- `WebSocket /ws` — Real-time scan updates

#### AI-Assisted Triage (Ollama)
- **Finding prioritization:** AI ranks findings by exploitability + business impact
- **False positive reduction:** AI analyzes response context to filter noise
- **Payload generation:** AI mutates payloads based on WAF behavior
- **Executive summary:** AI-generated plain-English report summary
- **Remediation advice:** Context-specific fix recommendations per finding

---

### Phase 3: React Dashboard

#### Pages (5)
1. **New Scan** — Target input, module selection, config
2. **Live Scan** — Real-time findings, progress bar, module status
3. **Findings** — Filterable table (severity, type, URL, confidence)
4. **Recon** — Attack surface map, tech stack, discovered URLs
5. **Reports** — Generate & download HTML/PDF/STIX reports

#### Components (12+)
- ScanConfig, FindingCard, SeverityBadge, AttackSurfaceMap
- TechFingerprint, URLTree, RequestResponseViewer
- PayloadTimeline, AIInsightPanel, ReportPreview
- StatsBar, ModuleStatus

#### D3 Visualizations
- Attack surface treemap
- Finding severity distribution (donut chart)
- Scan timeline (findings over time)
- Module coverage heatmap

---

### Phase 4: Integrations + Deploy + Polish

#### Portfolio Integrations
- **GHOSTWIRE bridge:** Send captured HTTP traffic for network-level analysis
- **HATCHERY bridge:** Submit discovered malicious payloads for sandbox analysis
- **DEADDROP bridge:** Export findings as forensic evidence with chain-of-custody
- **HONEYTRAP bridge:** Feed attacker IOCs to honeypot deployment

#### STIX 2.1 Export
- Vulnerability objects per finding
- Attack pattern mapping (MITRE ATT&CK / CAPEC)
- Indicator objects for IOCs
- Relationship objects linking findings to targets

#### Professional Reports
- HTML with embedded evidence (request/response pairs, screenshots)
- PDF via WeasyPrint with professional styling
- Executive summary (AI-generated)
- Technical detail with reproduction steps
- Remediation roadmap (prioritized)

#### Deployment
- Docker Compose (API + Dashboard + Ollama)
- CLI-only mode (no dashboard required)
- Config files for scan profiles (quick, full, stealth, api-focused)

---

## 📏 Estimated Scale

| Phase | LOC Estimate | Files |
|-------|-------------|-------|
| Phase 1: Core Engine | ~4,500 | 25+ |
| Phase 2: API + AI | ~2,000 | 15+ |
| Phase 3: Dashboard | ~3,500 | 20+ |
| Phase 4: Integrations + Deploy | ~1,500 | 15+ |
| **Total** | **~11,500** | **75+** |

---

## 🧪 Testing Strategy

- **Unit tests:** Each scanner module (pytest, target 80%+ coverage)
- **Integration tests:** Full scan workflow against DVWA/WebGoat
- **AI triage tests:** Verify AI finding prioritization accuracy
- **API tests:** Fastify endpoint validation
- **Dashboard:** Component rendering + WebSocket updates
- **E2E tests:** Docker Compose stack spin-up → scan → report

---

## 🔧 Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| **CLI** | Python 3.12 + Click + Rich | Proven from GHOSTWIRE/HATCHERY/DEADDROP |
| **Scanner Engine** | Python (requests, httpx, BeautifulSoup, lxml, aiohttp) | Async HTTP for speed, mature parsing libs |
| **AI** | Ollama (local LLM) | Consistent with portfolio, no API keys needed |
| **API** | TypeScript + Fastify + WebSocket | Consistent with HATCHERY/GHOSTWIRE/HONEYTRAP |
| **Dashboard** | React 19 + Vite + Tailwind + D3 | Portfolio standard |
| **Database** | SQLite (scan storage) | Lightweight, no external DB needed |
| **Reports** | Jinja2 + WeasyPrint | Professional HTML/PDF generation |
| **Export** | STIX 2.1 | Threat intel sharing standard |
| **Docker** | Docker Compose | Full stack deployment |

---

## 🎯 What Makes WebBreaker Different

| Feature | sqlmap | ZAP | Wapiti | XSStrike | **WebBreaker** |
|---------|--------|-----|--------|----------|---------------|
| SQLi | ✅ Deep | ✅ | ✅ | ❌ | ✅ |
| XSS | ❌ | ✅ | ✅ | ✅ Deep | ✅ |
| CSRF | ❌ | ✅ | ✅ | ❌ | ✅ |
| Command Injection | ❌ | ❌ | ❌ | ❌ | ✅ |
| LFI/RFI | ❌ | ✅ | ✅ | ❌ | ✅ |
| Dir Brute | ❌ | ❌ | ❌ | ❌ | ✅ |
| Param Fuzzing | ❌ | Partial | ❌ | ❌ | ✅ |
| AI Triage | ❌ | ❌ | ❌ | ❌ | ✅ |
| React Dashboard | ❌ | ❌ (Java GUI) | ❌ | ❌ | ✅ |
| STIX Export | ❌ | ❌ | ❌ | ❌ | ✅ |
| Portfolio Integrations | ❌ | ❌ | ❌ | ❌ | ✅ |
| Professional Reports | ❌ | Partial | ❌ | ❌ | ✅ |
| CLI-first | ✅ | ❌ | ✅ | ✅ | ✅ |

**Nobody has built this combination. WebBreaker is the unified toolkit with AI.**

---

## ⚠️ Ethical Safeguards

- **Authorization header:** Every scan requires `--auth` flag confirming authorized testing
- **Scope enforcement:** Hard scope boundaries, no scanning outside declared targets
- **Rate limiting:** Default conservative rates to avoid DoS
- **No destructive payloads:** Detection-focused, exploitation limited to proof-of-concept
- **Audit logging:** Full chain-of-custody for all actions (legal compliance)
- **Disclaimer:** Built into CLI, API responses, and reports

---

## 📋 Build Phases (Execution Order)

| Phase | Scope | Target |
|-------|-------|--------|
| **Phase 1** | CLI + all 10 scanner modules + payloads | Full scanning capability |
| **Phase 2** | Fastify API + AI triage + WebSocket | API + AI integration |
| **Phase 3** | React dashboard + D3 visualizations | Visual interface |
| **Phase 4** | Portfolio integrations + STIX + reports + Docker | Polish & integration |

Each phase = one build session, ~3-5 hours of focused work.

---

## ✅ Review Checklist

- [ ] Does the module list cover everything you want?
- [ ] Is the AI triage approach right (Ollama local vs. cloud API)?
- [ ] Should we add any modules? (SSRF? Open Redirect? XXE? IDOR?)
- [ ] Tech stack preferences — any changes?
- [ ] Priority order of phases — good as-is?
- [ ] Any features you want cut to keep scope tight?
- [ ] Any features you want added?
- [ ] Ready to build?

---

_This spec is yours to refine. Once approved, we build._