# 🔥 WebBreaker — Web Application Penetration Testing Toolkit

**For authorized security assessments only.**

WebBreaker is an all-in-one web application pentest toolkit that combines reconnaissance, vulnerability scanning, exploitation, AI-assisted triage, and professional reporting into a single CLI-first workflow.

## Features

- **11 Scanner Modules:** SQLi, XSS, CSRF, Command Injection, LFI, RFI, Dir Brute Force, Parameter Fuzzing, Security Headers, Session Analysis, and Recon/Spider
- **Recon & Spidering:** Recursive web crawler, tech fingerprinting, form/parameter extraction
- **AI-Assisted Triage:** Ollama-powered finding prioritization, false positive reduction, payload mutation (falls back to rule-based when Ollama is unavailable)
- **React Dashboard:** Real-time scan monitoring, findings table, recon viewer, AI triage panel
- **STIX 2.1 Export:** JSON and STIX report generation via API
- **Portfolio Integrations:** Data formatters for GHOSTWIRE, HATCHERY, DEADDROP, HONEYTRAP (stubs — no live network calls)
- **CLI-First:** Full functionality from the terminal, dashboard is optional

## Quick Start

```bash
# Install dependencies
pip3 install -r requirements.txt

# Run a scan
python3 cli.py scan https://target.com --auth

# Run specific modules
python3 cli.py scan https://target.com --auth -m sqli,xss,csrf

# Stealth mode
python3 cli.py scan https://target.com --auth --stealth

# Quick fingerprint
python3 cli.py fingerprint https://target.com --auth

# View past scans
python3 cli.py scans

# View findings
python3 cli.py findings <scan_id>

# Generate report
python3 cli.py report <scan_id>
```

## Scanner Modules

| Module | Flag | What It Detects |
|--------|------|----------------|
| Recon | `recon` | URLs, forms, tech stack, parameters |
| SQL Injection | `sqli` | Error, boolean, time-based, UNION, stacked, OOB + WAF bypass |
| XSS | `xss` | Reflected, stored, DOM-based + WAF bypass |
| CSRF | `csrf` | Missing tokens, weak tokens, SameSite, PoC builder |
| Command Injection | `cmdi` | OS command injection (Linux + Windows) + filter bypass |
| LFI | `lfi` | Path traversal, null byte, PHP wrappers, log poisoning |
| RFI | `rfi` | Remote file inclusion with callback support |
| Dir Brute | `dirbrute` | Hidden directories, sensitive files, recursive |
| Fuzz | `fuzz` | Hidden parameters, overflow, type juggling, template injection |
| Headers | `headers` | 25+ security headers, CSP bypass analysis, A-F grading |
| Session | `session` | Cookie flags, SameSite, entropy, fixation, HSTS |

## Dashboard

```bash
# Start the API
cd api && npm install && node server.js

# Start the dashboard (dev mode)
cd dashboard && npm install && npm run dev
```

- Dashboard: http://localhost:5173
- API: http://localhost:3100
- WebSocket: ws://localhost:3100/ws

For production, use the provided Dockerfiles for API and Dashboard (see `api/Dockerfile` and `dashboard/Dockerfile`).

> **Note:** Use the provided `docker-compose.yml` for local development, or the Dockerfiles directly for production deployment.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/scan` | Start a new scan |
| GET | `/scan/:id` | Get scan status |
| GET | `/scan/:id/findings` | Get findings |
| GET | `/scan/:id/recon` | Get recon data |
| POST | `/scan/:id/report` | Generate report (JSON or STIX) |
| POST | `/scan/:id/triage` | AI-powered triage |
| GET | `/scans` | List all scans |
| DELETE | `/scan/:id` | Delete a scan |
| GET | `/dashboard/stats` | Aggregate statistics |
| WS | `/ws` | Real-time scan updates |

## AI Triage Setup

AI triage uses a local Ollama model. By default, it tries `webbreaker-triage` (you need to create or pull a model):

```bash
# Pull a recommended model
ollama pull llama3.2

# Or create a custom model
ollama create webbreaker-triage -f Modelfile
```

When Ollama is unavailable, triage falls back to rule-based prioritization.

## Ethical Use

- **Authorization required:** `--auth` flag mandatory for all scans
- **Scope enforcement:** No scanning outside declared target
- **Rate limiting:** Conservative defaults to avoid DoS
- **Detection-focused:** Exploitation limited to proof-of-concept
- **Audit logging:** Full chain-of-custody for legal compliance

## Tech Stack

| Layer | Technology |
|-------|-----------|
| CLI | Python 3.12+ + Click + Rich |
| Scanner Engine | Python (httpx, BeautifulSoup, lxml, aiohttp) |
| AI | Ollama (local LLM, optional) |
| API | Node.js + Fastify + WebSocket + better-sqlite3 |
| Dashboard | React 19 + Vite + Tailwind 4 |
| Database | SQLite (WAL mode) |
| Export | STIX 2.1, HTML, PDF |
| Reports | Jinja2 HTML + WeasyPrint PDF |

## License

MIT — For authorized security assessments only.