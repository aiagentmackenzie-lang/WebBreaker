/**
 * WebBreaker API Server — Fastify REST API + WebSocket
 * Provides programmatic access to scans, findings, reports, and AI triage.
 */

import Fastify from 'fastify';
import cors from '@fastify/cors';
import websocket from '@fastify/websocket';
import Database from 'better-sqlite3';
import { v4 as uuidv4 } from 'uuid';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ─── Database ──────────────────────────────────────────────────────
const DB_PATH = process.env.WEBBREAKER_DB || path.join(__dirname, '..', 'webbreaker.db');

let db;
try {
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
} catch {
  db = new Database(DB_PATH);
}

db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    config TEXT NOT NULL,
    status TEXT DEFAULT 'running',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    findings_count INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    url TEXT NOT NULL,
    parameter TEXT NOT NULL,
    payload TEXT NOT NULL,
    evidence TEXT NOT NULL,
    request TEXT DEFAULT '',
    response TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    confidence REAL DEFAULT 1.0,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
  );
  CREATE TABLE IF NOT EXISTS recon (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    status_code INTEGER,
    content_length INTEGER,
    content_type TEXT,
    tech TEXT DEFAULT '',
    forms TEXT DEFAULT '[]',
    links TEXT DEFAULT '[]',
    params TEXT DEFAULT '[]',
    depth INTEGER DEFAULT 0,
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
  );
  CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
  CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
  CREATE INDEX IF NOT EXISTS idx_recon_scan ON recon(scan_id);
`);

// ─── Prepared statements ───────────────────────────────────────────
const stmts = {
  createScan: db.prepare(`INSERT INTO scans (id, target, config, started_at) VALUES (?, ?, ?, ?)`),
  updateScan: db.prepare(`UPDATE scans SET status=?, findings_count=?, completed_at=? WHERE id=?`),
  getScan: db.prepare(`SELECT * FROM scans WHERE id=?`),
  listScans: db.prepare(`SELECT * FROM scans ORDER BY started_at DESC`),
  deleteScan: db.prepare(`DELETE FROM scans WHERE id=?`),
  deleteFindings: db.prepare(`DELETE FROM findings WHERE scan_id=?`),
  deleteRecon: db.prepare(`DELETE FROM recon WHERE scan_id=?`),
  insertFinding: db.prepare(`INSERT INTO findings (scan_id, type, severity, url, parameter, payload, evidence, request, response, remediation, confidence, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
  getFindings: db.prepare(`SELECT * FROM findings WHERE scan_id=? ORDER BY id`),
  getFindingsBySeverity: db.prepare(`SELECT * FROM findings WHERE scan_id=? AND severity=? ORDER BY id`),
  getRecon: db.prepare(`SELECT * FROM recon WHERE scan_id=? ORDER BY depth, id`),
  insertRecon: db.prepare(`INSERT INTO recon (scan_id, url, method, status_code, content_length, content_type, tech, forms, links, params, depth, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
};

// ─── Fastify Server ────────────────────────────────────────────────
const app = Fastify({ logger: true });

await app.register(cors, { origin: true });
await app.register(websocket);

// ─── WebSocket — live scan updates ─────────────────────────────────
const scanSubscribers = new Map(); // scanId -> Set<WebSocket>

app.register(async function (fastify) {
  fastify.get('/ws', { websocket: true }, (conn, req) => {
    conn.socket.on('message', (msg) => {
      try {
        const data = JSON.parse(msg.toString());
        if (data.type === 'subscribe' && data.scanId) {
          if (!scanSubscribers.has(data.scanId)) scanSubscribers.set(data.scanId, new Set());
          scanSubscribers.get(data.scanId).add(conn.socket);
          conn.socket.scanId = data.scanId;
        }
      } catch { /* ignore malformed messages */ }
    });

    conn.socket.on('close', () => {
      if (conn.socket.scanId) {
        const subs = scanSubscribers.get(conn.socket.scanId);
        if (subs) { subs.delete(conn.socket); if (subs.size === 0) scanSubscribers.delete(conn.socket.scanId); }
      }
    });
  });
});

function broadcastScanUpdate(scanId, data) {
  const subs = scanSubscribers.get(scanId);
  if (subs) {
    const msg = JSON.stringify(data);
    for (const ws of subs) {
      try { ws.send(msg); } catch { /* socket closed */ }
    }
  }
}

// ─── Routes ───────────────────────────────────────────────────────

// POST /scan — Start a new scan
app.post('/scan', async (req, reply) => {
  const { target, modules, depth, threads, timeout, delay, proxy, authHeader, cookies, scope, stealth, rateLimit } = req.body || {};

  if (!target) return reply.code(400).send({ error: 'target is required' });

  const scanId = uuidv4().slice(0, 8);
  const config = JSON.stringify({ modules: modules || 'all', depth: depth || 3, threads: threads || 20 });
  stmts.createScan.run(scanId, target, config, new Date().toISOString());

  // Spawn Python scanner process
  const cliPath = path.join(__dirname, '..', 'cli.py');
  const args = ['scan', target, '--auth', '--output', '/dev/stdout',
    '--modules', (modules || 'all').toString(),
    '--depth', String(depth || 3),
    '--threads', String(threads || 20),
    '--db', DB_PATH,
  ];
  if (proxy) args.push('--proxy', proxy);
  if (stealth) args.push('--stealth');
  if (rateLimit) args.push('--rate-limit', String(rateLimit));

  const proc = spawn('python3', [cliPath, ...args], { detached: true, stdio: 'pipe' });

  let output = '';
  proc.stdout?.on('data', (d) => {
    const chunk = d.toString();
    output += chunk;
    broadcastScanUpdate(scanId, { type: 'progress', data: chunk });
  });
  proc.stderr?.on('data', (d) => {
    output += d.toString();
  });

  proc.on('close', (code) => {
    const status = code === 0 ? 'completed' : code === 1 ? 'completed_with_high' : 'error';
    // Count findings from DB
    const findings = stmts.getFindings.all(scanId);
    stmts.updateScan.run(status, findings.length, new Date().toISOString(), scanId);
    broadcastScanUpdate(scanId, { type: 'complete', status, findingsCount: findings.length });
  });

  proc.unref();
  return { scanId, target, status: 'running' };
});

// GET /scan/:id — Get scan status
app.get('/scan/:id', async (req, reply) => {
  const scan = stmts.getScan.get(req.params.id);
  if (!scan) return reply.code(404).send({ error: 'Scan not found' });
  const findings = stmts.getFindings.all(req.params.id);
  return { ...scan, config: JSON.parse(scan.config), findingsCount: findings.length };
});

// GET /scan/:id/findings — Get findings for a scan
app.get('/scan/:id/findings', async (req, reply) => {
  const { severity } = req.query || {};
  const findings = severity
    ? stmts.getFindingsBySeverity.all(req.params.id, severity.toUpperCase())
    : stmts.getFindings.all(req.params.id);
  return findings;
});

// GET /scan/:id/recon — Get recon data for a scan
app.get('/scan/:id/recon', async (req, reply) => {
  const recon = stmts.getRecon.all(req.params.id);
  return recon.map(r => ({
    ...r,
    forms: JSON.parse(r.forms || '[]'),
    links: JSON.parse(r.links || '[]'),
    params: JSON.parse(r.params || '[]'),
  }));
});

// POST /scan/:id/report — Generate report
app.post('/scan/:id/report', async (req, reply) => {
  const scan = stmts.getScan.get(req.params.id);
  if (!scan) return reply.code(404).send({ error: 'Scan not found' });
  const findings = stmts.getFindings.all(req.params.id);
  const recon = stmts.getRecon.all(req.params.id);
  const { format = 'json' } = req.body || {};

  const report = {
    scanId: req.params.id,
    target: scan.target,
    status: scan.status,
    startedAt: scan.started_at,
    completedAt: scan.completed_at,
    totalFindings: findings.length,
    bySeverity: {},
    byType: {},
    urlsDiscovered: recon.length,
    findings,
  };

  for (const f of findings) {
    report.bySeverity[f.severity] = (report.bySeverity[f.severity] || 0) + 1;
    report.byType[f.type] = (report.byType[f.type] || 0) + 1;
  }

  return report;
});

// GET /scans — List all scans
app.get('/scans', async () => {
  return stmts.listScans.all();
});

// DELETE /scan/:id — Delete a scan
app.delete('/scan/:id', async (req, reply) => {
  stmts.deleteFindings.run(req.params.id);
  stmts.deleteRecon.run(req.params.id);
  const result = stmts.deleteScan.run(req.params.id);
  return { deleted: result.changes > 0 };
});

// GET /dashboard/stats — Aggregate statistics
app.get('/dashboard/stats', async () => {
  const scans = stmts.listScans.all();
  const totalScans = scans.length;
  const completedScans = scans.filter(s => s.status !== 'running').length;
  const totalFindings = scans.reduce((sum, s) => sum + s.findings_count, 0);

  // Recent findings across all scans
  const recentFindings = db.prepare(`
    SELECT f.* FROM findings f
    JOIN scans s ON f.scan_id = s.id
    ORDER BY f.id DESC LIMIT 50
  `).all();

  const bySeverity = {};
  for (const f of recentFindings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  }

  return {
    totalScans,
    completedScans,
    totalFindings,
    recentFindings,
    bySeverity,
  };
});

// POST /scan/:id/triage — AI-powered triage
app.post('/scan/:id/triage', async (req, reply) => {
  const findings = stmts.getFindings.all(req.params.id);
  if (!findings.length) return { error: 'No findings to triage' };

  // Try to call Ollama
  try {
    const response = await fetch('http://localhost:11434/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: req.body?.model || 'webbreaker-triage',
        messages: [
          { role: 'system', content: 'You are a senior web security analyst. Respond in JSON only.' },
          { role: 'user', content: `Triage these findings and return JSON with prioritized array, false_positives array, attack_narrative string, remediation_priority array, executive_summary string:\n${JSON.stringify(findings.slice(0, 20))}` },
        ],
        stream: false,
      }),
    });
    const data = await response.json();
    return { aiTriaged: true, analysis: data.message?.content || data };
  } catch {
    // Fallback: rule-based triage
    const prioritized = findings.map((f, i) => ({
      index: i,
      priority: ['CRITICAL', 'HIGH'].includes(f.severity) ? 'P1' : f.severity === 'MEDIUM' ? 'P2' : 'P3',
      reason: `Severity: ${f.severity}, Confidence: ${f.confidence}`,
    }));

    const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = findings.filter(f => f.severity === 'HIGH').length;

    return {
      aiTriaged: false,
      analysis: {
        prioritized,
        false_positives: findings.filter((f, i) => f.confidence < 0.5).map((f, i) => ({ index: i, reason: 'Low confidence' })),
        attack_narrative: 'AI unavailable. Review findings manually based on priority.',
        remediation_priority: prioritized.filter(p => p.priority === 'P1').slice(0, 5).map((p, i) => ({ order: i + 1, finding_index: p.index, action: findings[p.index].remediation })),
        executive_summary: `Assessment found ${findings.length} findings: ${criticalCount} critical, ${highCount} high. Prioritize critical and high findings immediately.`,
      },
    };
  }
});

// ─── Start server ─────────────────────────────────────────────────
const PORT = process.env.WEBBREAKER_PORT || 3100;
const HOST = process.env.WEBBREAKER_HOST || '0.0.0.0';

try {
  await app.listen({ port: PORT, host: HOST });
  console.log(`🔥 WebBreaker API running on http://${HOST}:${PORT}`);
  console.log(`📡 WebSocket: ws://${HOST}:${PORT}/ws`);
} catch (err) {
  console.error('Failed to start:', err);
  process.exit(1);
}