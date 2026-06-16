// ─── Public Status Page ──────────────────────────────────────────────
// Server-rendered HTML showing service health inferred from KV stats.
// Served at /status — no auth, no client JS.

import type { Env } from './worker';

const STATS_KEY = 'stats:global';
const STATS_DAILY_PREFIX = 'stats:daily:';
const ERRORS_KEY = 'stats:errors';

interface GlobalStats {
  total_scans: number;
  cache_hits: number;
  cache_misses: number;
  rate_limited: number;
  errors: number;
  last_scan: string | null;
}

interface DailyStats {
  date: string;
  scans: number;
  cache_hits: number;
  cache_misses: number;
  rate_limited: number;
  errors: number;
}

interface ErrorLog {
  ts: string;
  target: string;
  status: number;
  detail: string;
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function timeAgo(iso: string | null): string {
  if (!iso) return 'never';
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function statusColor(errors: number): string {
  if (errors === 0) return '#22c55e';
  if (errors <= 3) return '#eab308';
  return '#ef4444';
}

function statusLabel(errors: number): string {
  if (errors === 0) return 'Operational';
  if (errors <= 3) return 'Degraded';
  return 'Errors Detected';
}

function barColor(errors: number): string {
  if (errors === 0) return '#22c55e33';
  if (errors <= 2) return '#eab308';
  return '#ef4444';
}

export async function renderStatusPage(env: Env): Promise<Response> {
  const [globalRaw, errRaw] = await Promise.all([
    env.CACHE.get(STATS_KEY),
    env.CACHE.get(ERRORS_KEY),
  ]);

  const stats: GlobalStats = globalRaw ? JSON.parse(globalRaw) : {
    total_scans: 0, cache_hits: 0, cache_misses: 0,
    rate_limited: 0, errors: 0, last_scan: null,
  };
  const errors: ErrorLog[] = errRaw ? JSON.parse(errRaw) : [];

  // Last 7 days of daily stats
  const dailyStats: DailyStats[] = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().slice(0, 10);
    const dayRaw = await env.CACHE.get(STATS_DAILY_PREFIX + dateStr);
    if (dayRaw) {
      dailyStats.push(JSON.parse(dayRaw));
    } else {
      dailyStats.push({ date: dateStr, scans: 0, cache_hits: 0, cache_misses: 0, rate_limited: 0, errors: 0 });
    }
  }

  // Errors in last 24h
  const oneDayAgo = Date.now() - 86_400_000;
  const recentErrors = errors.filter(e => new Date(e.ts).getTime() > oneDayAgo);
  const errors24h = recentErrors.length;

  const overallColor = statusColor(errors24h);
  const overallLabel = errors24h === 0 ? 'All Systems Operational'
    : errors24h <= 3 ? 'Degraded Performance' : 'Service Disruptions Detected';

  // Max scans in a day for bar scaling
  const maxScans = Math.max(1, ...dailyStats.map(d => d.scans));

  const dayBars = dailyStats.map(d => {
    const h = Math.max(4, Math.round((d.scans / maxScans) * 48));
    const c = barColor(d.errors);
    const title = `${d.date} — ${d.scans} scans, ${d.errors} errors`;
    return `<div class="bar-col"><div class="bar" style="height:${h}px;background:${c}" title="${esc(title)}"></div><div class="bar-date">${d.date.slice(5)}</div></div>`;
  }).join('');

  const lastError = errors.length > 0 ? errors[0] : null;
  const lastErrorHtml = lastError
    ? `<div class="last-err">Last error: ${timeAgo(lastError.ts)} — HTTP ${lastError.status}: ${esc(lastError.detail).slice(0, 80)}</div>`
    : '';

  // Dependencies
  const probeUrl = env.PROBE_URL || 'https://yoke-probe.fly.dev';
  const deps = [
    { name: 'TLS Probe', url: probeUrl, desc: 'Go binary on Fly.io — TLS handshake scanning' },
    { name: 'Cloudflare KV', url: 'KV (managed)', desc: 'Result caching and stats storage' },
  ];

  const depRows = deps.map(dep => {
    // Infer probe health from error data
    const probeErrors = dep.name === 'TLS Probe' ? errors24h : 0;
    const sc = statusColor(probeErrors);
    const sl = statusLabel(probeErrors);
    return `<div class="dep-row">
      <div class="dep-header">
        <div class="dep-name"><span class="dot" style="background:${sc}"></span><strong>${esc(dep.name)}</strong><span class="dep-url">${esc(dep.url)}</span></div>
        <div class="dep-status" style="color:${sc}">${sl}</div>
      </div>
      <div class="dep-desc">${esc(dep.desc)}</div>
    </div>`;
  }).join('');

  const html = `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Status — certs.lol</title>
<meta name="description" content="Real-time service status for certs.lol TLS scanning.">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#0a0a0f;--surface:#111116;--border:#1c1c24;--text:#d8d8e0;--muted:#5c5c6b;--accent:#9b8afb;--ok:#22c55e;--warn:#eab308;--err:#ef4444}
@media(prefers-color-scheme:light){:root{--bg:#fafafa;--surface:#fff;--border:#e5e5e5;--text:#171717;--muted:#737373;--accent:#7c3aed;--ok:#16a34a;--warn:#ca8a04;--err:#dc2626}}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'Inter',system-ui,sans-serif;-webkit-font-smoothing:antialiased;line-height:1.5}
.page{max-width:720px;margin:0 auto;padding:2rem 1.5rem}
h1{font-size:1.5rem;font-weight:800;letter-spacing:-0.03em;margin-bottom:0.25rem}
h1 .t{color:var(--accent)}
.overall{display:inline-flex;align-items:center;gap:0.5rem;font-size:1.1rem;font-weight:500;margin:0.5rem 0}
.dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;display:inline-block}
.sub{color:var(--muted);font-size:12px;font-family:'JetBrains Mono',monospace;margin-bottom:2rem}
.section{margin-top:1.75rem}
.sec-label{font-size:10px;text-transform:uppercase;letter-spacing:0.12em;color:var(--muted);font-family:'JetBrains Mono',monospace;font-weight:600;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)}
.bars-row{display:flex;gap:4px;align-items:flex-end;margin-bottom:0.5rem}
.bar-col{display:flex;flex-direction:column;align-items:center;flex:1}
.bar{border-radius:3px;min-width:8px;width:100%;cursor:default;transition:opacity 0.15s}
.bar:hover{opacity:0.7}
.bar-date{font-size:9px;color:var(--muted);font-family:'JetBrains Mono',monospace;margin-top:4px}
.dep-row{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem;margin-bottom:0.75rem}
.dep-header{display:flex;justify-content:space-between;align-items:center}
.dep-name{display:flex;align-items:center;gap:0.5rem;font-size:0.9rem}
.dep-url{color:var(--muted);font-size:0.75rem;font-family:'JetBrains Mono',monospace}
.dep-status{font-size:0.8rem;font-weight:500}
.dep-desc{font-size:0.75rem;color:var(--muted);margin-top:0.3rem}
.last-err{font-family:'JetBrains Mono',monospace;font-size:0.7rem;margin-top:0.75rem;color:var(--err)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:0.5rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px 16px}
.card .label{font-size:10px;text-transform:uppercase;letter-spacing:0.1em;color:var(--muted);font-family:'JetBrains Mono',monospace;margin-bottom:4px}
.card .val{font-size:24px;font-weight:800;font-family:'JetBrains Mono',monospace}
.card .val.ok{color:var(--ok)}.card .val.warn{color:var(--warn)}.card .val.err{color:var(--err)}.card .val.accent{color:var(--accent)}
footer{margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border);font-size:0.75rem;color:var(--muted);display:flex;justify-content:space-between;flex-wrap:wrap;gap:0.5rem}
footer a{color:var(--accent);text-decoration:none}
@media(max-width:600px){.dep-url{display:none}.page{padding:1rem}}
</style></head><body>
<div class="page">
<h1>certs<span class="t">.lol</span> status</h1>
<div class="overall"><span class="dot" style="background:${overallColor}"></span>${esc(overallLabel)}</div>
<div class="sub">last scan: ${timeAgo(stats.last_scan)} · updated ${new Date().toISOString().slice(0, 19)} UTC</div>

<div class="section">
  <div class="sec-label">Dependencies</div>
  ${depRows}
  ${lastErrorHtml}
</div>

<div class="section">
  <div class="sec-label">Last 7 Days</div>
  <div class="bars-row">${dayBars}</div>
  <div class="cards">
    <div class="card"><div class="label">Total Scans</div><div class="val accent">${stats.total_scans.toLocaleString()}</div></div>
    <div class="card"><div class="label">Errors (24h)</div><div class="val ${errors24h === 0 ? 'ok' : errors24h <= 3 ? 'warn' : 'err'}">${errors24h}</div></div>
    <div class="card"><div class="label">Error Rate</div><div class="val ${stats.errors === 0 ? 'ok' : 'warn'}">${stats.total_scans > 0 ? ((stats.errors / stats.total_scans) * 100).toFixed(1) : '0'}%</div></div>
  </div>
</div>

<footer>
  <span><a href="/">certs.lol</a> · <a href="/about">about</a> · <a href="/cli">cli</a> · <a href="/api/docs">api</a></span>
  <span><a href="https://ns.lol">ns.lol</a> · <a href="https://yoke.lol">yoke.lol</a></span>
</footer>
</div></body></html>`;

  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'public, max-age=60',
    },
  });
}
