import type { Env } from './worker';

// Keys for usage counters in KV
const STATS_KEY = 'stats:global';
const STATS_DAILY_PREFIX = 'stats:daily:';
const ERRORS_KEY = 'stats:errors';
const LEGACY_TOP_DOMAINS_KEY = 'stats:top-domains';
const LEGACY_CLEANUP_KEY = 'stats:privacy-cleanup-v2';

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
  status: number;
  detail: string;
}


function scrubIdentifier(value: string): string {
  return value
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[ip]')
    .replace(/(?<![A-Za-z0-9-])([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?![A-Za-z0-9-])/g, '[domain]')
    .replace(/\b[0-9a-fA-F:]{2,}:[0-9a-fA-F:.]{2,}\b/g, '[ip]');
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

export async function cleanupLegacyTargetStats(env: Env): Promise<void> {
  const done = await env.CACHE.get(LEGACY_CLEANUP_KEY);
  if (done) return;

  await Promise.all([
    env.CACHE.delete(LEGACY_TOP_DOMAINS_KEY),
    env.CACHE.delete(ERRORS_KEY),
  ]);
  await env.CACHE.put(LEGACY_CLEANUP_KEY, '1');
}

export async function trackScan(env: Env, event: {
  target: string;
  cache_hit: boolean;
  error?: boolean;
  rate_limited?: boolean;
  status?: number;
  detail?: string;
}): Promise<void> {
  try {
    await cleanupLegacyTargetStats(env);

    // Global stats
    const raw = await env.CACHE.get(STATS_KEY);
    const stats: GlobalStats = raw ? JSON.parse(raw) : {
      total_scans: 0, cache_hits: 0, cache_misses: 0,
      rate_limited: 0, errors: 0, last_scan: null,
    };

    stats.total_scans++;
    if (event.rate_limited) stats.rate_limited++;
    else if (event.error) stats.errors++;
    else if (event.cache_hit) stats.cache_hits++;
    else stats.cache_misses++;
    stats.last_scan = new Date().toISOString();

    await env.CACHE.put(STATS_KEY, JSON.stringify(stats));

    // Daily stats
    const d = today();
    const dailyKey = STATS_DAILY_PREFIX + d;
    const dailyRaw = await env.CACHE.get(dailyKey);
    const daily: DailyStats = dailyRaw ? JSON.parse(dailyRaw) : {
      date: d, scans: 0, cache_hits: 0, cache_misses: 0,
      rate_limited: 0, errors: 0,
    };

    daily.scans++;
    if (event.rate_limited) daily.rate_limited++;
    else if (event.error) daily.errors++;
    else if (event.cache_hit) daily.cache_hits++;
    else daily.cache_misses++;

    await env.CACHE.put(dailyKey, JSON.stringify(daily), { expirationTtl: 86400 * 30 }); // 30d retention
    // Error log (keep last 50)
    if (event.error && event.detail) {
      const errRaw = await env.CACHE.get(ERRORS_KEY);
      const errors: ErrorLog[] = errRaw ? JSON.parse(errRaw) : [];
      errors.unshift({
        ts: new Date().toISOString(),
        status: event.status || 0,
        detail: scrubIdentifier(event.detail),
      });
      await env.CACHE.put(ERRORS_KEY, JSON.stringify(errors.slice(0, 50)));
    }
  } catch {
    // Stats tracking should never break the request
  }
}

export async function handleUsage(request: Request, env: Env): Promise<Response> {
  // Admin key auth — accept ?key=, Bearer token, or Basic auth (password = ADMIN_KEY)
  const url = new URL(request.url);
  const authHeader = request.headers.get('Authorization') || '';
  let key = url.searchParams.get('key') || '';

  // Bearer token
  if (!key && authHeader.startsWith('Bearer ')) {
    key = authHeader.slice(7);
  }

  // HTTP Basic Auth (browser native prompt) — password field is the admin key
  if (!key && authHeader.startsWith('Basic ')) {
    try {
      const decoded = atob(authHeader.slice(6));
      key = decoded.split(':').slice(1).join(':');
    } catch { /* invalid base64 */ }
  }
  
  if (key !== env.ADMIN_KEY) {
    return new Response('Unauthorized', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="Usage Dashboard"' },
    });
  }

  await cleanupLegacyTargetStats(env);

  const [globalRaw, errRaw] = await Promise.all([
    env.CACHE.get(STATS_KEY),
    env.CACHE.get(ERRORS_KEY),
  ]);

  const stats: GlobalStats = globalRaw ? JSON.parse(globalRaw) : {
    total_scans: 0, cache_hits: 0, cache_misses: 0,
    rate_limited: 0, errors: 0, last_scan: null,
  };
  const errors: ErrorLog[] = errRaw ? JSON.parse(errRaw) : [];

  // Get last 7 days of daily stats
  const dailyStats: DailyStats[] = [];
  for (let i = 0; i < 7; i++) {
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

  const accept = request.headers.get('Accept') || '';
  if (accept.includes('application/json') || !accept.includes('text/html')) {
    return new Response(JSON.stringify({
      global: stats,
      daily: dailyStats,
      recent_errors: errors.slice(0, 10),
    }, null, 2) + '\n', {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // HTML dashboard
  const hitRate = stats.total_scans > 0
    ? ((stats.cache_hits / stats.total_scans) * 100).toFixed(1)
    : '0';
  const dailyRows = dailyStats.map(d =>
    `<div class="r"><span class="k">${d.date}</span><span class="v">${d.scans} scans · ${d.cache_hits} hits · ${d.cache_misses} miss · ${d.rate_limited} rl · ${d.errors} err</span></div>`
  ).join('');

  const errorRows = errors.slice(0, 10).map(e =>
    `<div class="r"><span class="k" style="width:170px">${e.ts.slice(0, 19)}</span><span class="v">${e.status} ${esc(e.detail).slice(0, 80)}</span></div>`
  ).join('');

  return new Response(`<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Usage — certs.lol</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#d8d8e0;font-family:'Inter',system-ui,sans-serif;-webkit-font-smoothing:antialiased}
.page{max-width:720px;margin:0 auto;padding:2rem 1.5rem}
h1{font-size:1.5rem;font-weight:800;letter-spacing:-0.03em;margin-bottom:0.5rem}
h1 .t{color:#9b8afb}
.sub{color:#5c5c6b;font-size:12px;font-family:'JetBrains Mono',monospace;margin-bottom:2rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:2rem}
.card{background:#111116;border:1px solid #1c1c24;border-radius:8px;padding:14px 16px}
.card .label{font-size:10px;text-transform:uppercase;letter-spacing:0.1em;color:#5c5c6b;font-family:'JetBrains Mono',monospace;margin-bottom:4px}
.card .val{font-size:24px;font-weight:800;color:#38d9a9;font-family:'JetBrains Mono',monospace}
.card .val.warn{color:#fbbf24}.card .val.err{color:#f87171}.card .val.inf{color:#6ea8fe}
.section{margin-top:1.75rem}
.sec-label{font-size:10px;text-transform:uppercase;letter-spacing:0.12em;color:#5c5c6b;font-family:'JetBrains Mono',monospace;font-weight:600;margin-bottom:6px;padding-bottom:6px;border-bottom:1px solid #1c1c24}
.r{display:flex;font-size:12px;line-height:2;font-family:'JetBrains Mono',monospace}
.r .k{color:#5c5c6b;width:155px;flex-shrink:0}
.r .v{color:#d8d8e0}
</style></head><body>
<div class="page">
<h1>certs<span class="t">.lol</span> usage</h1>
<div class="sub">last scan: ${stats.last_scan ? stats.last_scan.slice(0, 19).replace('T', ' ') + ' UTC' : 'never'}</div>

<div class="cards">
  <div class="card"><div class="label">Total Scans</div><div class="val">${stats.total_scans.toLocaleString()}</div></div>
  <div class="card"><div class="label">Cache Hits</div><div class="val inf">${stats.cache_hits.toLocaleString()}</div></div>
  <div class="card"><div class="label">Cache Misses</div><div class="val">${stats.cache_misses.toLocaleString()}</div></div>
  <div class="card"><div class="label">Hit Rate</div><div class="val inf">${hitRate}%</div></div>
  <div class="card"><div class="label">Rate Limited</div><div class="val warn">${stats.rate_limited.toLocaleString()}</div></div>
  <div class="card"><div class="label">Errors</div><div class="val err">${stats.errors.toLocaleString()}</div></div>
</div>

<div class="section">
  <div class="sec-label">Last 7 Days</div>
  ${dailyRows}
</div>
${errors.length > 0 ? `<div class="section">
  <div class="sec-label">Recent Errors</div>
  ${errorRows}
</div>` : ''}

</div></body></html>`, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
