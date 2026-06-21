import type { ScanResult } from './worker';

export interface RateLimitInfo {
  remaining: number;
  limit: number;
  reset?: number;
}

export function html(data?: ScanResult, error?: string, rl?: RateLimitInfo, nonce?: string): string {
  const title = data ? `${data.target} — certs.lol` : 'certs.lol — Fast, API-first TLS scanning.';
  const desc = data ? `TLS scan: ${data.target} scored ${data.grade}. ${data.probe_ms}ms.` : 'Fast, API-first TLS scanning. No accounts, no tracking, no nonsense.';
  const targetVal = data?.target || '';
  const isIP = data?.is_ip || false;
  const nonceAttr = nonce ? ` nonce="${nonce}"` : '';

  const hooks = [
    ["is {d}'s email spoofable?", "check on yoke.lol →"],
    ["has {d} been breached?", "check on yoke.lol →"],
    ["what tech stack does {d} run?", "see on yoke.lol →"],
    ["is {d} accessible?", "check on yoke.lol →"],
    ["how fast is {d}?", "see on yoke.lol →"],
    ["can search engines find {d}?", "check on yoke.lol →"],
  ];
  const randomHook = hooks[Math.floor(Math.random() * hooks.length)];

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(desc)}">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:type" content="website">
<meta property="og:url" content="https://certs.lol${data ? '/' + esc(data.target) : ''}">
<meta property="og:image" content="https://certs.lol/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${esc(title)}">
<meta name="twitter:description" content="${esc(desc)}">
<meta name="twitter:image" content="https://certs.lol/og.png">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="canonical" href="https://certs.lol${data ? '/' + esc(data.target) : ''}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<script type="application/ld+json"${nonceAttr}>${JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'WebApplication',
    name: 'certs.lol',
    url: 'https://certs.lol',
    description: 'Fast, API-first TLS scanning. No accounts, no tracking, no nonsense.',
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Any',
    offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
    author: { '@type': 'Organization', name: 'Yoke', url: 'https://yoke.lol' },
  })}</script>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
:root{--font-mono:'JetBrains Mono',ui-monospace,'Cascadia Code','Source Code Pro',Menlo,Consolas,monospace;--font-sans:'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;--radius:8px;--radius-sm:6px}
body[data-theme="dark"]{
  --bg:#0a0a12;--surface:#15151f;--surface-raised:#1e1e2a;--surface-hover:#26263a;--border:#2a2a3a;--border-muted:#1e1e2a;
  --text:#e0e0ea;--text-secondary:#a8a8b8;--muted:#7a7a8e;--dim:#55556a;--faint:#3a3a4a;
  --accent:#9b8afb;--accent-fg:#0a0a12;--accent-dim:rgba(155,138,251,0.08);--accent-subtle:rgba(155,138,251,0.08);
  --ok:#3fb950;--ok-subtle:rgba(63,185,80,0.08);
  --info:#6ea8fe;--warn:#e5a820;--warn-subtle:rgba(229,168,32,0.08);--err:#f85149;--err-subtle:rgba(248,81,73,0.08);
  --purple:#bc8cff;
}
body[data-theme="light"]{
  --bg:#fafafe;--surface:#f0f0f5;--surface-raised:#e8e8ef;--surface-hover:#dddde6;--border:#d0d0dc;--border-muted:#e0e0ea;
  --text:#1a1a2e;--text-secondary:#4a4a60;--muted:#6a6a80;--dim:#9090a4;--faint:#b8b8c8;
  --accent:#7c3aed;--accent-fg:#ffffff;--accent-dim:rgba(124,58,237,0.06);--accent-subtle:rgba(124,58,237,0.06);
  --ok:#16a34a;--ok-subtle:rgba(22,163,74,0.06);
  --info:#2563eb;--warn:#b58900;--warn-subtle:rgba(181,137,0,0.06);--err:#dc2626;--err-subtle:rgba(220,38,38,0.06);
  --purple:#8250df;
}
html{background:var(--bg)}
body{background:var(--bg);color:var(--text);font-family:var(--font-sans);-webkit-font-smoothing:antialiased;line-height:1.6;transition:background .25s,color .25s}
.page{max-width:640px;margin:0 auto;padding:0 1.5rem}

.hdr{padding:2rem 0 0;display:flex;align-items:baseline;gap:16px}
.logo{font-size:1.5rem;font-weight:800;letter-spacing:-0.04em;text-decoration:none;color:var(--text)}
.logo span{color:var(--accent)}
.tag{font-size:11px;color:var(--dim);font-family:var(--font-mono)}

.theme-toggle{position:fixed;top:16px;right:16px;z-index:100;display:flex;border-radius:var(--radius-sm);overflow:hidden;border:1px solid var(--border);background:var(--surface);font-family:var(--font-mono);font-size:11px}
.theme-opt{padding:5px 10px;cursor:pointer;border:none;background:none;color:var(--dim);transition:all .15s;white-space:nowrap}
.theme-opt.active{background:var(--accent);color:var(--accent-fg);font-weight:600}
.theme-opt:not(.active):hover{color:var(--text)}

.input-wrap{margin-top:2rem;border-bottom:2px solid var(--accent);padding-bottom:10px;font-family:var(--font-mono);font-size:14px;display:flex;align-items:center;transition:border-color .25s;outline:none}
.input-wrap form{display:contents}
.p{color:var(--accent);font-weight:600;margin-right:10px}
.cm{color:var(--accent);font-weight:600}.dm{color:var(--dim)}
.di{background:none;border:none;color:var(--text);font-family:var(--font-mono);font-size:14px;outline:none;flex:1;min-width:80px;caret-color:var(--accent)}
.di::placeholder{color:var(--faint)}
.cur{display:inline-block;width:7px;height:14px;background:var(--accent);animation:b 1.1s step-end infinite;vertical-align:text-bottom;margin-left:1px}
@keyframes b{0%,100%{opacity:.7}50%{opacity:0}}

.grade-block{margin-top:2rem;display:flex;align-items:center;gap:20px}
.grade-letter{font-size:52px;font-weight:800;font-family:var(--font-mono);line-height:1;transition:color .25s}
.grade-A-plus,.grade-A{color:var(--ok)}.grade-B{color:var(--info)}.grade-C{color:var(--warn)}.grade-D,.grade-F{color:var(--err)}
.grade-domain{font-size:18px;font-weight:700;letter-spacing:-0.02em;margin:0}
.grade-meta{font-size:11px;color:var(--dim);font-family:var(--font-mono);margin-top:4px}


.err-block{margin-top:2rem;padding:20px;background:var(--err-subtle);border:1px solid rgba(248,81,73,0.2);border-radius:8px;color:var(--text);font-family:var(--font-sans);font-size:13px;line-height:1.6}
.err-block .err-title{color:var(--err);font-family:var(--font-mono);font-size:14px;font-weight:600;margin:0 0 12px}
.err-block p{margin:8px 0;color:var(--muted)}
.err-block a{color:var(--accent);text-decoration:none}
.err-block a:hover{text-decoration:underline}

.section{margin-top:1.75rem}
.sec-label{font-size:10px;text-transform:uppercase;letter-spacing:0.12em;color:var(--dim);font-family:var(--font-mono);font-weight:600;margin:0 0 6px;padding-bottom:6px;border-bottom:1px solid var(--border);transition:border-color .25s,color .25s}
.r{display:flex;font-size:13px;line-height:2;font-family:var(--font-mono)}
.r .k{color:var(--dim);width:155px;flex-shrink:0}
.r .v{color:var(--text);word-break:break-all}
.r .v.ok{color:var(--ok)}.r .v.hi{color:var(--info);font-weight:600}
.r .v.inf{color:var(--info)}.r .v.off{color:var(--faint)}
.r .v.warn{color:var(--warn)}.r .v.err{color:var(--err)}

.cipher-grid{display:flex;flex-wrap:wrap;gap:4px 8px;margin-top:4px;font-family:var(--font-mono);font-size:11px}
.cipher-grid .c{padding:2px 6px;border-radius:3px}
.cipher-grid .c.strong{background:var(--ok-subtle);color:var(--ok)}
.cipher-grid .c.acceptable{background:var(--accent-dim);color:var(--info)}
.cipher-grid .c.insecure{background:var(--err-subtle);color:var(--err)}
.cipher-grid .c.weak{background:var(--warn-subtle);color:var(--warn)}

.cache-tag{background:var(--accent-dim);color:var(--info);padding:1px 5px;border-radius:3px;font-size:10px;text-transform:uppercase;letter-spacing:0.05em}
.rescan-btn{color:var(--dim);text-decoration:none;font-size:11px;padding:1px 6px;border:1px solid var(--border);border-radius:3px;transition:all .2s}
.rescan-btn:hover{color:var(--accent);border-color:var(--accent);text-decoration:none}

.hook{margin-top:2.25rem;padding:14px 0;border-top:1px solid var(--border);border-bottom:1px solid var(--border);display:flex;align-items:baseline;gap:10px;font-family:var(--font-mono);font-size:12px}
.hook .ar{color:var(--accent);font-size:14px}
.hook .q{color:var(--muted)}
.hook a{color:var(--accent);text-decoration:none;font-weight:500}
.hook a:hover{text-decoration:underline}

.footer{padding:2rem 0 3rem;margin-top:2rem;font-size:10px;color:var(--faint);font-family:var(--font-mono);text-align:center;display:flex;flex-direction:column;align-items:center;gap:10px}
.footer a{color:var(--dim);text-decoration:none;transition:color .2s}
.footer a:hover{color:var(--muted);text-decoration:none}
.footer-links{display:flex;justify-content:center;gap:16px;flex-wrap:wrap}
.footer-links a{color:var(--dim);text-decoration:none}
.footer-links a:hover{color:var(--muted)}
.footer-family{display:flex;justify-content:center;gap:16px}
.footer-family a{color:var(--faint);text-decoration:none;transition:color .2s}
.footer-family a:hover{color:var(--accent)}
.yoke-badge{display:inline-block}
.yoke-badge img{opacity:0.6;transition:opacity .2s;vertical-align:middle}
.yoke-badge:hover img{opacity:1}
.footer-tagline{font-size:10px;color:var(--faint);margin-bottom:2px}
.footer-tagline a{color:var(--dim);text-decoration:none;transition:color .2s}
.footer-tagline a:hover{color:var(--accent)}

.examples{display:flex;gap:8px;justify-content:center;margin-top:20px;flex-wrap:wrap}
.examples a{padding:6px 14px;background:var(--surface);border:1px solid var(--border);border-radius:6px;font-family:var(--font-mono);font-size:0.82rem;color:var(--accent);text-decoration:none;transition:background .2s}
.examples a:hover{background:var(--surface-raised);text-decoration:none}

.skip-nav{position:absolute;left:-9999px;top:0;z-index:200;padding:8px 16px;background:var(--accent);color:var(--accent-fg,#fff);font-family:var(--font-mono);font-size:12px;text-decoration:none;border-radius:0 0 6px 0}
.skip-nav:focus{left:0}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.input-wrap :focus-visible,.input-wrap:focus-visible{outline:none}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}

.show-m{display:none}
@media(max-width:520px){
  .page{padding:0 1rem}
  .hdr{flex-direction:column;gap:4px;padding-top:2rem}
  .input-wrap{font-size:13px;margin-top:1.5rem}.di{font-size:13px}
  .hide-m{display:none}.show-m{display:inline}
  .grade-letter{font-size:38px}.grade-domain{font-size:15px}
  .grade-block{gap:14px;margin-top:1.5rem}
  .section{margin-top:1.5rem}
  .r .k{width:120px;font-size:12px}.r .v{font-size:12px}
  .hook{font-size:11px;flex-wrap:wrap}
  .footer-links,.footer-family{flex-direction:row;gap:16px}
}
/* Rate limit pill */
.rl-pill{position:fixed;bottom:16px;right:16px;background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:6px 14px;font-family:var(--font-mono);font-size:11px;color:var(--dim);z-index:100;cursor:pointer;opacity:0.7;transition:opacity 0.3s,color 0.3s,border-color 0.3s}
.rl-pill.warn{color:var(--warn);border-color:var(--warn);opacity:1}
.rl-pill.danger{color:var(--err);border-color:var(--err);opacity:1}
.rl-detail{display:none;position:fixed;bottom:48px;right:16px;background:var(--surface-raised);border:1px solid var(--border);border-radius:8px;padding:10px 14px;min-width:220px;font-family:var(--font-mono);font-size:12px;color:var(--text);z-index:101;box-shadow:0 8px 24px rgba(0,0,0,0.6)}
.rl-detail.visible{display:block}
.rl-detail .rl-title{font-weight:600;margin-bottom:4px}
.rl-bar{height:4px;border-radius:2px;background:var(--border);margin-bottom:8px;overflow:hidden}
.rl-bar-fill{height:100%;border-radius:2px;transition:width 0.3s}
.rl-detail .rl-info{color:var(--dim);font-size:11px;white-space:pre-line}
</style>
</head>
<body data-theme="dark">

<a href="#main" class="skip-nav">Skip to content</a>
<div class="theme-toggle" role="radiogroup" aria-label="Theme">
  <button class="theme-opt active" role="radio" aria-checked="true" data-theme="dark">Dark</button>
  <button class="theme-opt" role="radio" aria-checked="false" data-theme="light">Light</button>
</div>

<div class="page">
<header class="hdr">
  <a class="logo" href="/" aria-label="certs.lol home">certs<span>.lol</span></a>
  <div class="tag">fast, API-first TLS scanning</div>
</header>

<nav class="input-wrap" aria-label="Domain scan">
  <form action="/" method="get" id="scanForm" role="search">
  <span class="cm" aria-hidden="true">$</span><span class="dm" aria-hidden="true">&nbsp;certs&nbsp;▸&nbsp;</span><label for="scanInput" class="sr-only">Domain or IP to scan</label><input class="di" id="scanInput" type="text" name="q" value="${esc(targetVal)}" placeholder="domain or IP" spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off" inputmode="url" autofocus><span class="cur" aria-hidden="true"></span>
  </form>
</nav>

<main id="main">

${error ? `<div class="err-block">${error}</div>` : ''}
${data ? renderResult(data, randomHook, isIP) : (error ? '' : renderEmpty())}

</main>

<footer class="footer">
  <div class="footer-links"><a href="/cli">cli</a><a href="/api/docs">docs</a><a href="https://github.com/yokedotlol/certs-lol">github</a><a href="/about">about</a><a href="/privacy">privacy</a><a href="/terms">terms</a></div>
  <div class="footer-tagline">Part of the <a href="https://yoke.lol/tools">.lol tools</a></div>
  <div class="footer-family"><a href="https://yoke.lol">yoke</a><a href="https://ns.lol">ns</a><a href="https://xhttp.lol">xhttp</a><a href="https://vrfy.lol">vrfy</a></div>
  <a href="https://yoke.lol/certs.lol" class="yoke-badge"><img src="https://yoke.lol/badge/certs.lol.svg" alt="Yoke score for certs.lol" height="20"></a>
</footer>
</div>

<script${nonceAttr}>
const body=document.body;
const toggleBtns=document.querySelectorAll('.theme-opt');
const saved=localStorage.getItem('certs-theme');
function setTheme(t){
  body.dataset.theme=t;
  toggleBtns.forEach(b=>{
    const isActive=b.dataset.theme===t;
    b.classList.toggle('active',isActive);
    b.setAttribute('aria-checked',isActive?'true':'false');
  });
  localStorage.setItem('certs-theme',t);
}
if(saved){setTheme(saved)}
toggleBtns.forEach(b=>b.addEventListener('click',()=>setTheme(b.dataset.theme)));
});
document.getElementById('scanForm').addEventListener('submit',(e)=>{
  e.preventDefault();
  const q=document.querySelector('.di').value.trim();
  if(q)window.location.href='/'+encodeURIComponent(q);
});
// Rate limit pill
(function(){
  const pill=document.getElementById('rlPill');
  const detail=document.getElementById('rlDetail');
  if(!pill||!detail)return;
  const r=parseInt(pill.dataset.remaining||'',10);
  const l=parseInt(pill.dataset.limit||'',10);
  if(isNaN(r)||isNaN(l)||l<=0)return;
  const pct=r/l;
  const used=l-r;
  pill.textContent=r<=0?'Resets soon':r+'/'+l;
  pill.style.display='block';
  if(pct<=0.10){pill.classList.add('danger')}
  else if(pct<=0.25){pill.classList.add('warn')}
  const color=pct<=0.10?'var(--err)':pct<=0.25?'var(--warn)':'var(--dim)';
  document.getElementById('rlTitle').textContent=r<=0?'Rate limit reached':pct<=0.25?'Running low':'API usage';
  document.getElementById('rlTitle').style.color=color;
  document.getElementById('rlBarFill').style.width=Math.min((used/l)*100,100)+'%';
  document.getElementById('rlBarFill').style.background=color;
  document.getElementById('rlInfo').textContent=used+' of '+l+' scans used this hour\\nRolling 1-hour window';
  pill.addEventListener('mouseenter',function(){detail.classList.add('visible')});
  pill.addEventListener('mouseleave',function(){detail.classList.remove('visible')});
  pill.addEventListener('click',function(){detail.classList.toggle('visible')});
})();
</script>
${rl ? `<div class="rl-pill" id="rlPill" data-remaining="${rl.remaining}" data-limit="${rl.limit}"></div>
<div class="rl-detail" id="rlDetail">
  <div class="rl-title" id="rlTitle">API usage</div>
  <div class="rl-bar"><div class="rl-bar-fill" id="rlBarFill"></div></div>
  <div class="rl-info" id="rlInfo"></div>
</div>` : ''}
</body>
</html>`;
}

function renderEmpty(): string {
  return `
<div style="margin-top:3rem;text-align:center">
  <p style="color:var(--dim);font-family:var(--font-mono);font-size:12px"><code>curl -s https://certs.lol/stripe.com</code></p>
  <div class="examples">
    <a href="/stripe.com">stripe.com</a>
    <a href="/github.com">github.com</a>
    <a href="/cloudflare.com">cloudflare.com</a>
  </div>
</div>`;
}

function renderResult(d: ScanResult, hook: string[], isIP: boolean): string {
  const gradeClass = d.grade === 'A+' ? 'A-plus' : d.grade.charAt(0);
  const cached = d._meta?.cache_hit ? ' · <span class="cache-tag" title="Cached result">cached</span>' : '';
  const scannedAt = d.scanned_at ? timeAgo(d.scanned_at) : '';
  const rescanBtn = `<a href="/${esc(d.target)}?force" class="rescan-btn" title="Force fresh scan">↻ rescan</a>`;

  // Parse subject CN
  const subjectCN = d.subject.replace(/^CN=/, '');
  const issuerParts = d.issuer.replace(/^CN=/, '').replace(/,O=/g, ' · ').replace(/,C=/g, ' · ');

  // Days remaining
  const days = d.days_remaining;
  const daysClass = days > 30 ? 'ok' : days > 7 ? 'warn' : 'err';

  // Protocol checks
  const hasTLS13 = d.protocols.includes('TLS 1.3');
  const hasTLS12 = d.protocols.includes('TLS 1.2');
  const hasTLS11 = d.protocols.includes('TLS 1.1');
  const hasTLS10 = d.protocols.includes('TLS 1.0');

  // Cipher summary
  const cs = d.cipher_summary;

  // SANs display
  const sansDisplay = d.sans.length <= 5
    ? d.sans.join(', ')
    : d.sans.slice(0, 4).join(', ') + ` + ${d.sans.length - 4} more`;

  let s = `
<div class="grade-block">
  <div class="grade-letter grade-${gradeClass}" aria-label="Grade ${esc(d.grade)}">${esc(d.grade)}</div>
  <div>
    <h1 class="grade-domain">${esc(d.target)}</h1>
    <div class="grade-meta">${d.probe_ms}ms${cached}${scannedAt ? ` · ${scannedAt}` : ''} ${rescanBtn}</div>
  </div>
</div>`;

  // Certificate
  s += section('Certificate', [
    row('subject', subjectCN),
    row('issuer', issuerParts, 'inf'),
    row('sans', sansDisplay),
    row('key', d.key_alg + (d.key_size ? ` ${d.key_size}` : '')),
    row('serial', d.serial.toLowerCase()),
    row('valid from', formatDate(d.valid_from)),
    row('expires', `${formatDate(d.valid_to)} (${days} days)`, daysClass),
    row('chain', `${d.chain_depth} certs · ${d.chain_valid ? 'valid' : 'INVALID'}`, d.chain_valid ? 'ok' : 'err'),
    row('ocsp stapling', d.ocsp_stapling ? '✓ present' : '✗ missing', d.ocsp_stapling ? 'ok' : 'off'),
    row('scts', d.has_scts ? `✓ ${d.sct_count} embedded` : '✗ none', d.has_scts ? 'ok' : 'off'),
  ]);

  // Certificate Chain
  if (d.chain_certs && d.chain_certs.length > 1) {
    const chainRows: string[] = [];
    d.chain_certs.forEach((cert, i) => {
      const cn = extractCN(cert.subject);
      const issuerCN = extractCN(cert.issuer);
      const label = i === 0 ? 'leaf' : i === d.chain_certs!.length - 1 ? 'root' : `intermediate ${i}`;
      const certDays = cert.valid_to
        ? Math.max(0, Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000))
        : 0;
      chainRows.push(row(label, `${cn}`, 'inf'));
      chainRows.push(row('  issuer', issuerCN, 'off'));
      chainRows.push(row('  key', `${cert.key_alg}${cert.key_size ? ' ' + cert.key_size : ''} · ${cert.signature_alg}`, 'off'));
      chainRows.push(row('  expires', `${formatDate(cert.valid_to)} (${certDays}d)`, certDays < 30 ? 'warn' : 'off'));
    });
    s += section('Chain', chainRows);
  }

  // Protocol
  s += section('Protocol', [
    row('tls 1.3', hasTLS13 ? '✓ supported' : '✗ no', hasTLS13 ? 'ok' : 'off'),
    row('tls 1.2', hasTLS12 ? '✓ supported' : '✗ no', hasTLS12 ? 'ok' : 'off'),
    row('tls 1.1', hasTLS11 ? '⚠ enabled' : '✗ disabled', hasTLS11 ? 'warn' : 'ok'),
    row('tls 1.0', hasTLS10 ? '⚠ enabled' : '✗ disabled', hasTLS10 ? 'warn' : 'ok'),
    row('key exchange', d.key_exchange),
    row('forward secrecy', d.forward_secrecy ? '✓ yes' : '✗ no', d.forward_secrecy ? 'ok' : 'err'),
  ]);

  // Cipher Suites
  const tls13Ciphers = d.ciphers.filter(c => c.id >= 4865 && c.id <= 4869);
  const tls12Ciphers = d.ciphers.filter(c => c.id < 4865 || c.id > 4869);

  let cipherRows = [
    row('total', `${d.ciphers.length} suites`),
    row('strong', String(cs.strong), 'ok'),
    row('acceptable', String(cs.acceptable), cs.acceptable > 0 ? 'inf' : ''),
  ];
  if (cs.weak > 0) cipherRows.push(row('weak', String(cs.weak), 'warn'));
  if (cs.insecure > 0) cipherRows.push(row('insecure', String(cs.insecure), 'err'));

  s += section('Cipher Suites', cipherRows);

  // Cipher detail grid
  if (tls13Ciphers.length > 0) {
    s += `<div style="margin-top:6px;margin-bottom:2px;font-size:10px;color:var(--dim);font-family:var(--font-mono);font-weight:600">TLS 1.3</div>`;
    s += `<div class="cipher-grid">${tls13Ciphers.map(c =>
      `<span class="c ${c.strength}">${cipherShort(c.name)}</span>`
    ).join('')}</div>`;
  }
  if (tls12Ciphers.length > 0) {
    s += `<div style="margin-top:8px;margin-bottom:2px;font-size:10px;color:var(--dim);font-family:var(--font-mono);font-weight:600">TLS 1.2</div>`;
    s += `<div class="cipher-grid">${tls12Ciphers.map(c =>
      `<span class="c ${c.strength}">${cipherShort(c.name)}</span>`
    ).join('')}</div>`;
  }

  // Transport
  const hsts = d.hsts;
  const h3 = d.http3;
  const transportRows = [];

  transportRows.push(row('hsts', hsts.enabled ? `✓ max-age=${hsts.max_age}` : '✗ missing', hsts.enabled ? 'ok' : ''));
  if (hsts.enabled) {
    transportRows.push(row('includeSubDomains', hsts.include_subdomains ? '✓' : '✗', hsts.include_subdomains ? 'ok' : 'off'));
    transportRows.push(row('preload directive', hsts.preload ? '✓' : '✗', hsts.preload ? 'ok' : 'off'));
    transportRows.push(row('preload list', hsts.on_preload_list ? '✓ listed' : '✗ not listed', hsts.on_preload_list ? 'ok' : 'off'));
  }
  transportRows.push(row('http/2', h3.http2 ? '✓ supported' : '—', h3.http2 ? 'ok' : 'off'));
  transportRows.push(row('http/3', h3.supported ? '✓ QUIC' : '—', h3.supported ? 'ok' : 'off'));
  if (h3.alt_svc) {
    transportRows.push(row('alt-svc', h3.alt_svc, 'off'));
  }
  s += section('Transport', transportRows);

  // DNS Security (domains only)
  if (!isIP && d.dns_security) {
    const dns = d.dns_security;
    const dnsRows = [
      row('dnssec', dns.dnssec ? '✓ signed' : '✗ unsigned', dns.dnssec ? 'ok' : ''),
      row('caa', dns.caa.length ? dns.caa.join(', ') : '—', dns.caa.length ? 'ok' : 'off'),
      row('dane / tlsa', dns.dane_tlsa || '—', dns.dane_tlsa ? 'ok' : 'off'),
    ];
    s += section('DNS Security', dnsRows);
  }

  // Compliance
  if (d.compliance && d.compliance.length > 0) {
    const compRows: string[] = [];
    for (const c of d.compliance) {
      if (c.meets_requirements) {
        compRows.push(row(c.display_name, '✓ meets transport requirements', 'ok'));
      } else {
        const fails = c.findings.filter(f => f.status === 'fail');
        const warns = c.findings.filter(f => f.status === 'warn');
        const issues: string[] = fails.map(f => f.detail);
        if (warns.length > 0 && fails.length === 0) {
          issues.push(...warns.map(f => f.detail));
        }
        const issueCount = fails.length + (fails.length === 0 ? warns.length : 0);
        const cls = fails.length > 0 ? 'err' : 'warn';
        compRows.push(row(c.display_name, `✗ ${issueCount} issue${issueCount !== 1 ? 's' : ''}: ${issues.join('; ')}`, cls));
      }
    }
    compRows.push(row('', 'transport-layer checks only', 'off'));
    s += section('Compliance', compRows);
  }

  // Yoke hook (domains only)
  if (!isIP && d.target) {
    const q = hook[0].replace('{d}', d.target);
    s += `<div class="hook"><span class="ar">→</span><span class="q">${esc(q)}</span> <a href="https://yoke.lol/${esc(d.target)}">${esc(hook[1])}</a></div>`;
  }

  return s;
}

function extractCN(dn: string): string {
  const match = dn.match(/CN=([^,]+)/);
  return match ? match[1] : dn;
}

function cipherShort(name: string): string {
  return name
    .replace(/^TLS_/, '')
    .replace(/_WITH_/, ' ')
    .replace(/_/g, '-');
}

function formatDate(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toISOString().slice(0, 10);
}

function timeAgo(iso: string): string {
  if (!iso) return '';
  const secs = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 60) return 'just now';
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

function section(label: string, rows: string[]): string {
  return `<section class="section"><h2 class="sec-label">${label}</h2>${rows.join('')}</section>`;
}

function row(key: string, value: string, cls = ''): string {
  return `<div class="r"><span class="k">${esc(key)}</span><span class="v${cls ? ' ' + cls : ''}">${esc(value)}</span></div>`;
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
