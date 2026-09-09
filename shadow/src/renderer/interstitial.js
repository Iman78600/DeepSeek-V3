'use strict';
/* Renders the block page. Data arrives base64-encoded in the ?d= parameter,
   so no page content is ever interpolated into HTML as markup. */

const params = new URLSearchParams(location.search);
let payload = { kind: 'block', verdict: { score: 0, reasons: [], severity: 'high' }, targetUrl: '' };
try {
  payload = JSON.parse(atob(decodeURIComponent(params.get('d') || '')));
} catch { /* fall through to defaults */ }

const v = payload.verdict || {};
const set = (id, text) => { document.getElementById(id).textContent = text; };

if (payload.kind === 'certificate') {
  set('headline', 'This connection is not trustworthy');
  set('subline', 'The site presented a certificate that failed verification. Someone may be sitting between you and the real site.');
} else if (v.verdict === 'warn') {
  set('headline', 'Shadow is not sure about this page');
  set('subline', 'Enough is unusual here that you should look before you continue.');
}

set('target', payload.targetUrl || '');
set('score', String(v.score ?? 0));
set('scorelabel', `risk out of 100 - ${v.severity || 'unknown'} - ${(v.reasons || []).length} finding(s)`);

const findings = document.getElementById('findings');
for (const r of (v.reasons || [])) {
  const div = document.createElement('div');
  div.className = `finding ${r.severity || 'medium'}`;
  const h = document.createElement('h3');
  h.textContent = r.title;
  const p = document.createElement('p');
  p.textContent = r.detail || '';
  div.appendChild(h);
  div.appendChild(p);
  findings.appendChild(div);
}

set('fineprint',
  'Shadow decides locally, on this machine. Nothing about the pages you visit is sent anywhere. '
  + 'If you think this is wrong, open the site report and add the site to your trusted list.');

document.getElementById('back').onclick = () => window.shadow.tabs.back();
document.getElementById('home').onclick = () => window.shadow.tabs.open();
document.getElementById('proceed').onclick = () => {
  const sure = confirm(
    'Shadow found real evidence that this page is dangerous.\n\n'
    + (v.reasons || []).slice(0, 3).map((r) => `- ${r.title}`).join('\n')
    + '\n\nContinuing loads the page in full. Are you sure?');
  if (sure) window.shadow.soc.proceed(payload.targetUrl);
};
