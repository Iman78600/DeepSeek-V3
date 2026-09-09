'use strict';
/* Shadow browser chrome. Talks to the main process only through window.shadow. */

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};

let state = { tabs: [], activeTabId: null, settings: {}, tor: null, presets: {} };

// --------------------------------------------------------------------- tabs
function renderTabs() {
  const strip = $('#tabs');
  strip.textContent = '';
  for (const tab of state.tabs) {
    const node = el('div', `tab${tab.id === state.activeTabId ? ' active' : ''}`);
    const dot = el('div', 'dot');
    const v = tab.verdict ? tab.verdict.verdict : null;
    dot.style.background = v === 'block' ? 'var(--critical)'
      : v === 'warn' ? 'var(--medium)'
      : v === 'allow' ? 'var(--ok)' : 'var(--muted)';
    node.appendChild(dot);
    node.appendChild(el('div', 'title', tab.title || 'New tab'));
    const close = el('div', 'close', '×');
    close.onclick = (e) => { e.stopPropagation(); window.shadow.tabs.close(tab.id); };
    node.appendChild(close);
    node.onclick = () => window.shadow.tabs.activate(tab.id);
    strip.appendChild(node);
  }

  const active = state.tabs.find((t) => t.id === state.activeTabId);
  if (active) {
    if (document.activeElement !== $('#address')) {
      $('#address').value = active.url && active.url.startsWith('file://') ? '' : (active.url || '');
    }
    $('#back').disabled = !active.canGoBack;
    $('#forward').disabled = !active.canGoForward;

    const badge = $('#risk-badge');
    const verdict = active.verdict ? active.verdict.verdict : 'unknown';
    badge.className = `badge ${verdict}`;
    badge.title = active.verdict
      ? `Risk ${active.verdict.score}/100 (${active.verdict.severity}) - click for the full report`
      : 'No analysis yet';

    const counter = $('#blocked-count');
    counter.textContent = String(active.blockedCount || 0);
    counter.className = `counter${active.blockedCount > 10 ? ' hot' : ''}`;

    for (const alert of active.alerts || []) toast(alert.title, alert.detail, alert.severity, alert.id);
  }
}

// -------------------------------------------------------------------- panel
let panelName = null;

function openPanel(title, wide = false) {
  $('#panel').classList.remove('hidden');
  $('#panel').classList.toggle('wide', wide);
  $('#panel-title').textContent = title;
  $('#panel-body').textContent = '';
  return $('#panel-body');
}
function closePanel() { $('#panel').classList.add('hidden'); panelName = null; }
function togglePanel(name, fn, title, wide) {
  if (panelName === name) return closePanel();
  panelName = name;
  fn(openPanel(title, wide));
}

function severityCard(sig) {
  const card = el('div', `card ${sig.severity || 'info'}`);
  const h = el('h3');
  h.appendChild(el('span', `sev ${sig.severity || 'info'}`, sig.severity || 'info'));
  h.appendChild(document.createTextNode(sig.title));
  card.appendChild(h);
  if (sig.detail) card.appendChild(el('p', null, sig.detail));
  return card;
}

// ------------------------------------------------------------ site report
async function renderSiteReport(body) {
  const report = await window.shadow.soc.report();
  if (!report) {
    body.appendChild(el('div', 'empty', 'Nothing analysed yet. Load a page first.'));
    return;
  }

  const ring = el('div', 'score-ring');
  ring.appendChild(el('div', `score-num ${report.verdict}`, String(report.score)));
  const lab = el('div');
  lab.appendChild(el('div', null, report.verdict === 'block' ? 'Blocked'
    : report.verdict === 'warn' ? 'Proceed with care' : 'Looks clean'));
  lab.appendChild(el('div', 'score-label', `${report.hostname || ''} - ${report.signals.length} checks fired - ${report.mode} mode`));
  ring.appendChild(lab);
  body.appendChild(ring);

  if (!report.signals.length) {
    body.appendChild(el('div', 'empty', 'The analyst found nothing worth reporting on this page.'));
  }
  for (const sig of report.signals) {
    if ((sig.score || 0) <= 0 && sig.severity === 'info') continue;
    body.appendChild(severityCard(sig));
  }

  const actions = el('div', 'actions');
  if (report.hostname) {
    const trust = el('button', 'action', `Always trust ${report.hostname}`);
    trust.onclick = async () => {
      await window.shadow.soc.trustSite(report.hostname);
      toast('Site trusted', `${report.hostname} will not be hard-blocked by the analyst again.`, 'low');
      closePanel();
    };
    actions.appendChild(trust);

    const block = el('button', 'action danger', `Block ${report.hostname}`);
    block.onclick = async () => {
      await window.shadow.firewall.blockDomain(report.hostname);
      toast('Domain blocked', `${report.hostname} is now on your personal blocklist.`, 'medium');
    };
    actions.appendChild(block);
  }
  body.appendChild(actions);
}

// -------------------------------------------------------------- downloads
async function renderDownloads(body) {
  const items = await window.shadow.downloads.list();
  if (!items.length) {
    body.appendChild(el('div', 'empty',
      'No downloads yet. Everything you download is held in a sandbox and scanned before you can open it.'));
    return;
  }
  for (const d of items) {
    const card = el('div', `card ${d.severity || 'info'}`);
    const h = el('h3');
    if (d.verdict) h.appendChild(el('span', `sev ${d.severity}`, d.verdict === 'block' ? 'blocked' : d.verdict));
    h.appendChild(document.createTextNode(d.name));
    card.appendChild(h);

    card.appendChild(el('p', null,
      `${d.detectedType || '?'} - ${d.size || '?'} - ${d.state}${d.score !== null ? ` - risk ${d.score}/100` : ''}`));
    if (d.sha256) card.appendChild(el('div', 'mono', `sha256 ${d.sha256}`));

    for (const r of (d.reasons || []).slice(0, 4)) {
      const line = el('p', null, `- ${r.title}`);
      card.appendChild(line);
    }

    const actions = el('div', 'actions');
    if (d.state === 'quarantined') {
      const rel = el('button', d.verdict === 'block' ? 'action danger' : 'action primary',
        d.verdict === 'block' ? 'Release anyway' : 'Release to Downloads');
      rel.onclick = async () => {
        try {
          const r = await window.shadow.downloads.release(d.id, d.verdict === 'block');
          if (r) toast('Released', `${d.name} is in your Downloads folder.`, 'low');
        } catch (err) {
          toast('Release refused', err.message, 'high');
        }
        renderDownloads(openPanel('Downloads'));
      };
      actions.appendChild(rel);

      const det = el('button', 'action', 'Detonate in sandbox');
      det.onclick = async () => {
        det.textContent = 'Running...';
        const result = await window.shadow.downloads.detonate(d.id);
        det.textContent = 'Detonate in sandbox';
        if (!result.available) toast('Detonation unavailable', result.reason, 'medium');
        else if (!result.executed) toast('Not detonated', result.reason, 'medium');
        else toast('Detonation finished',
          result.behaviours.length ? `Observed: ${result.behaviours.join(', ')}` : 'Nothing obvious happened. That is not proof it is safe.',
          result.behaviours.length ? 'high' : 'low');
        renderDownloads(openPanel('Downloads'));
      };
      actions.appendChild(det);

      const del = el('button', 'action', 'Delete');
      del.onclick = async () => {
        await window.shadow.downloads.remove(d.id);
        renderDownloads(openPanel('Downloads'));
      };
      actions.appendChild(del);
    }
    card.appendChild(actions);
    body.appendChild(card);
  }

  const folder = el('button', 'action', 'Open quarantine folder');
  folder.onclick = () => window.shadow.downloads.openFolder();
  body.appendChild(folder);
}

// ------------------------------------------------------------ SOC dashboard
async function renderSoc(body) {
  const [stats, fw, recent] = await Promise.all([
    window.shadow.events.stats(),
    window.shadow.firewall.summary(),
    window.shadow.events.query({ limit: 60 }),
  ]);

  const tiles = el('div', 'tiles');
  const tile = (n, l) => {
    const t = el('div', 'tile');
    t.appendChild(el('div', 'n', String(n)));
    t.appendChild(el('div', 'l', l));
    return t;
  };
  tiles.appendChild(tile(stats.blocked, 'requests blocked (24h)'));
  tiles.appendChild(tile(stats.pagesBlocked, 'pages blocked'));
  tiles.appendChild(tile(stats.downloadsScanned, 'downloads scanned'));
  tiles.appendChild(tile(stats.downloadsBlocked, 'downloads condemned'));
  body.appendChild(tiles);

  const cats = el('div', 'card');
  cats.appendChild(el('h3', null, 'What the firewall stopped'));
  const entries = Object.entries(fw.byCategory || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) cats.appendChild(el('p', null, 'Nothing yet this session.'));
  for (const [cat, n] of entries) {
    const row = el('div', 'row');
    row.appendChild(el('div', 'k', cat));
    row.appendChild(el('div', 'v', String(n)));
    cats.appendChild(row);
  }
  body.appendChild(cats);

  if (stats.topHosts.length) {
    const hosts = el('div', 'card');
    hosts.appendChild(el('h3', null, 'Most-seen hosts'));
    for (const h of stats.topHosts) {
      const row = el('div', 'row');
      row.appendChild(el('div', 'k mono', h.host));
      row.appendChild(el('div', 'v', String(h.count)));
      hosts.appendChild(row);
    }
    body.appendChild(hosts);
  }

  const lists = el('div', 'card');
  lists.appendChild(el('h3', null, 'Blocklists loaded'));
  for (const [cat, n] of Object.entries(fw.lists.categories)) {
    const row = el('div', 'row');
    row.appendChild(el('div', 'k', cat));
    row.appendChild(el('div', 'v', `${n.toLocaleString()} domains`));
    lists.appendChild(row);
  }
  body.appendChild(lists);

  const log = el('div', 'card');
  log.appendChild(el('h3', null, 'Recent events'));
  for (const e of recent) {
    const line = el('div', 'log-line');
    line.appendChild(el('div', 't', new Date(e.at).toLocaleTimeString()));
    const msg = e.type === 'firewall-block' ? `blocked ${e.hostname} (${e.category})`
      : e.type === 'page-verdict' ? `${e.verdict} ${e.hostname} [${e.score}]`
      : e.type === 'download-scanned' ? `scanned ${e.name} [${e.score}]`
      : `${e.type}${e.hostname ? ` ${e.hostname}` : ''}`;
    line.appendChild(el('div', 'm', msg));
    log.appendChild(line);
  }
  body.appendChild(log);

  const actions = el('div', 'actions');
  const exp = el('button', 'action', 'Export log (JSONL)');
  exp.onclick = async () => {
    const p = await window.shadow.events.export();
    if (p) toast('Exported', p, 'low');
  };
  const clr = el('button', 'action danger', 'Clear log');
  clr.onclick = async () => { await window.shadow.events.clear(); renderSoc(openPanel('SOC dashboard', true)); };
  actions.appendChild(exp);
  actions.appendChild(clr);
  body.appendChild(actions);
}

// ---------------------------------------------------------------- settings
const SETTING_GROUPS = [
  ['The analyst', [
    ['soc.enabled', 'Analyse every page', 'Score sites before and after they load.'],
    ['soc.mode', 'Strictness', 'How much evidence it takes to block.', ['strict', 'balanced', 'relaxed']],
    ['soc.blockOnUrlVerdict', 'Block before loading', 'Stop a dangerous page before a single byte is fetched.'],
    ['soc.deepPageScan', 'Inspect page content', 'Look at the rendered page, not just the address.'],
  ]],
  ['Firewall', [
    ['firewall.enabled', 'Firewall on', 'Filter every request the page makes.'],
    ['firewall.httpsOnly', 'HTTPS only', 'Upgrade plain HTTP automatically.'],
    ['firewall.blockPrivateNetwork', 'Protect your local network', 'Stop web pages reaching your router, printer or NAS.'],
    ['firewall.blockTrackers', 'Block trackers', ''],
    ['firewall.blockAds', 'Block ads', ''],
    ['firewall.blockMining', 'Block cryptominers', ''],
    ['firewall.lockdown', 'Lockdown mode', 'Block all third-party scripts and frames. Breaks many sites.'],
  ]],
  ['Download sandbox', [
    ['sandbox.enabled', 'Sandbox downloads', 'Nothing reaches your Downloads folder unscanned.'],
    ['sandbox.detonate', 'Detonate in a container', 'Run the file in a throwaway container and watch it. Needs Docker or Podman.'],
    ['sandbox.autoDeleteMalicious', 'Delete malicious files automatically', ''],
  ]],
  ['Anonymity', [
    ['tor.enabled', 'Route through Tor', 'All traffic goes through the Tor network. Slower, much more private.'],
    ['tor.newCircuitPerSite', 'New circuit per site', 'Different exit relay for each site you visit.'],
  ]],
  ['Anti-fingerprinting', [
    ['hardening.canvasNoise', 'Canvas noise', 'Break canvas and audio fingerprinting.'],
    ['hardening.fontProtection', 'Font protection', 'Hide which fonts you have installed.'],
    ['hardening.timingJitter', 'Reduce timer precision', 'Blunt timing-based side channels.'],
    ['hardening.webrtc', 'WebRTC', 'WebRTC can leak your real IP even behind a proxy.', ['disabled', 'public-only', 'default']],
    ['hardening.blockWebgl', 'Block WebGL', 'Strong protection, breaks 3D content and some maps.'],
    ['hardening.spoofUserAgent', 'Generic User-Agent', 'Look like every other Chrome user.'],
    ['hardening.blockThirdPartyCookies', 'Block third-party cookies', ''],
    ['hardening.denyPermissions', 'Deny permission prompts', 'Camera, microphone, location and notifications are refused by default.'],
    ['hardening.sanitizeClipboard', 'Protect the clipboard', 'Stop pages swapping what you copy.'],
  ]],
  ['Privacy', [
    ['privacy.clearOnExit', 'Wipe everything on exit', 'Cookies, cache and storage are destroyed when Shadow closes.'],
    ['privacy.persistLog', 'Keep the SOC log on disk', 'Turn off for a session that leaves no trace.'],
  ]],
];

async function renderSettings(body) {
  const current = await window.shadow.settings.all();
  const presets = await window.shadow.settings.presets();

  const presetCard = el('div', 'card');
  presetCard.appendChild(el('h3', null, 'Security profile'));
  for (const [name, p] of Object.entries(presets)) {
    const row = el('div', 'switch');
    const left = el('div');
    left.appendChild(el('div', 'label', p.label));
    left.appendChild(el('div', 'desc', p.summary));
    row.appendChild(left);
    const btn = el('button', `action${current['profile.preset'] === name ? ' primary' : ''}`,
      current['profile.preset'] === name ? 'Active' : 'Use');
    btn.onclick = async () => {
      await window.shadow.settings.applyPreset(name);
      toast('Profile applied', p.label, 'low');
      renderSettings(openPanel('Settings', true));
    };
    row.appendChild(btn);
    presetCard.appendChild(row);
  }
  body.appendChild(presetCard);

  for (const [groupName, items] of SETTING_GROUPS) {
    const card = el('div', 'card');
    card.appendChild(el('h3', null, groupName));
    for (const [key, label, desc, options] of items) {
      const row = el('div', 'switch');
      const left = el('div');
      left.appendChild(el('div', 'label', label));
      if (desc) left.appendChild(el('div', 'desc', desc));
      row.appendChild(left);

      if (options) {
        const sel = el('select');
        for (const opt of options) {
          const o = el('option', null, opt);
          o.value = opt;
          if (current[key] === opt) o.selected = true;
          sel.appendChild(o);
        }
        sel.onchange = async () => {
          await window.shadow.settings.set(key, sel.value);
          toast('Setting changed', `${label}: ${sel.value}`, 'low');
        };
        row.appendChild(sel);
      } else {
        const box = el('input');
        box.type = 'checkbox';
        box.checked = Boolean(current[key]);
        box.onchange = async () => {
          try {
            await window.shadow.settings.set(key, box.checked);
          } catch (err) {
            box.checked = !box.checked;
            toast('Could not change setting', err.message, 'high');
          }
        };
        row.appendChild(box);
      }
      card.appendChild(row);
    }
    body.appendChild(card);
  }

  const priv = el('div', 'actions');
  const clear = el('button', 'action', 'Clear all browsing data now');
  clear.onclick = async () => { await window.shadow.privacy.clearNow(); toast('Cleared', 'Cookies, cache and storage are gone.', 'low'); };
  priv.appendChild(clear);
  body.appendChild(priv);

  const v = await window.shadow.app.version();
  const about = el('div', 'card');
  about.appendChild(el('h3', null, 'About'));
  for (const [k, val] of Object.entries(v)) {
    const row = el('div', 'row');
    row.appendChild(el('div', 'k', k));
    row.appendChild(el('div', 'v mono', String(val)));
    about.appendChild(row);
  }
  body.appendChild(about);
}

// --------------------------------------------------------------------- tor
async function renderTor(body) {
  const status = await window.shadow.tor.status();

  const card = el('div', 'card');
  card.appendChild(el('h3', null, `Tor: ${status.state}`));
  if (status.state === 'starting') card.appendChild(el('p', null, `Bootstrapping ${status.bootstrap}%`));
  if (status.error) card.appendChild(el('p', null, status.error));
  if (status.state === 'running' || status.state === 'external') {
    card.appendChild(el('p', null,
      `Traffic is going through 127.0.0.1:${status.socksPort}. Three relays, none of which knows both who you are and where you are going.`));
  }
  body.appendChild(card);

  const honest = el('div', 'card info');
  honest.appendChild(el('h3', null, 'About the "free VPN" part'));
  honest.appendChild(el('p', null,
    'Shadow does not ship a free VPN, because a free VPN has to pay for its servers somehow and the usual way is selling your traffic. '
    + 'Tor is the free option that does not have that problem, and it is what Shadow uses. '
    + 'If you already pay for a VPN you trust, point Shadow at it under proxy settings.'));
  honest.appendChild(el('p', null,
    'Tor hides where you are connecting from. It does not hide who you are if you log into an account. '
    + 'Keep the anti-fingerprinting settings on for the other half of the job.'));
  body.appendChild(honest);

  const actions = el('div', 'actions');
  if (status.state === 'running' || status.state === 'external') {
    const stop = el('button', 'action danger', 'Stop Tor');
    stop.onclick = async () => { await window.shadow.tor.stop(); renderTor(openPanel('Tor')); };
    actions.appendChild(stop);

    const nid = el('button', 'action', 'New identity');
    nid.onclick = async () => {
      const r = await window.shadow.tor.newIdentity();
      toast(r.ok ? 'New circuit' : 'Could not change circuit',
        r.ok ? 'You have a new exit relay, and cookies were cleared.' : (r.error || ''), r.ok ? 'low' : 'medium');
    };
    actions.appendChild(nid);

    const ver = el('button', 'action', 'Verify');
    ver.onclick = async () => {
      const r = await window.shadow.tor.verify();
      toast(r.ok ? 'Confirmed on Tor' : 'Not going through Tor',
        r.ok ? `Exit IP ${r.ip}` : (r.error || 'check.torproject.org says this is not a Tor connection'),
        r.ok ? 'low' : 'critical');
    };
    actions.appendChild(ver);
  } else {
    const start = el('button', 'action primary', 'Start Tor');
    start.onclick = async () => {
      start.textContent = 'Starting...';
      await window.shadow.tor.start();
      renderTor(openPanel('Tor'));
    };
    actions.appendChild(start);
  }
  body.appendChild(actions);
}

// ------------------------------------------------------------------- toasts
const shownToasts = new Set();
function toast(title, detail, severity = 'low', dedupeKey = null) {
  if (dedupeKey) {
    if (shownToasts.has(dedupeKey)) return;
    shownToasts.add(dedupeKey);
  }
  const node = el('div', `toast ${severity}`);
  node.appendChild(el('div', 'tt', title));
  if (detail) node.appendChild(el('div', 'td', detail));
  $('#toast-stack').appendChild(node);
  setTimeout(() => node.remove(), severity === 'critical' ? 14000 : 6000);
}

// -------------------------------------------------------------------- wiring
$('#address').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') window.shadow.tabs.navigate($('#address').value);
  if (e.key === 'Escape') $('#address').blur();
});
$('#address').addEventListener('focus', () => $('#address').select());

$('#back').onclick = () => window.shadow.tabs.back();
$('#forward').onclick = () => window.shadow.tabs.forward();
$('#reload').onclick = () => window.shadow.tabs.reload();
$('#new-tab').onclick = () => window.shadow.tabs.open();
$('#panel-close').onclick = closePanel;

$('#risk-badge').onclick = () => togglePanel('site', renderSiteReport, 'Site report');
$('#btn-shield').onclick = () => togglePanel('site', renderSiteReport, 'Site report');
$('#btn-downloads').onclick = () => togglePanel('downloads', renderDownloads, 'Downloads');
$('#btn-soc').onclick = () => togglePanel('soc', renderSoc, 'SOC dashboard', true);
$('#btn-settings').onclick = () => togglePanel('settings', renderSettings, 'Settings', true);
$('#btn-tor').onclick = () => togglePanel('tor', renderTor, 'Tor');

window.shadow.tabs.onUpdate((payload) => {
  state.tabs = payload.tabs;
  state.activeTabId = payload.activeTabId;
  renderTabs();
});

window.shadow.app.onBoot((payload) => {
  state.settings = payload.settings;
  state.tor = payload.tor;
  state.presets = payload.presets;
  updateTorButton(payload.tor);
});

window.shadow.downloads.onScanned((d) => {
  if (!d) return;
  const sev = d.verdict === 'block' ? 'critical' : d.verdict === 'warn' ? 'high' : 'low';
  toast(
    d.verdict === 'block' ? `Blocked: ${d.name}` : `Scanned: ${d.name}`,
    d.reasons && d.reasons.length ? d.reasons[0].title : 'Nothing suspicious found. It is waiting in quarantine.',
    sev);
  if (panelName === 'downloads') renderDownloads(openPanel('Downloads'));
});

window.shadow.downloads.onStarted((d) => {
  toast('Download quarantined', `${d.name} is being scanned before you can open it.`, 'low');
});

function updateTorButton(status) {
  const btn = $('#btn-tor');
  if (!status) return;
  const cls = status.state === 'running' || status.state === 'external' ? 'tor-on'
    : status.state === 'starting' ? 'tor-starting'
    : status.state === 'failed' ? 'tor-failed' : 'tor-off';
  btn.className = `icon-btn ${cls}`;
  btn.title = `Tor: ${status.state}${status.state === 'starting' ? ` (${status.bootstrap}%)` : ''}`;
}
setInterval(async () => {
  try { updateTorButton(await window.shadow.tor.status()); } catch { /* main not ready */ }
}, 3000);

// Keyboard shortcuts
window.addEventListener('keydown', (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (!mod) return;
  if (e.key === 't') { e.preventDefault(); window.shadow.tabs.open(); }
  if (e.key === 'w') { e.preventDefault(); window.shadow.tabs.close(state.activeTabId); }
  if (e.key === 'l') { e.preventDefault(); $('#address').focus(); }
  if (e.key === 'r') { e.preventDefault(); window.shadow.tabs.reload(); }
  if (e.shiftKey && e.key === 'S') { e.preventDefault(); togglePanel('soc', renderSoc, 'SOC dashboard', true); }
});
