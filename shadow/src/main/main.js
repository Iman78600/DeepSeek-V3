'use strict';
/**
 * Shadow - main process.
 *
 * Boot order matters:
 *   1. settings          (everything else reads it)
 *   2. command-line switches   (must happen before app 'ready')
 *   3. event log, blocklists, analyzer, firewall, quarantine, tor
 *   4. session hardening + firewall attach
 *   5. window + tabs
 */

const { app, BrowserWindow, WebContentsView, session, ipcMain, shell, dialog, Menu, net } = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');

const { SettingsStore } = require('./storage/store');
const { EventLog } = require('./soc/events');
const { Blocklists } = require('./firewall/blocklists');
const { Firewall } = require('./firewall/firewall');
const { Analyzer } = require('./soc/analyzer');
const { Quarantine } = require('./sandbox/quarantine');
const { Detonator } = require('./sandbox/detonate');
const { TorManager } = require('./tor');
const { hardenSession, webPreferences, commandLineSwitches } = require('./hardening/profile');
const { shieldSource } = require('./hardening/fingerprint-shield');
const { isNavigable, assertNavigable } = require('./hardening/url-policy');
const { registerIpc } = require('./ipc');

const SHADOW_HOME = path.join(os.homedir(), '.shadow');
const CHROME_HEIGHT = 88;   // height of the browser toolbar in CSS pixels
const RENDERER_DIR = path.join(__dirname, '..', 'renderer');

// ---------------------------------------------------------------------------
// Core services
// ---------------------------------------------------------------------------

const settings = new SettingsStore({ file: path.join(SHADOW_HOME, 'settings.json') });
const events = new EventLog({ file: path.join(SHADOW_HOME, 'soc-events.jsonl'), settings });
const blocklists = new Blocklists({ dir: path.join(__dirname, '..', '..', 'config', 'lists'), settings }).load();
const firewall = new Firewall({ settings, blocklists, events });
const analyzer = new Analyzer({ blocklists, settings, events });
const detonator = new Detonator({ settings, events });
const quarantine = new Quarantine({
  dir: path.join(SHADOW_HOME, 'quarantine'), settings, events, detonator,
});
const tor = new TorManager({ settings, events, dataDir: path.join(SHADOW_HOME, 'tor') });

firewall.setRules(settings.get('firewall.customRules') || []);

// A per-run seed for the fingerprint noise in the site preload.
const FINGERPRINT_SEED = crypto.randomBytes(4).readUInt32BE(0);

// ---------------------------------------------------------------------------
// Command-line switches (before ready)
// ---------------------------------------------------------------------------

for (const [name, value] of commandLineSwitches(settings)) {
  if (value === null) app.commandLine.appendSwitch(name);
  else app.commandLine.appendSwitch(name, value);
}
// Shadow renders untrusted content, so the OS-level renderer sandbox stays on.
//
// The one exception is an explicit --no-sandbox on the command line. Some
// environments cannot provide the sandbox at all (a container running as root,
// a kernel with user namespaces disabled). Calling enableSandbox() anyway wins
// over the flag, and the result is not a safer browser: it is an unbootable
// one that crash-loops its child processes with an error most people will not
// recognise. Honour the flag, and say plainly what was given up.
const SANDBOX_DISABLED = process.argv.includes('--no-sandbox');
if (SANDBOX_DISABLED) {
  console.warn(
    '\n  Shadow is running WITHOUT the operating system renderer sandbox.\n'
    + '  A bug in a web page can then reach the rest of this machine.\n'
    + '  Use this only for testing, never for real browsing.\n');
} else {
  app.enableSandbox();
}

// ---------------------------------------------------------------------------
// Tab management
// ---------------------------------------------------------------------------

/** @type {BrowserWindow} */
let win = null;
/** @type {Map<number, {id, view, url, title, verdict, alerts}>} */
const tabs = new Map();
let activeTabId = null;
let nextTabId = 1;

function chromeView() { return win ? win.contentView.children[0] : null; }

function layoutTabs() {
  if (!win) return;
  const { width, height } = win.getContentBounds();
  const chrome = chromeView();
  if (chrome) chrome.setBounds({ x: 0, y: 0, width, height });
  for (const tab of tabs.values()) {
    tab.view.setVisible(tab.id === activeTabId);
    if (tab.id === activeTabId) {
      tab.view.setBounds({ x: 0, y: CHROME_HEIGHT, width, height: height - CHROME_HEIGHT });
    }
  }
}

function sendToChrome(channel, payload) {
  const chrome = chromeView();
  if (chrome && !chrome.webContents.isDestroyed()) chrome.webContents.send(channel, payload);
}

function tabSummary(tab) {
  return {
    id: tab.id,
    url: tab.url,
    title: tab.title,
    loading: tab.loading,
    canGoBack: tab.view.webContents.navigationHistory.canGoBack(),
    canGoForward: tab.view.webContents.navigationHistory.canGoForward(),
    verdict: tab.verdict ? {
      verdict: tab.verdict.verdict,
      score: tab.verdict.score,
      severity: tab.verdict.severity,
      reasons: tab.verdict.reasons,
      hostname: tab.verdict.hostname,
    } : null,
    blockedCount: tab.blockedCount || 0,
    alerts: tab.alerts || [],
  };
}

function broadcastTabs() {
  sendToChrome('shadow:tabs', {
    tabs: [...tabs.values()].map(tabSummary),
    activeTabId,
  });
}

function interstitial(kind, verdict, targetUrl) {
  const file = path.join(__dirname, '..', 'renderer', 'interstitial.html');
  const payload = Buffer.from(JSON.stringify({ kind, verdict, targetUrl })).toString('base64');
  return `file://${file}?d=${encodeURIComponent(payload)}`;
}

/**
 * Attach the DevTools protocol to a tab and register the fingerprint shield so
 * it runs before page script on every navigation and in every frame.
 * A failure here is logged, never fatal: browsing still works, that tab is
 * simply more identifiable, and the SOC log says so.
 */
function installFingerprintShield(wc, tabId) {
  const anyEnabled = settings.get('hardening.canvasNoise')
    || settings.get('hardening.fontProtection')
    || settings.get('hardening.timingJitter');
  if (!anyEnabled) return;

  try {
    if (!wc.debugger.isAttached()) wc.debugger.attach('1.3');
  } catch (err) {
    events.record({ type: 'shield-failed', tabId, stage: 'attach', error: err.message });
    return;
  }

  const source = shieldSource({
    canvasNoise: settings.get('hardening.canvasNoise'),
    fontProtection: settings.get('hardening.fontProtection'),
    timingJitter: settings.get('hardening.timingJitter'),
    blockWebgl: settings.get('hardening.blockWebgl'),
  }, FINGERPRINT_SEED);

  wc.debugger.sendCommand('Page.enable')
    .then(() => wc.debugger.sendCommand('Page.addScriptToEvaluateOnNewDocument', {
      source,
      runImmediately: true,
    }))
    .catch((err) => {
      events.record({ type: 'shield-failed', tabId, stage: 'inject', error: err.message });
    });
}

function createTab(url = settings.get('privacy.homepage') || 'shadow://home') {
  const id = nextTabId++;
  const view = new WebContentsView({
    webPreferences: {
      ...webPreferences(path.join(__dirname, '..', 'preload', 'site-preload.js'), settings),
      partition: 'persist:shadow-web',
    },
  });

  const tab = { id, view, url, title: 'New tab', loading: false, verdict: null, alerts: [], blockedCount: 0 };
  tabs.set(id, tab);
  win.contentView.addChildView(view);

  const wc = view.webContents;

  // --- Fingerprint shield --------------------------------------------------
  // Injected into the page's own JavaScript world before any page script runs.
  // A preload cannot do this job: contextIsolation gives the preload its own
  // copies of navigator, Date and the canvas prototypes, so patching them
  // there would protect nothing. See hardening/fingerprint-shield.js.
  installFingerprintShield(wc, id);

  // --- Navigation gate: the analyst runs before the page is fetched --------
  //
  // Both events are needed. 'will-navigate' covers the address the user or the
  // page asked for; 'will-redirect' covers where the server actually sent
  // them. Checking only the first lets any safe-looking link redirect straight
  // into a phishing page without ever being scored.
  const gateNavigation = async (event, targetUrl, trigger) => {
    if (isInternal(targetUrl)) return;

    // A scheme a tab may not load is refused outright, whatever the analyst
    // would have said about it.
    if (!isNavigable(targetUrl, { rendererDir: RENDERER_DIR })) {
      event.preventDefault();
      events.record({ type: 'navigation-refused', tabId: id, url: targetUrl, trigger, reason: 'scheme' });
      return;
    }

    if (!settings.get('soc.enabled')) return;
    if (analyzer.hasOverride(targetUrl)) return;

    const verdict = await analyzer.inspectUrl(targetUrl, { tabId: id, trigger });
    tab.verdict = verdict;
    if (verdict.verdict === 'block' && settings.get('soc.blockOnUrlVerdict')) {
      event.preventDefault();
      wc.loadURL(interstitial('block', verdict, targetUrl));
    }
    broadcastTabs();
  };

  wc.on('will-navigate', (event, targetUrl) => gateNavigation(event, targetUrl, 'will-navigate'));
  wc.on('will-redirect', (event, targetUrl) => gateNavigation(event, targetUrl, 'will-redirect'));

  // Frames get the same treatment. A blocked top-level page is no help if the
  // same content loads in an iframe.
  wc.on('did-frame-navigate', (_e, frameUrl, httpCode, _s, isMainFrame) => {
    if (isMainFrame || !settings.get('soc.enabled')) return;
    analyzer.inspectUrl(frameUrl, { tabId: id, trigger: 'subframe' }).catch(() => {});
    void httpCode;
  });

  wc.on('did-start-loading', () => { tab.loading = true; tab.alerts = []; tab.blockedCount = 0; broadcastTabs(); });
  wc.on('did-stop-loading', () => { tab.loading = false; broadcastTabs(); });

  wc.on('did-navigate', (_e, navUrl) => { tab.url = navUrl; broadcastTabs(); });
  wc.on('did-navigate-in-page', (_e, navUrl) => { tab.url = navUrl; broadcastTabs(); });
  wc.on('page-title-updated', (_e, title) => { tab.title = title; broadcastTabs(); });

  wc.on('did-fail-load', (_e, code, description, failedUrl, isMainFrame) => {
    if (!isMainFrame || code === -3) return; // -3 is an aborted load
    events.record({ type: 'load-failed', url: failedUrl, code, description, tabId: id });
  });

  // --- Certificate problems go to the analyst, never to a "proceed" button --
  wc.on('certificate-error', async (event, certUrl, error, certificate, callback) => {
    event.preventDefault();
    const hostname = (() => { try { return new URL(certUrl).hostname; } catch { return ''; } })();
    const verdict = analyzer.inspectPage({
      url: certUrl, html: '', certificate, certificateError: error,
    });
    tab.verdict = verdict;
    events.record({ type: 'certificate-error', url: certUrl, hostname, error, verdict: verdict.verdict, score: verdict.score });
    callback(false);  // never trust it silently
    wc.loadURL(interstitial('certificate', verdict, certUrl));
    broadcastTabs();
  });

  // --- New windows: no popups, open in a tab, analysed like anything else ---
  wc.setWindowOpenHandler(({ url: target, disposition }) => {
    if (disposition === 'save-to-disk') return { action: 'deny' };
    // window.open is page-controlled, so the page does not get to pick the
    // scheme either. Without this, window.open('file:///...') reaches the disk.
    if (!isNavigable(target, { rendererDir: RENDERER_DIR })) {
      events.record({ type: 'popup-refused', tabId: id, url: target, reason: 'scheme' });
      return { action: 'deny' };
    }
    createTab(target);
    return { action: 'deny' };
  });

  // --- A renderer that crashes is a signal, not just an annoyance ----------
  wc.on('render-process-gone', (_e, details) => {
    events.record({ type: 'renderer-crash', tabId: id, url: tab.url, reason: details.reason, exitCode: details.exitCode });
    if (details.reason === 'crashed' || details.reason === 'oom') {
      tab.alerts.push({
        severity: 'medium',
        title: 'The page crashed its renderer',
        detail: 'A page that crashes the browser process may be probing for a memory bug. Shadow logged it.',
      });
    }
    broadcastTabs();
  });

  if (url.startsWith('shadow://')) {
    wc.loadURL(homePageUrl());
  } else {
    // Last line of defence: no caller gets to load a scheme that is not
    // allowed, however it reached here.
    try {
      wc.loadURL(assertNavigable(url, { rendererDir: RENDERER_DIR }));
    } catch (err) {
      events.record({ type: 'navigation-refused', tabId: id, url, reason: err.message });
      wc.loadURL(homePageUrl());
    }
  }
  activeTabId = id;
  layoutTabs();
  broadcastTabs();
  return tab;
}

/** Shadow's own bundled pages, which are exempt from the navigation gate. */
function isInternal(targetUrl) {
  const { isInternalPage } = require('./hardening/url-policy');
  return isInternalPage(targetUrl, RENDERER_DIR);
}

function homePageUrl() {
  return `file://${path.join(__dirname, '..', 'renderer', 'home.html')}`;
}

function closeTab(id) {
  const tab = tabs.get(id);
  if (!tab) return;
  win.contentView.removeChildView(tab.view);
  try { if (tab.view.webContents.debugger.isAttached()) tab.view.webContents.debugger.detach(); } catch { /* already gone */ }
  tab.view.webContents.close();
  tabs.delete(id);
  if (activeTabId === id) {
    activeTabId = [...tabs.keys()].pop() || null;
    if (!activeTabId) createTab();
  }
  layoutTabs();
  broadcastTabs();
}

// ---------------------------------------------------------------------------
// Downloads: everything goes to quarantine
// ---------------------------------------------------------------------------

function wireDownloads(sess) {
  sess.on('will-download', (event, item, webContents) => {
    if (!settings.get('sandbox.enabled')) return;

    const rec = quarantine.reserve(item.getFilename(), {
      sourceUrl: item.getURL(),
      mimeType: item.getMimeType(),
      referrer: webContents ? webContents.getURL() : '',
    });

    item.setSavePath(rec.savePath);
    sendToChrome('shadow:download-started', {
      id: rec.id, name: rec.originalName, sourceUrl: rec.sourceUrl,
      totalBytes: item.getTotalBytes(),
    });

    item.on('updated', (_e, state) => {
      sendToChrome('shadow:download-progress', {
        id: rec.id, received: item.getReceivedBytes(), total: item.getTotalBytes(), state,
      });
    });

    item.once('done', async (_e, state) => {
      if (state !== 'completed') {
        rec.state = 'failed';
        sendToChrome('shadow:download-failed', { id: rec.id, name: rec.originalName, state });
        return;
      }
      const done = await quarantine.complete(rec.id);
      sendToChrome('shadow:download-scanned', quarantine.list().find((d) => d.id === rec.id));

      if (done.verdict && done.verdict.verdict === 'block') {
        dialog.showMessageBox(win, {
          type: 'error',
          title: 'Shadow blocked a download',
          message: `"${done.originalName}" looks malicious.`,
          detail: `Risk score ${done.verdict.score}/100.\n\n` +
            done.verdict.reasons.slice(0, 4).map((r) => `- ${r.title}`).join('\n') +
            '\n\nThe file is locked in quarantine. It cannot run from there.',
          buttons: ['Keep it quarantined', 'Delete it now'],
          defaultId: 0,
          cancelId: 0,
        }).then(({ response }) => { if (response === 1) quarantine.discard(rec.id); });
      }
    });
    void event;
  });
}

// ---------------------------------------------------------------------------
// Window
// ---------------------------------------------------------------------------

function createWindow() {
  win = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 800,
    minHeight: 600,
    backgroundColor: '#0d0f14',
    title: 'Shadow',
    autoHideMenuBar: true,
    // No preload and no page here on purpose. The chrome UI lives in the
    // WebContentsView below, so the window itself never renders content and
    // does not need a privileged bridge of its own.
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  const chrome = new WebContentsView({
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload', 'browser-preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webviewTag: false,
      // The chrome UI is local and must never be navigated anywhere else.
      navigateOnDragDrop: false,
    },
  });

  // The UI is not a browser tab. Anything that tries to navigate it away from
  // index.html, or open a window from it, is refused.
  chrome.webContents.on('will-navigate', (event, target) => {
    if (!isInternal(target)) {
      event.preventDefault();
      events.record({ type: 'chrome-navigation-refused', url: target });
    }
  });
  chrome.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.contentView.addChildView(chrome);
  chrome.webContents.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));

  win.on('resize', layoutTabs);
  win.on('closed', () => { win = null; tabs.clear(); });

  chrome.webContents.once('did-finish-load', () => {
    createTab();
    sendToChrome('shadow:boot', {
      settings: settings.all(),
      tor: tor.status(),
      blocklists: blocklists.summary(),
      presets: require('../../config/presets.json'),
    });
  });

  layoutTabs();
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

app.whenReady().then(async () => {
  const webSession = session.fromPartition('persist:shadow-web');

  // --- file:// is confined to Shadow's own pages --------------------------
  //
  // The navigation gate catches a page that tries to reach the disk, but it is
  // not the whole story: Chromium's webRequest API never fires for the file
  // scheme, so the firewall cannot see file:// at all, and any code path that
  // reaches loadURL() without passing through will-navigate would still load
  // it. Enforcing it on the protocol itself covers every path at once.
  //
  // Shadow's own interstitial and home pages are file:// URLs that expose a
  // small IPC bridge, so "can load a local file" and "can reach that bridge"
  // are the same capability.
  webSession.protocol.handle('file', async (request) => {
    let filePath;
    try {
      const u = new URL(request.url);
      filePath = decodeURIComponent(u.pathname);
      if (process.platform === 'win32' && /^\/[a-z]:/i.test(filePath)) filePath = filePath.slice(1);
    } catch {
      return new Response('bad request', { status: 400 });
    }

    const resolved = path.resolve(filePath);
    const inside = resolved === RENDERER_DIR || resolved.startsWith(RENDERER_DIR + path.sep);
    if (!inside) {
      events.record({
        type: 'file-access-blocked',
        severity: 'high',
        path: resolved.slice(0, 300),
        detail: 'Something tried to load a local file that is not part of Shadow.',
      });
      return new Response(
        'Shadow does not load local files.',
        { status: 403, headers: { 'content-type': 'text/plain' } });
    }
    return net.fetch(`file://${resolved}`, { bypassCustomProtocolHandlers: true });
  });


  hardenSession(webSession, { settings, events });
  if (settings.get('firewall.enabled')) firewall.attach(webSession);
  wireDownloads(webSession);

  // Cookie policy
  if (settings.get('hardening.blockThirdPartyCookies')) {
    webSession.cookies.on('changed', () => { /* observation hook */ });
  }

  // Proxy / Tor
  if (settings.get('tor.enabled') && settings.get('tor.autoStart')) {
    await tor.start();
  }
  await webSession.setProxy(tor.proxyConfig());

  // The shield is injected per tab from installFingerprintShield(); the seed
  // lives in the main process so every tab in a session shares one value.

  // Deep page analysis, driven by the site preload's observations.
  ipcMain.on('shadow:page-observed', (event, observation) => {
    if (!settings.get('soc.deepPageScan')) return;
    if (!observation || typeof observation !== 'object') return;
    const tab = [...tabs.values()].find((t) => t.view.webContents.id === event.sender.id);
    if (!tab) return;

    // Use the URL the browser knows the tab is on, never the one the page
    // reported. A compromised renderer could otherwise claim to be on a
    // trusted site and have its content scored against that origin, or turn
    // its own risk badge green.
    const realUrl = tab.view.webContents.getURL();
    const html = typeof observation.html === 'string'
      ? observation.html.slice(0, 2_000_000)
      : '';

    const verdict = analyzer.inspectPage({
      url: realUrl,
      html,
      observations: observation,
    });
    tab.verdict = verdict;

    if (verdict.verdict === 'block' && !analyzer.hasOverride(realUrl)) {
      tab.view.webContents.loadURL(interstitial('block', verdict, realUrl));
    }
    broadcastTabs();
  });

  const ALERT_SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);
  ipcMain.on('shadow:page-alert', (event, alert) => {
    const tab = [...tabs.values()].find((t) => t.view.webContents.id === event.sender.id);
    if (!tab || !alert || typeof alert !== 'object') return;
    // Anything crossing this boundary comes from a renderer, so it is
    // normalised into a fixed shape before it can reach the UI or the log.
    // The cap stops a compromised page from burying real findings under noise.
    if (tab.alerts.length >= 20) return;
    const safe = {
      id: String(alert.id || 'page-alert').slice(0, 64).replace(/[^a-z0-9_-]/gi, ''),
      severity: ALERT_SEVERITIES.has(alert.severity) ? alert.severity : 'medium',
      title: String(alert.title || 'The page did something unusual').slice(0, 200),
      detail: String(alert.detail || '').slice(0, 500),
    };
    tab.alerts.push(safe);
    events.record({ type: 'page-alert', tabId: tab.id, url: tab.view.webContents.getURL(), ...safe });
    broadcastTabs();
  });

  // Live firewall counters per tab.
  events.on((entry) => {
    if (entry.type === 'firewall-block') {
      const tab = tabs.get(activeTabId);
      if (tab) { tab.blockedCount = (tab.blockedCount || 0) + 1; }
      sendToChrome('shadow:firewall-event', entry);
    }
  });

  registerIpc({
    ipcMain, app, dialog, shell, win: () => win,
    settings, events, blocklists, firewall, analyzer, quarantine, tor, detonator,
    tabs, createTab, closeTab, layoutTabs, broadcastTabs,
    rendererDir: RENDERER_DIR,
    setActiveTab: (id) => { if (tabs.has(id)) { activeTabId = id; layoutTabs(); broadcastTabs(); } },
    getActiveTab: () => tabs.get(activeTabId),
    webSession,
    homePageUrl,
  });

  Menu.setApplicationMenu(null);
  createWindow();

  events.record({
    type: 'startup',
    preset: settings.get('profile.preset'),
    tor: settings.get('tor.enabled'),
    osSandbox: !SANDBOX_DISABLED,
  });
  if (SANDBOX_DISABLED) {
    events.record({
      type: 'protection-disabled',
      severity: 'critical',
      what: 'os-sandbox',
      detail: 'Shadow was started with --no-sandbox. Renderer processes are not isolated by the operating system.',
    });
  }
});

app.on('window-all-closed', async () => {
  if (settings.get('privacy.clearOnExit')) {
    try {
      const s = session.fromPartition('persist:shadow-web');
      await s.clearStorageData({ storages: ['cookies', 'localstorage', 'indexdb', 'websql', 'serviceworkers', 'cachestorage'] });
      await s.clearCache();
      await s.clearAuthCache();
    } catch { /* shutting down anyway */ }
  }
  if (settings.get('sandbox.retentionDays')) quarantine.sweep(settings.get('sandbox.retentionDays'));
  tor.stop();
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });

// A web page must never be able to open another application.
app.on('web-contents-created', (_e, contents) => {
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
  contents.on('will-attach-webview', (event) => event.preventDefault());
});

// Never let a second instance hijack the profile.
if (!app.requestSingleInstanceLock()) app.quit();
app.on('second-instance', () => { if (win) { win.focus(); } });

module.exports = { settings, events, blocklists, firewall, analyzer, quarantine, tor };
