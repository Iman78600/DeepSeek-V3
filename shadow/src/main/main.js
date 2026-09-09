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

const { app, BrowserWindow, WebContentsView, session, ipcMain, shell, dialog, Menu } = require('electron');
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
const { registerIpc } = require('./ipc');

const SHADOW_HOME = path.join(os.homedir(), '.shadow');
const CHROME_HEIGHT = 88;   // height of the browser toolbar in CSS pixels

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
// Shadow renders untrusted content. Keep the strongest process isolation on.
app.enableSandbox();

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
  wc.on('will-navigate', async (event, targetUrl) => {
    if (!settings.get('soc.enabled')) return;
    if (targetUrl.startsWith('file://') && targetUrl.includes('interstitial.html')) return;
    if (analyzer.hasOverride(targetUrl)) return;

    const verdict = await analyzer.inspectUrl(targetUrl, { tabId: id, trigger: 'will-navigate' });
    tab.verdict = verdict;
    if (verdict.verdict === 'block' && settings.get('soc.blockOnUrlVerdict')) {
      event.preventDefault();
      wc.loadURL(interstitial('block', verdict, targetUrl));
    }
    broadcastTabs();
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

  wc.loadURL(url.startsWith('shadow://') ? homePageUrl() : url);
  activeTabId = id;
  layoutTabs();
  broadcastTabs();
  return tab;
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
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload', 'browser-preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,   // the chrome UI needs the preload bridge
    },
  });

  const chrome = new WebContentsView({
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload', 'browser-preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
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
    const tab = [...tabs.values()].find((t) => t.view.webContents.id === event.sender.id);
    if (!tab) return;

    const verdict = analyzer.inspectPage({
      url: observation.url,
      html: observation.html,
      observations: observation,
    });
    tab.verdict = verdict;

    if (verdict.verdict === 'block' && !analyzer.hasOverride(observation.url)) {
      tab.view.webContents.loadURL(interstitial('block', verdict, observation.url));
    }
    broadcastTabs();
  });

  ipcMain.on('shadow:page-alert', (event, alert) => {
    const tab = [...tabs.values()].find((t) => t.view.webContents.id === event.sender.id);
    if (!tab) return;
    tab.alerts.push(alert);
    events.record({ type: 'page-alert', tabId: tab.id, url: tab.url, ...alert });
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
    setActiveTab: (id) => { if (tabs.has(id)) { activeTabId = id; layoutTabs(); broadcastTabs(); } },
    getActiveTab: () => tabs.get(activeTabId),
    webSession,
    homePageUrl,
  });

  Menu.setApplicationMenu(null);
  createWindow();

  events.record({ type: 'startup', preset: settings.get('profile.preset'), tor: settings.get('tor.enabled') });
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
