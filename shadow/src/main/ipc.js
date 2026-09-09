'use strict';
/**
 * Every channel the browser UI can call. This is the trust boundary between
 * the chrome UI and the privileged main process, so each handler validates
 * its own input rather than assuming the caller is well-behaved.
 */

const path = require('path');
const fs = require('fs');
const os = require('os');

function registerIpc(ctx) {
  const {
    ipcMain, app, dialog, shell, win,
    settings, events, blocklists, firewall, analyzer, quarantine, tor, detonator,
    tabs, createTab, closeTab, setActiveTab, getActiveTab, webSession, homePageUrl,
  } = ctx;

  const handle = (channel, fn) => ipcMain.handle(channel, async (event, ...args) => {
    try { return { ok: true, data: await fn(...args) }; }
    catch (err) { return { ok: false, error: err.message, code: err.code || null }; }
  });

  // --- Tabs ---------------------------------------------------------------
  handle('tab:new', (url) => {
    const tab = createTab(typeof url === 'string' && url ? url : undefined);
    return tab.id;
  });
  handle('tab:close', (id) => { closeTab(Number(id)); return true; });
  handle('tab:activate', (id) => { setActiveTab(Number(id)); return true; });

  handle('tab:navigate', async (raw) => {
    const tab = getActiveTab();
    if (!tab) throw new Error('no active tab');
    const target = normalizeAddress(String(raw || ''), settings);
    if (target === 'shadow://home') { tab.view.webContents.loadURL(homePageUrl()); return target; }
    await tab.view.webContents.loadURL(target);
    return target;
  });

  handle('tab:back', () => { const t = getActiveTab(); if (t) t.view.webContents.navigationHistory.goBack(); return true; });
  handle('tab:forward', () => { const t = getActiveTab(); if (t) t.view.webContents.navigationHistory.goForward(); return true; });
  handle('tab:reload', () => { const t = getActiveTab(); if (t) t.view.webContents.reload(); return true; });
  handle('tab:stop', () => { const t = getActiveTab(); if (t) t.view.webContents.stop(); return true; });

  // --- The analyst --------------------------------------------------------
  handle('soc:inspect', (url) => analyzer.inspectUrl(String(url), { trigger: 'manual' }));
  handle('soc:report', () => {
    const t = getActiveTab();
    return t && t.verdict ? t.verdict : null;
  });
  handle('soc:proceed', (url) => {
    analyzer.override(String(url));
    events.record({ type: 'user-override', url: String(url) });
    const t = getActiveTab();
    if (t) t.view.webContents.loadURL(String(url));
    return true;
  });
  handle('soc:trust-site', (hostname) => {
    analyzer.trustOrigin(String(hostname));
    const list = settings.get('soc.allowlist') || [];
    if (!list.includes(String(hostname))) settings.set('soc.allowlist', [...list, String(hostname)]);
    events.record({ type: 'user-allowlist', hostname: String(hostname) });
    return settings.get('soc.allowlist');
  });

  // --- Events / dashboard --------------------------------------------------
  handle('events:query', (opts) => events.query(opts || {}));
  handle('events:stats', (windowMs) => events.stats(Number(windowMs) || undefined));
  handle('events:clear', () => { events.clear(); return true; });
  handle('events:export', async () => {
    const { canceled, filePath } = await dialog.showSaveDialog(win(), {
      title: 'Export SOC event log',
      defaultPath: path.join(os.homedir(), `shadow-soc-${new Date().toISOString().slice(0, 10)}.jsonl`),
      filters: [{ name: 'JSON Lines', extensions: ['jsonl'] }],
    });
    if (canceled || !filePath) return null;
    return events.export(filePath);
  });

  // --- Firewall ------------------------------------------------------------
  handle('firewall:summary', () => ({ ...firewall.summary(), lists: blocklists.summary() }));
  handle('firewall:add-rule', (rule) => {
    if (!rule || typeof rule !== 'object' || !rule.match) throw new Error('a rule needs a match');
    const added = firewall.addRule(rule);
    settings.set('firewall.customRules', firewall.rules);
    events.record({ type: 'firewall-rule-added', rule: added });
    return added;
  });
  handle('firewall:remove-rule', (id) => {
    const removed = firewall.removeRule(String(id));
    settings.set('firewall.customRules', firewall.rules);
    return removed;
  });
  handle('firewall:block-domain', (domain) => {
    const ok = blocklists.addCustom(String(domain));
    if (!ok) throw new Error(`"${domain}" is not a valid domain`);
    events.record({ type: 'firewall-domain-blocked', domain: String(domain) });
    return blocklists.summary();
  });
  handle('firewall:unblock-domain', (domain) => blocklists.removeCustom(String(domain)));

  // --- Downloads / sandbox --------------------------------------------------
  handle('downloads:list', () => quarantine.list());
  handle('downloads:report', (id) => {
    const rec = quarantine.get(String(id));
    if (!rec) throw new Error('unknown download');
    return {
      id: rec.id,
      name: rec.originalName,
      state: rec.state,
      sourceUrl: rec.sourceUrl,
      report: rec.report,
      verdict: rec.verdict,
      detonation: rec.detonation || null,
    };
  });
  handle('downloads:release', async (id, force) => {
    const rec = quarantine.get(String(id));
    if (!rec) throw new Error('unknown download');

    if (force) {
      const { response } = await dialog.showMessageBox(win(), {
        type: 'warning',
        title: 'Release a file Shadow blocked?',
        message: `Shadow rated "${rec.originalName}" ${rec.verdict.score}/100 (${rec.verdict.severity}).`,
        detail: `${rec.verdict.reasons.slice(0, 3).map((r) => `- ${r.title}`).join('\n')}\n\n` +
          'Releasing puts it in your Downloads folder where you can run it. ' +
          'Do this only if you know exactly what this file is.',
        buttons: ['Cancel', 'Release it anyway'],
        defaultId: 0,
        cancelId: 0,
      });
      if (response !== 1) return null;
    }
    return quarantine.release(String(id), { force: Boolean(force) });
  });
  handle('downloads:delete', (id) => quarantine.discard(String(id)));
  handle('downloads:open-folder', () => { shell.openPath(quarantine.dir); return quarantine.dir; });
  handle('downloads:detonate', async (id) => {
    const rec = quarantine.get(String(id));
    if (!rec) throw new Error('unknown download');
    rec.detonation = await detonator.run(rec.savePath, { originalName: rec.originalName });
    return rec.detonation;
  });
  handle('downloads:detonation-available', () => detonator.available());

  // --- Tor / proxy -----------------------------------------------------------
  handle('tor:status', () => tor.status());
  handle('tor:start', async () => {
    const status = await tor.start();
    await webSession.setProxy(tor.proxyConfig());
    return status;
  });
  handle('tor:stop', async () => {
    const status = tor.stop();
    await webSession.setProxy(tor.proxyConfig());
    return status;
  });
  handle('tor:new-identity', async () => {
    const result = await tor.newIdentity();
    if (result.ok) {
      await webSession.clearStorageData({ storages: ['cookies'] });
      await webSession.clearAuthCache();
    }
    return result;
  });
  handle('tor:verify', () => tor.verify(webSession));

  // --- Settings ---------------------------------------------------------------
  handle('settings:all', () => settings.all());
  handle('settings:set', async (key, value) => {
    const result = settings.set(String(key), value);
    await applySettingChange(String(key));
    events.record({ type: 'setting-changed', key: String(key), value });
    return result;
  });
  handle('settings:preset', async (name) => {
    const preset = settings.applyPreset(String(name));
    await applySettingChange('*');
    events.record({ type: 'preset-applied', preset: String(name) });
    return { preset, settings: settings.all() };
  });
  handle('settings:presets', () => require('../../config/presets.json'));
  handle('settings:reset', async () => { settings.reset(); await applySettingChange('*'); return settings.all(); });

  // Some settings need work beyond writing the file.
  async function applySettingChange(key) {
    if (key === '*' || key.startsWith('tor.') || key.startsWith('proxy.')) {
      if (settings.get('tor.enabled') && tor.state !== 'running' && tor.state !== 'external') {
        await tor.start();
      }
      if (!settings.get('tor.enabled') && (tor.state === 'running')) tor.stop();
      await webSession.setProxy(tor.proxyConfig());
    }
    if (key === '*' || key === 'hardening.spoofUserAgent' || key === 'hardening.userAgent') {
      const { genericUserAgent } = require('./hardening/profile');
      webSession.setUserAgent(
        settings.get('hardening.spoofUserAgent')
          ? (settings.get('hardening.userAgent') || genericUserAgent())
          : app.userAgentFallback,
        'en-US,en;q=0.9');
    }
    if (key === 'firewall.customRules') firewall.setRules(settings.get('firewall.customRules') || []);
    if (key === '*' || key.startsWith('hardening.')) {
      for (const tab of tabs.values()) {
        try { tab.view.webContents.reload(); } catch { /* closing */ }
      }
    }
  }

  // --- Privacy ------------------------------------------------------------------
  handle('privacy:clear-now', async () => {
    await webSession.clearStorageData();
    await webSession.clearCache();
    await webSession.clearAuthCache();
    events.record({ type: 'privacy-cleared', manual: true });
    return true;
  });

  // --- App ------------------------------------------------------------------------
  handle('app:version', () => ({
    shadow: app.getVersion(),
    electron: process.versions.electron,
    chromium: process.versions.chrome,
    node: process.versions.node,
    platform: `${os.type()} ${os.release()} ${os.arch()}`,
  }));
  handle('app:open-external', async (url) => {
    // A link out of Shadow leaves Shadow's protection, so say so first.
    const { response } = await dialog.showMessageBox(win(), {
      type: 'question',
      title: 'Open outside Shadow?',
      message: 'This will open in your normal browser.',
      detail: `${String(url).slice(0, 200)}\n\nOutside Shadow there is no analyst, no firewall and no download sandbox.`,
      buttons: ['Cancel', 'Open anyway'],
      defaultId: 0,
      cancelId: 0,
    });
    if (response !== 1) return false;
    await shell.openExternal(String(url));
    return true;
  });
}

/** Turn whatever the user typed into a URL or a search. */
function normalizeAddress(input, settings) {
  const text = input.trim();
  if (!text) return 'shadow://home';
  if (/^shadow:\/\//i.test(text)) return text;

  const looksLikeUrl = /^[a-z][a-z0-9+.-]*:\/\//i.test(text)
    || (/^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?(\/|$)/i.test(text) && !text.includes(' '))
    || /^localhost(:\d+)?(\/|$)/i.test(text);

  if (looksLikeUrl) {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) return text;
    return `https://${text}`;
  }
  const engine = (settings && settings.get('privacy.searchEngine')) || 'https://duckduckgo.com/?q=%s';
  return engine.replace('%s', encodeURIComponent(text));
}

module.exports = { registerIpc, normalizeAddress };
