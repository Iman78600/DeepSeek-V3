'use strict';
/**
 * Bridge between Shadow's own UI and the main process.
 * Nothing here gives the UI arbitrary access: every method maps to one
 * named IPC channel that the main process validates.
 */

const { contextBridge, ipcRenderer } = require('electron');

const call = (channel, ...args) => ipcRenderer.invoke(channel, ...args)
  .then((res) => {
    if (res && res.ok === false) {
      const err = new Error(res.error || 'request failed');
      err.code = res.code;
      throw err;
    }
    return res ? res.data : undefined;
  });

const on = (channel, fn) => {
  const wrapped = (_event, payload) => fn(payload);
  ipcRenderer.on(channel, wrapped);
  return () => ipcRenderer.removeListener(channel, wrapped);
};

contextBridge.exposeInMainWorld('shadow', {
  tabs: {
    open: (url) => call('tab:new', url),
    close: (id) => call('tab:close', id),
    activate: (id) => call('tab:activate', id),
    navigate: (url) => call('tab:navigate', url),
    back: () => call('tab:back'),
    forward: () => call('tab:forward'),
    reload: () => call('tab:reload'),
    stop: () => call('tab:stop'),
    onUpdate: (fn) => on('shadow:tabs', fn),
  },
  soc: {
    inspect: (url) => call('soc:inspect', url),
    report: () => call('soc:report'),
    proceed: (url) => call('soc:proceed', url),
    trustSite: (hostname) => call('soc:trust-site', hostname),
  },
  events: {
    query: (opts) => call('events:query', opts),
    stats: (windowMs) => call('events:stats', windowMs),
    clear: () => call('events:clear'),
    export: () => call('events:export'),
    onFirewall: (fn) => on('shadow:firewall-event', fn),
  },
  firewall: {
    summary: () => call('firewall:summary'),
    addRule: (rule) => call('firewall:add-rule', rule),
    removeRule: (id) => call('firewall:remove-rule', id),
    blockDomain: (d) => call('firewall:block-domain', d),
    unblockDomain: (d) => call('firewall:unblock-domain', d),
  },
  downloads: {
    list: () => call('downloads:list'),
    report: (id) => call('downloads:report', id),
    release: (id, force) => call('downloads:release', id, force),
    remove: (id) => call('downloads:delete', id),
    openFolder: () => call('downloads:open-folder'),
    detonate: (id) => call('downloads:detonate', id),
    detonationAvailable: () => call('downloads:detonation-available'),
    onStarted: (fn) => on('shadow:download-started', fn),
    onProgress: (fn) => on('shadow:download-progress', fn),
    onScanned: (fn) => on('shadow:download-scanned', fn),
    onFailed: (fn) => on('shadow:download-failed', fn),
  },
  tor: {
    status: () => call('tor:status'),
    start: () => call('tor:start'),
    stop: () => call('tor:stop'),
    newIdentity: () => call('tor:new-identity'),
    verify: () => call('tor:verify'),
  },
  settings: {
    all: () => call('settings:all'),
    set: (key, value) => call('settings:set', key, value),
    presets: () => call('settings:presets'),
    applyPreset: (name) => call('settings:preset', name),
    reset: () => call('settings:reset'),
  },
  privacy: {
    clearNow: () => call('privacy:clear-now'),
  },
  app: {
    version: () => call('app:version'),
    openExternal: (url) => call('app:open-external', url),
    onBoot: (fn) => on('shadow:boot', fn),
  },
});
