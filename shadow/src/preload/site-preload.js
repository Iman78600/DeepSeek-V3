'use strict';
/**
 * Injected into every web page, in an isolated world.
 *
 * This file holds only the work that genuinely belongs in an isolated world:
 * observing the page and talking to the main process over IPC. It shares the
 * DOM with the page but not the JavaScript context, so it can read what was
 * rendered without the page being able to reach back and tamper with it.
 *
 * The fingerprint shield is deliberately NOT here. With contextIsolation on,
 * `navigator`, `Date` and the canvas prototypes in this file are separate
 * wrapper objects from the ones page script sees, so patching them here would
 * look correct and protect nothing. That work is injected into the page's own
 * world from the main process instead: see main/hardening/fingerprint-shield.js.
 */

const { ipcRenderer, contextBridge } = require('electron');

// --------------------------------------------------------------------------
// 1. Clipboard protection
//
// Crypto-clipper scripts listen for 'copy' and replace the copied text with an
// attacker's wallet address. DOM events do cross world boundaries, so this
// listener sees the same event the page handler does. It runs last, on the
// bubble phase, so it observes whatever the page wrote and can put the real
// selection back.
// --------------------------------------------------------------------------
const WALLET = /\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62}|4[0-9AB][0-9a-zA-Z]{93})\b/;

document.addEventListener('copy', (e) => {
  try {
    const selected = String(window.getSelection() || '').trim();
    const written = e.clipboardData && e.clipboardData.getData('text/plain');
    if (!written || !selected || written === selected) return;
    // Only intervene when the page swapped in something wallet-shaped that the
    // user did not select. Legitimate "copy this code" buttons are untouched.
    if (WALLET.test(written) && !WALLET.test(selected)) {
      e.preventDefault();
      e.clipboardData.setData('text/plain', selected);
      ipcRenderer.send('shadow:page-alert', {
        id: 'clipboard-swap',
        severity: 'critical',
        title: 'This page tried to change what you copied',
        detail: 'It replaced your selection with a cryptocurrency address. Shadow put your original text back.',
      });
    }
  } catch { /* never break copy */ }
}, false);

// --------------------------------------------------------------------------
// 2. Report the rendered page back to the analyst
//
// The HTML the server sent and the page the browser ended up showing are often
// very different. Phishing kits assemble their login form in JavaScript
// precisely so that a scanner reading the raw response sees nothing.
// --------------------------------------------------------------------------
function observePage() {
  const scripts = [...document.querySelectorAll('script[src]')].map((s) => s.src).slice(0, 100);

  const forms = [...document.forms].map((f) => ({
    action: f.action,
    method: f.method,
    hasPassword: Boolean(f.querySelector('input[type="password"]')),
    fieldNames: [...f.elements].map((el) => el.name || el.id || el.type).filter(Boolean).slice(0, 30),
  }));

  const frames = [...document.querySelectorAll('iframe')].map((f) => {
    let hidden = false;
    try {
      const cs = window.getComputedStyle(f);
      hidden = cs.display === 'none' || cs.visibility === 'hidden'
        || parseFloat(cs.opacity || '1') < 0.05
        || f.offsetWidth <= 1 || f.offsetHeight <= 1;
    } catch { /* detached */ }
    return { src: f.src, hidden };
  }).slice(0, 50);

  return {
    url: location.href,
    title: document.title,
    scripts,
    forms,
    frames,
    passwordFields: document.querySelectorAll('input[type="password"]').length,
    externalScriptCount: scripts.filter((s) => {
      try { return new URL(s).hostname !== location.hostname; } catch { return false; }
    }).length,
    hiddenFrameCount: frames.filter((f) => f.hidden).length,
    html: document.documentElement ? document.documentElement.outerHTML.slice(0, 2000000) : '',
  };
}

function report(stage) {
  try { ipcRenderer.send('shadow:page-observed', { stage, ...observePage() }); }
  catch { /* main process gone */ }
}

document.addEventListener('DOMContentLoaded', () => report('dom-ready'));
window.addEventListener('load', () => setTimeout(() => report('load'), 400));

// Re-check when a password form appears after load, which is exactly how a
// single-page phishing kit avoids being caught by a first-pass scan.
let mutationBudget = 3;
const observer = new MutationObserver((records) => {
  if (mutationBudget <= 0) return;
  const addedForm = records.some((r) => [...r.addedNodes].some((n) => n.nodeType === 1
    && (n.tagName === 'FORM' || (n.querySelector && n.querySelector('input[type="password"]')))));
  if (addedForm) { mutationBudget--; report('mutation'); }
});
document.addEventListener('DOMContentLoaded', () => {
  try { observer.observe(document.documentElement, { childList: true, subtree: true }); }
  catch { /* no document element yet */ }
});

// --------------------------------------------------------------------------
// 3. Shadow's own pages
//
// The block page and the home page are rendered inside a tab, so they get this
// preload rather than the chrome one. They need a tiny, explicit bridge: three
// actions, nothing else. Web content never reaches this, because it is only
// exposed for file:// pages Shadow itself loaded.
// --------------------------------------------------------------------------
const isShadowPage = location.protocol === 'file:'
  && /\/(?:interstitial|home)\.html$/.test(location.pathname);

if (isShadowPage) {
  const call = (channel, ...args) => ipcRenderer.invoke(channel, ...args)
    .then((res) => (res && res.ok === false ? Promise.reject(new Error(res.error)) : (res ? res.data : undefined)));

  contextBridge.exposeInMainWorld('shadow', {
    tabs: {
      back: () => call('tab:back'),
      open: (url) => call('tab:new', url),
      navigate: (url) => call('tab:navigate', url),
    },
    soc: {
      proceed: (url) => call('soc:proceed', url),
      trustSite: (hostname) => call('soc:trust-site', hostname),
    },
  });
}
