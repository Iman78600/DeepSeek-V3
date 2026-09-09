'use strict';
/**
 * One place that answers "is this URL allowed to be loaded / opened".
 *
 * Why this exists: several privileged IPC handlers used to take a URL string
 * from the browser UI and hand it straight to loadURL() or shell.openExternal().
 * That is fine while the UI is well-behaved, but the UI is a renderer process,
 * and a renderer is exactly what a browser exploit takes over first. A single
 * `file:///home/you/.ssh/id_rsa` or a custom protocol handler is enough to turn
 * a rendering bug into file theft or code execution.
 *
 * So: deny by default, allow a named list, and make every caller go through here.
 */

const path = require('path');

/** Schemes a tab may navigate to. */
const NAVIGABLE_SCHEMES = new Set(['http:', 'https:']);

/** Schemes Shadow may hand to the operating system. */
const EXTERNAL_SCHEMES = new Set(['http:', 'https:', 'mailto:']);

/**
 * Schemes that must never be navigated to from anywhere, even by the user.
 * javascript: and data: run attacker-chosen code in whatever origin is current.
 */
const ALWAYS_FORBIDDEN = new Set([
  'javascript:', 'data:', 'blob:', 'vbscript:', 'jscript:', 'chrome:',
  'chrome-extension:', 'devtools:', 'view-source:', 'ws:', 'wss:',
  'filesystem:', 'intent:', 'ms-msdt:', 'search-ms:', 'ms-officecmd:',
]);

class UrlPolicyError extends Error {
  constructor(message, url) {
    super(message);
    this.name = 'UrlPolicyError';
    this.code = 'URL_REFUSED';
    this.url = String(url).slice(0, 200);
  }
}

function parse(raw) {
  try { return new URL(String(raw)); } catch { return null; }
}

/**
 * True for any file inside Shadow's own renderer directory: the pages and the
 * stylesheet and script they load. Resolves the path first, so a traversal
 * that lands outside the directory is not internal however it is spelled.
 */
function isInternalAsset(raw, rendererDir) {
  if (!rendererDir) return false;
  let u;
  try { u = new URL(String(raw)); } catch { return false; }
  if (u.protocol !== 'file:') return false;

  let filePath;
  try { filePath = decodeURIComponent(u.pathname); } catch { return false; }
  if (process.platform === 'win32' && /^\/[a-z]:/i.test(filePath)) filePath = filePath.slice(1);

  const resolved = path.resolve(filePath);
  const base = path.resolve(rendererDir);
  return resolved === base || resolved.startsWith(base + path.sep);
}

/**
 * True only for Shadow's own bundled pages, identified by real filesystem
 * position rather than by how the path is spelled. Prevents a crafted
 * `file:///tmp/evil/interstitial.html` from being treated as internal.
 */
function isInternalPage(raw, rendererDir) {
  const u = parse(raw);
  if (!u || u.protocol !== 'file:') return false;
  if (!rendererDir) return false;
  let filePath;
  try { filePath = decodeURIComponent(u.pathname); } catch { return false; }
  if (process.platform === 'win32' && /^\/[a-z]:/i.test(filePath)) filePath = filePath.slice(1);

  const resolved = path.resolve(filePath);
  const base = path.resolve(rendererDir);
  const inside = resolved === base || resolved.startsWith(base + path.sep);
  if (!inside) return false;
  return ['index.html', 'home.html', 'interstitial.html'].includes(path.basename(resolved));
}

/**
 * Can a tab load this?
 * @param {string} raw
 * @param {object} [opts] { rendererDir, allowInternal }
 */
function isNavigable(raw, opts = {}) {
  const u = parse(raw);
  if (!u) return false;
  if (ALWAYS_FORBIDDEN.has(u.protocol)) return false;
  if (opts.allowInternal !== false && isInternalPage(raw, opts.rendererDir)) return true;
  if (u.protocol === 'about:') return raw === 'about:blank';
  return NAVIGABLE_SCHEMES.has(u.protocol);
}

/** Throwing form, for privileged IPC handlers. */
function assertNavigable(raw, opts = {}) {
  if (!isNavigable(raw, opts)) {
    const u = parse(raw);
    throw new UrlPolicyError(
      u ? `Shadow will not open a "${u.protocol}" address. Only http and https pages are allowed.`
        : 'That is not a valid web address.',
      raw);
  }
  return String(raw);
}

/** Can this be handed to the operating system's default handler? */
function isSafeExternal(raw) {
  const u = parse(raw);
  if (!u) return false;
  return EXTERNAL_SCHEMES.has(u.protocol);
}

function assertSafeExternal(raw) {
  if (!isSafeExternal(raw)) {
    const u = parse(raw);
    throw new UrlPolicyError(
      `Shadow will not hand a "${u ? u.protocol : 'malformed'}" address to your system. `
      + 'Custom protocols are how a web page gets another program to run.',
      raw);
  }
  return String(raw);
}

module.exports = {
  isNavigable, assertNavigable, isSafeExternal, assertSafeExternal,
  isInternalPage, isInternalAsset, UrlPolicyError,
  NAVIGABLE_SCHEMES, EXTERNAL_SCHEMES, ALWAYS_FORBIDDEN,
};
