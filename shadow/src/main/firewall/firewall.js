'use strict';
/**
 * Shadow's network firewall.
 *
 * The decision logic lives in `decideRequest`, which is a pure function of
 * (request, config) so it can be unit tested without Electron. `attach()` is
 * the thin Electron binding that wires it to session.webRequest.
 *
 * Everything a page tries to fetch - scripts, images, XHR, websockets,
 * beacons - passes through here before a socket is opened.
 */

const { classifyHost, BLOCKED_PORTS, evaluate } = require('./rules');
const { splitHost } = require('../soc/heuristics/url-heuristics');

const DEFAULT_PORTS = { 'http:': 80, 'https:': 443, 'ws:': 80, 'wss:': 443, 'ftp:': 21 };

// Resource types a page can request. Used for per-type policy.
const HIGH_RISK_TYPES = new Set(['script', 'subFrame', 'object', 'xhr', 'webSocket']);

function parseRequest(details) {
  let u;
  try { u = new URL(details.url); } catch { return null; }
  const hostname = u.hostname.toLowerCase();
  const port = u.port || DEFAULT_PORTS[u.protocol] || '';
  let initiatorHost = '';
  const initiator = details.referrer || details.initiator || details.webContentsUrl || '';
  try { if (initiator) initiatorHost = new URL(initiator).hostname.toLowerCase(); } catch { /* ignore */ }
  const thirdParty = Boolean(initiatorHost)
    && splitHost(initiatorHost).registrable !== splitHost(hostname).registrable;

  return {
    url: details.url,
    hostname,
    scheme: u.protocol.replace(':', ''),
    port: String(port),
    path: u.pathname,
    method: details.method || 'GET',
    resourceType: details.resourceType || 'other',
    initiatorHost,
    thirdParty,
  };
}

/**
 * The whole firewall policy in one pure function.
 *
 * @param {object} req    output of parseRequest
 * @param {object} config { settings, blocklists, rules, allowLocalhost }
 * @returns {{action:'allow'|'block'|'upgrade', reason?, category?, detail?, redirectURL?}}
 */
function decideRequest(req, config = {}) {
  const { settings, blocklists, rules } = config;
  const get = (k, d) => (settings && settings.get(k) !== undefined ? settings.get(k) : d);

  if (!req) return { action: 'block', reason: 'unparseable', category: 'malformed', detail: 'The request URL could not be parsed.' };

  // 1. Explicit user rules run first and can allow or block anything.
  const ruled = evaluate(rules, req);
  if (ruled && ruled.action === 'allow') return { action: 'allow', reason: 'user-rule', rule: ruled.rule };
  if (ruled && ruled.action === 'block') {
    return { action: 'block', reason: 'user-rule', category: 'custom',
      detail: ruled.rule.comment || `Blocked by your firewall rule ${ruled.rule.id || ''}`.trim() };
  }

  // 2. Schemes. Anything that is not web traffic never leaves the browser.
  const allowedSchemes = new Set(['http', 'https', 'ws', 'wss', 'data', 'blob', 'about', 'chrome-extension', 'devtools', 'file']);
  if (!allowedSchemes.has(req.scheme)) {
    return { action: 'block', reason: 'scheme', category: 'protocol',
      detail: `Shadow does not allow the "${req.scheme}:" protocol. External handlers are a common way to launch local programs from a web page.` };
  }
  if (req.scheme === 'file' && req.resourceType !== 'mainFrame') {
    return { action: 'block', reason: 'file-subresource', category: 'protocol',
      detail: 'A web page tried to read a local file.' };
  }

  // 3. Ports. Cross-protocol attacks use the browser to speak SMTP, Redis, SSH.
  if (req.port && BLOCKED_PORTS.has(Number(req.port))) {
    return { action: 'block', reason: 'port', category: 'protocol',
      detail: `Port ${req.port} is not a web port. Browsers are used to smuggle commands into services on ports like this.` };
  }

  // 4. Private network / SSRF / DNS-rebinding protection.
  //    A page on the public internet must not reach your LAN or localhost.
  if (get('firewall.blockPrivateNetwork', true)) {
    const local = classifyHost(req.hostname);
    if (local && local.private) {
      const initiatorLocal = req.initiatorHost ? classifyHost(req.initiatorHost) : null;
      const initiatorIsLocal = Boolean(initiatorLocal && initiatorLocal.private);
      const userTyped = req.resourceType === 'mainFrame' && !req.initiatorHost;
      if (local.metadata) {
        return { action: 'block', reason: 'metadata', category: 'ssrf',
          detail: 'This is a cloud metadata endpoint. Reaching it from a web page is how cloud credentials get stolen.' };
      }
      if (!initiatorIsLocal && !userTyped) {
        return { action: 'block', reason: 'private-network', category: 'ssrf',
          detail: `A page on the internet tried to reach ${req.hostname} (${local.label}). That is your own network, not the site's. This is how routers, printers and local dashboards get attacked from a browser tab.` };
      }
    }
  }

  // 5. Blocklists.
  if (blocklists) {
    const hits = blocklists.match(req.hostname, req.url);
    const worst = hits.sort((a, b) => b.score - a.score)[0];
    if (worst) {
      const threshold = get('firewall.blockThreshold', 10);
      if (worst.score >= threshold) {
        return { action: 'block', reason: 'blocklist', category: worst.list,
          detail: worst.detail, listHit: worst };
      }
    }
  }

  // 6. HTTPS-only mode: upgrade or refuse plaintext.
  if (req.scheme === 'http' && get('firewall.httpsOnly', true)) {
    const local = classifyHost(req.hostname);
    if (!local || !local.private) {
      const upgraded = req.url.replace(/^http:/i, 'https:');
      return { action: 'upgrade', reason: 'https-only', redirectURL: upgraded,
        detail: 'Shadow upgraded this request to HTTPS.' };
    }
  }

  // 7. Third-party high-risk subresources in lockdown mode.
  if (get('firewall.lockdown', false) && req.thirdParty && HIGH_RISK_TYPES.has(req.resourceType)) {
    return { action: 'block', reason: 'lockdown', category: 'third-party',
      detail: `Lockdown mode: ${req.hostname} is a third-party ${req.resourceType} on a page from ${req.initiatorHost}.` };
  }

  // 8. Beacons. These exist only to phone home as you leave.
  if (req.resourceType === 'ping' || (req.resourceType === 'beacon' && get('firewall.blockTrackers', true))) {
    return { action: 'block', reason: 'beacon', category: 'tracker',
      detail: 'Blocked a tracking beacon.' };
  }

  return { action: 'allow' };
}

/**
 * Response-header hardening. Runs on every response.
 * Returns a new headers object, or null to leave it untouched.
 */
function hardenResponseHeaders(details, config = {}) {
  const { settings } = config;
  const get = (k, d) => (settings && settings.get(k) !== undefined ? settings.get(k) : d);
  if (!get('hardening.rewriteHeaders', true)) return null;
  if (details.resourceType !== 'mainFrame' && details.resourceType !== 'subFrame') return null;

  const headers = { ...details.responseHeaders };
  const setIfAbsent = (name, value) => {
    const existing = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
    if (!existing) headers[name] = [value];
  };
  const drop = (name) => {
    for (const k of Object.keys(headers)) if (k.toLowerCase() === name.toLowerCase()) delete headers[k];
  };

  setIfAbsent('X-Content-Type-Options', 'nosniff');
  setIfAbsent('Referrer-Policy', 'strict-origin-when-cross-origin');
  setIfAbsent('X-Frame-Options', 'SAMEORIGIN');
  setIfAbsent('Permissions-Policy',
    'accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), ' +
    'display-capture=(), document-domain=(), encrypted-media=(), geolocation=(), ' +
    'gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), ' +
    'publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), ' +
    'xr-spatial-tracking=(), idle-detection=(), local-fonts=()');

  // Strip headers that leak the browsing session outward.
  if (get('hardening.stripServerHints', true)) {
    drop('Public-Key-Pins');
    drop('Public-Key-Pins-Report-Only');
  }

  return headers;
}

/**
 * Request-header hardening: remove identifying headers before they go out.
 */
function hardenRequestHeaders(details, config = {}) {
  const { settings } = config;
  const get = (k, d) => (settings && settings.get(k) !== undefined ? settings.get(k) : d);
  const headers = { ...details.requestHeaders };
  const drop = (name) => {
    for (const k of Object.keys(headers)) if (k.toLowerCase() === name.toLowerCase()) delete headers[k];
  };

  if (get('hardening.stripClientHints', true)) {
    for (const h of ['Sec-CH-UA-Full-Version', 'Sec-CH-UA-Full-Version-List',
      'Sec-CH-UA-Arch', 'Sec-CH-UA-Model', 'Sec-CH-UA-Bitness',
      'Sec-CH-UA-Platform-Version', 'Sec-CH-UA-WoW64', 'Sec-CH-Prefers-Color-Scheme',
      'Sec-CH-Prefers-Reduced-Motion', 'Device-Memory', 'Downlink', 'ECT', 'RTT',
      'Viewport-Width', 'Width', 'DPR', 'X-Requested-With']) drop(h);
  }
  if (get('hardening.dntAndGpc', true)) {
    headers['DNT'] = ['1'];
    headers['Sec-GPC'] = ['1'];
  }
  if (get('hardening.trimReferrer', true)) {
    const refKey = Object.keys(headers).find((k) => k.toLowerCase() === 'referer');
    if (refKey) {
      try {
        const r = new URL(headers[refKey][0]);
        headers[refKey] = [`${r.origin}/`]; // origin only, no path or query
      } catch { drop('Referer'); }
    }
  }
  return headers;
}

class Firewall {
  constructor({ settings, blocklists, events } = {}) {
    this.settings = settings;
    this.blocklists = blocklists;
    this.events = events;
    this.rules = [];
    this.stats = { seen: 0, blocked: 0, upgraded: 0, byCategory: {} };
    this.recentBlocks = [];
  }

  setRules(rules) { this.rules = Array.isArray(rules) ? rules : []; }

  addRule(rule) {
    this.rules.unshift({ id: `r${Date.now().toString(36)}`, enabled: true, ...rule });
    return this.rules[0];
  }

  removeRule(id) {
    const before = this.rules.length;
    this.rules = this.rules.filter((r) => r.id !== id);
    return this.rules.length !== before;
  }

  check(details) {
    this.stats.seen++;
    const req = parseRequest(details);
    const decision = decideRequest(req, {
      settings: this.settings,
      blocklists: this.blocklists,
      rules: this.rules,
    });

    if (decision.action === 'block') {
      this.stats.blocked++;
      const cat = decision.category || decision.reason || 'other';
      this.stats.byCategory[cat] = (this.stats.byCategory[cat] || 0) + 1;
      const entry = {
        at: Date.now(),
        url: req ? req.url : details.url,
        hostname: req ? req.hostname : '',
        resourceType: req ? req.resourceType : '',
        initiator: req ? req.initiatorHost : '',
        reason: decision.reason,
        category: cat,
        detail: decision.detail,
      };
      this.recentBlocks.unshift(entry);
      if (this.recentBlocks.length > 500) this.recentBlocks.length = 500;
      if (this.events) this.events.record({ type: 'firewall-block', ...entry });
    } else if (decision.action === 'upgrade') {
      this.stats.upgraded++;
    }
    return decision;
  }

  /** Wire this firewall into an Electron session. */
  attach(session) {
    const wr = session.webRequest;

    wr.onBeforeRequest({ urls: ['<all_urls>'] }, (details, callback) => {
      const decision = this.check(details);
      if (decision.action === 'block') return callback({ cancel: true });
      if (decision.action === 'upgrade') return callback({ redirectURL: decision.redirectURL });
      return callback({});
    });

    wr.onBeforeSendHeaders({ urls: ['<all_urls>'] }, (details, callback) => {
      callback({ requestHeaders: hardenRequestHeaders(details, { settings: this.settings }) });
    });

    wr.onHeadersReceived({ urls: ['<all_urls>'] }, (details, callback) => {
      const responseHeaders = hardenResponseHeaders(details, { settings: this.settings });
      callback(responseHeaders ? { responseHeaders } : {});
    });

    return this;
  }

  summary() {
    return {
      ...this.stats,
      rules: this.rules.length,
      recent: this.recentBlocks.slice(0, 50),
    };
  }
}

module.exports = { Firewall, decideRequest, parseRequest, hardenRequestHeaders, hardenResponseHeaders };
