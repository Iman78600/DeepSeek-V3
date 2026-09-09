'use strict';
/**
 * Firewall rule model and IP reasoning.
 *
 * Two jobs:
 *  1. Decide whether a destination IP is somewhere a web page has no business
 *     reaching (your router, your NAS, cloud metadata services, localhost).
 *  2. Evaluate an ordered list of user rules against a request.
 */

// ---------------------------------------------------------------------------
// IP helpers
// ---------------------------------------------------------------------------

function ipv4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255 || p === '' ) return null;
    n = (n * 256) + v;
  }
  return n;
}

function cidrToRange(cidr) {
  const [base, bitsStr] = cidr.split('/');
  const bits = Number(bitsStr);
  const start = ipv4ToInt(base);
  if (start === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const size = 2 ** (32 - bits);
  const network = Math.floor(start / size) * size;
  return [network, network + size - 1];
}

/** Networks a website should never be able to reach through your browser. */
const PRIVATE_V4 = [
  ['0.0.0.0/8',        'this network'],
  ['10.0.0.0/8',       'private LAN'],
  ['100.64.0.0/10',    'carrier-grade NAT'],
  ['127.0.0.0/8',      'your own machine (loopback)'],
  ['169.254.0.0/16',   'link-local / cloud metadata'],
  ['172.16.0.0/12',    'private LAN'],
  ['192.0.0.0/24',     'IETF protocol assignments'],
  ['192.0.2.0/24',     'documentation range'],
  ['192.168.0.0/16',   'home/office LAN'],
  ['198.18.0.0/15',    'benchmark range'],
  ['198.51.100.0/24',  'documentation range'],
  ['203.0.113.0/24',   'documentation range'],
  ['224.0.0.0/4',      'multicast'],
  ['240.0.0.0/4',      'reserved'],
].map(([cidr, label]) => ({ cidr, label, range: cidrToRange(cidr) }));

/** Cloud metadata endpoints. Reaching these from a page is credential theft. */
const METADATA_HOSTS = new Set([
  '169.254.169.254', 'metadata.google.internal', 'metadata.goog',
  '100.100.100.200', 'fd00:ec2::254', '169.254.170.2',
]);

function classifyIp(ip) {
  const addr = String(ip || '').replace(/^\[|\]$/g, '').toLowerCase();
  if (!addr) return null;

  if (addr.includes(':')) {
    if (addr === '::1') return { private: true, label: 'your own machine (loopback)' };
    if (addr.startsWith('fe80')) return { private: true, label: 'link-local' };
    if (/^f[cd]/.test(addr)) return { private: true, label: 'private IPv6 (ULA)' };
    if (addr === '::') return { private: true, label: 'unspecified address' };
    // IPv4-mapped IPv6, e.g. ::ffff:192.168.1.1
    const mapped = addr.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return classifyIp(mapped[1]);
    return null;
  }

  const n = ipv4ToInt(addr);
  if (n === null) return null;
  for (const entry of PRIVATE_V4) {
    if (entry.range && n >= entry.range[0] && n <= entry.range[1]) {
      return { private: true, label: entry.label, cidr: entry.cidr };
    }
  }
  return null;
}

/** Hostnames that resolve to the local machine or the local network by name. */
function classifyHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/\.$/, '');
  if (!h) return null;
  if (METADATA_HOSTS.has(h)) {
    return { private: true, metadata: true, label: 'cloud metadata service' };
  }
  if (h === 'localhost' || h.endsWith('.localhost')) return { private: true, label: 'your own machine' };
  if (h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.lan')
      || h.endsWith('.home') || h.endsWith('.home.arpa') || h.endsWith('.corp')
      || h.endsWith('.intranet') || h.endsWith('.private')) {
    return { private: true, label: 'local network name' };
  }
  if (!h.includes('.')) return { private: true, label: 'bare hostname on your network' };
  return classifyIp(h);
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/**
 * Ports the browser must never open. Chromium blocks most of these already;
 * Shadow enforces its own list so the rule is visible and auditable.
 */
const BLOCKED_PORTS = new Set([
  1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79,
  87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137,
  138, 139, 143, 161, 179, 389, 427, 445, 465, 512, 513, 514, 515, 526, 530,
  531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995,
  1719, 1720, 1723, 2049, 3306, 3389, 4045, 5060, 5061, 5432, 5900, 5901,
  6000, 6379, 6665, 6666, 6667, 6668, 6669, 6697, 9100, 10080, 11211, 27017,
]);

// ---------------------------------------------------------------------------
// Rule evaluation
// ---------------------------------------------------------------------------

/**
 * A rule looks like:
 *   { id, action: 'allow'|'block'|'log', match: {...}, comment }
 * match supports: host (glob), hostSuffix, urlPattern (regex string),
 * resourceType, method, scheme, port, thirdParty (bool).
 * First matching rule wins, so put allows above blocks.
 */
function globToRegExp(glob) {
  const escaped = String(glob).replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`, 'i');
}

function ruleMatches(rule, req) {
  const m = rule.match || {};
  if (m.scheme && m.scheme !== req.scheme) return false;
  if (m.method && m.method.toUpperCase() !== String(req.method || '').toUpperCase()) return false;
  if (m.resourceType) {
    const wanted = Array.isArray(m.resourceType) ? m.resourceType : [m.resourceType];
    if (!wanted.includes(req.resourceType)) return false;
  }
  if (m.port !== undefined && String(m.port) !== String(req.port)) return false;
  if (m.thirdParty !== undefined && Boolean(req.thirdParty) !== Boolean(m.thirdParty)) return false;
  if (m.hostSuffix) {
    const suffix = String(m.hostSuffix).toLowerCase().replace(/^\./, '');
    const h = String(req.hostname || '').toLowerCase();
    if (h !== suffix && !h.endsWith(`.${suffix}`)) return false;
  }
  if (m.host) {
    if (!globToRegExp(m.host).test(req.hostname || '')) return false;
  }
  if (m.urlPattern) {
    let re;
    try { re = new RegExp(m.urlPattern, 'i'); } catch { return false; }
    if (!re.test(req.url || '')) return false;
  }
  return Object.keys(m).length > 0;
}

/**
 * @param {Array} rules ordered rule list
 * @param {object} req  { url, hostname, scheme, port, method, resourceType, thirdParty }
 * @returns {{action, rule}|null}
 */
function evaluate(rules, req) {
  for (const rule of rules || []) {
    if (rule && rule.enabled !== false && ruleMatches(rule, req)) {
      return { action: rule.action || 'block', rule };
    }
  }
  return null;
}

module.exports = {
  classifyIp, classifyHost, ipv4ToInt, cidrToRange,
  BLOCKED_PORTS, PRIVATE_V4, METADATA_HOSTS,
  evaluate, ruleMatches, globToRegExp,
};
