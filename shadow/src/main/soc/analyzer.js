'use strict';
/**
 * The SOC analyst. Everything that decides "is this page safe" funnels
 * through here so there is exactly one place that produces a verdict.
 *
 * Kept free of Electron imports on purpose: tools/scan-cli.js and the test
 * suite drive this same class headlessly.
 */

const { analyzeUrl, splitHost } = require('./heuristics/url-heuristics');
const { analyzeContent } = require('./heuristics/content-heuristics');
const { analyzeCertificate } = require('./heuristics/tls-heuristics');
const { decide } = require('./scoring');
const { LEGITIMATE_BRAND_DOMAINS } = require('./data/brands');

/** Origins Shadow treats as known-good unless something certain fires. */
const DEFAULT_ALLOWLIST = new Set([
  ...LEGITIMATE_BRAND_DOMAINS,
  'wikipedia.org', 'wikimedia.org', 'mozilla.org', 'debian.org', 'ubuntu.com',
  'archlinux.org', 'kernel.org', 'python.org', 'nodejs.org', 'rust-lang.org',
  'npmjs.com', 'pypi.org', 'crates.io', 'stackoverflow.com', 'duckduckgo.com',
  'torproject.org', 'eff.org', 'cloudflare.com', 'nist.gov', 'cisa.gov',
  'mitre.org', 'virustotal.com', 'abuse.ch', 'sans.org', 'bbc.co.uk',
]);

class Analyzer {
  /**
   * @param {object} deps
   * @param {object} deps.blocklists  instance of firewall/blocklists.js
   * @param {object} deps.settings    settings store (get/set)
   * @param {object} [deps.events]    SOC event log
   * @param {object} [deps.reputation] optional external reputation service
   */
  constructor({ blocklists, settings, events, reputation } = {}) {
    this.blocklists = blocklists;
    this.settings = settings;
    this.events = events;
    this.reputation = reputation;
    this.cache = new Map();          // url -> { verdict, at }
    this.cacheTtlMs = 5 * 60 * 1000;
    this.userAllow = new Set();      // origins the user explicitly trusted
    this.sessionOverrides = new Map(); // url -> 'proceed'
  }

  mode() {
    return (this.settings && this.settings.get('soc.mode')) || 'balanced';
  }

  isAllowlisted(hostname) {
    const { registrable } = splitHost(hostname);
    if (!registrable) return false;
    if (this.userAllow.has(registrable)) return true;
    if (DEFAULT_ALLOWLIST.has(registrable)) return true;
    const extra = (this.settings && this.settings.get('soc.allowlist')) || [];
    return extra.includes(registrable) || extra.includes(hostname);
  }

  trustOrigin(hostname) {
    const { registrable } = splitHost(hostname);
    if (registrable) this.userAllow.add(registrable);
  }

  /**
   * Fast pre-navigation check. URL + blocklists only, no page content yet.
   * This is what gates a navigation before a single byte is fetched.
   */
  async inspectUrl(rawUrl, context = {}) {
    const cached = this.cache.get(rawUrl);
    if (cached && Date.now() - cached.at < this.cacheTtlMs) return cached.verdict;

    let hostname = '';
    try { hostname = new URL(rawUrl).hostname.toLowerCase(); } catch { /* handled below */ }

    const signals = analyzeUrl(rawUrl);

    if (this.blocklists && hostname) {
      const hits = this.blocklists.match(hostname, rawUrl);
      for (const hit of hits) {
        signals.push({
          id: `blocklist.${hit.list}`,
          score: hit.score,
          severity: hit.severity,
          title: hit.title,
          detail: hit.detail,
        });
      }
    }

    if (this.reputation && this.settings && this.settings.get('soc.reputationLookups')) {
      try {
        const rep = await this.reputation.lookup(rawUrl);
        if (rep) signals.push(...rep);
      } catch { /* reputation is best-effort, never blocks navigation */ }
    }

    const verdict = decide(signals, {
      mode: this.mode(),
      allowlisted: hostname ? this.isAllowlisted(hostname) : false,
      blocklisted: signals.some((s) => s.id.startsWith('blocklist.') && s.score >= 85),
    });

    verdict.url = rawUrl;
    verdict.hostname = hostname;
    verdict.stage = 'url';
    verdict.at = Date.now();

    this.cache.set(rawUrl, { verdict, at: Date.now() });
    this._log(verdict, context);
    return verdict;
  }

  /**
   * Deep check once the page has loaded. Re-runs the URL signals so the score
   * reflects everything known, then merges in content and certificate signals.
   */
  inspectPage({ url, html, certificate, certificateError, observations }) {
    let hostname = '';
    try { hostname = new URL(url).hostname.toLowerCase(); } catch { /* ignore */ }

    const signals = [
      ...analyzeUrl(url),
      ...analyzeContent(html, url, observations || {}),
      ...analyzeCertificate(certificate, hostname, { errorCode: certificateError }),
    ];

    if (this.blocklists && hostname) {
      for (const hit of this.blocklists.match(hostname, url)) {
        signals.push({ id: `blocklist.${hit.list}`, score: hit.score, severity: hit.severity, title: hit.title, detail: hit.detail });
      }
    }

    const verdict = decide(signals, {
      mode: this.mode(),
      allowlisted: hostname ? this.isAllowlisted(hostname) : false,
    });
    verdict.url = url;
    verdict.hostname = hostname;
    verdict.stage = 'page';
    verdict.at = Date.now();

    this._log(verdict, { stage: 'page' });
    return verdict;
  }

  /** The user chose to continue past a warning, for this URL, this session. */
  override(url) {
    this.sessionOverrides.set(url, Date.now());
  }

  hasOverride(url) {
    return this.sessionOverrides.has(url);
  }

  _log(verdict, context) {
    if (!this.events) return;
    if (verdict.verdict === 'allow' && verdict.score < 10) return; // don't flood the log
    this.events.record({
      type: 'page-verdict',
      verdict: verdict.verdict,
      score: verdict.score,
      severity: verdict.severity,
      url: verdict.url,
      hostname: verdict.hostname,
      stage: verdict.stage,
      reasons: verdict.reasons,
      context,
    });
  }
}

module.exports = { Analyzer, DEFAULT_ALLOWLIST };
