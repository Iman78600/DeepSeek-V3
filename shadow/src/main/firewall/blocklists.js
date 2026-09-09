'use strict';
/**
 * Blocklist store. Holds domain lists (ads, trackers, malware, phishing,
 * mining) in memory as Sets and answers "is this host on any list" in O(labels).
 *
 * Lists are plain text on disk under config/lists/*.txt, one entry per line,
 * accepting hosts-file format ("0.0.0.0 bad.example"), plain domains, and
 * "||domain^" adblock syntax. tools/update-blocklists.js refreshes them.
 */

const fs = require('fs');
const path = require('path');

const LIST_META = {
  malware:  { score: 95, severity: 'critical', title: 'Known malware host',      detail: 'This domain appears on a malware distribution or command-and-control feed.' },
  phishing: { score: 95, severity: 'critical', title: 'Known phishing host',     detail: 'This domain is on a live phishing feed.' },
  mining:   { score: 70, severity: 'high',     title: 'Cryptomining host',       detail: 'This domain serves in-browser cryptocurrency miners.' },
  scam:     { score: 80, severity: 'high',     title: 'Known scam host',         detail: 'This domain is on a fraud/scam feed.' },
  tracker:  { score: 12, severity: 'low',      title: 'Tracker',                 detail: 'This domain profiles you across sites.' },
  ads:      { score: 8,  severity: 'info',     title: 'Advertising host',        detail: 'This domain serves advertising.' },
  custom:   { score: 90, severity: 'high',     title: 'Blocked by your rules',   detail: 'You added this domain to your own blocklist.' },
};

// Small built-in seed so Shadow is useful on first run with no network.
const SEED = {
  mining: [
    'coinhive.com', 'coin-hive.com', 'jsecoin.com', 'crypto-loot.com',
    'cryptoloot.pro', 'coinimp.com', 'webminepool.com', 'minero.cc',
    'authedmine.com', 'load.jsecoin.com', 'webmine.cz', 'monerise.com',
    'cryptonight.wasm', 'deepMiner.js', 'minergate.com', 'nimiq.com',
  ],
  tracker: [
    'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
    'scorecardresearch.com', 'quantserve.com', 'criteo.com', 'criteo.net',
    'adnxs.com', 'rubiconproject.com', 'pubmatic.com', 'openx.net',
    'taboola.com', 'outbrain.com', 'hotjar.com', 'fullstory.com',
    'mouseflow.com', 'clarity.ms', 'segment.io', 'segment.com',
    'mixpanel.com', 'amplitude.com', 'branch.io', 'appsflyer.com',
    'adjust.com', 'kochava.com', 'bugsnag.com', 'sentry-cdn.com',
    'facebook.net', 'connect.facebook.net', 'analytics.tiktok.com',
    'bat.bing.com', 'ads.linkedin.com', 'px.ads.linkedin.com',
    'sc-static.net', 'snap.licdn.com', 'matomo.cloud', 'statcounter.com',
  ],
  ads: [
    'googlesyndication.com', 'googleadservices.com', 'adservice.google.com',
    'amazon-adsystem.com', 'adform.net', 'smartadserver.com', 'casalemedia.com',
    'sharethrough.com', 'teads.tv', 'yieldmo.com', 'indexww.com', '33across.com',
    'bidswitch.net', 'adsrvr.org', 'media.net', 'revcontent.com', 'mgid.com',
    'propellerads.com', 'popads.net', 'popcash.net', 'adcash.com', 'exoclick.com',
    'juicyads.com', 'trafficjunky.net', 'hilltopads.net', 'adsterra.com',
  ],
  scam: [
    'tech-support-alert.com', 'windows-security-alert.info',
  ],
};

function normalizeLine(line) {
  let s = String(line).trim();
  if (!s || s.startsWith('#') || s.startsWith('!') || s.startsWith('[')) return null;
  // adblock syntax: ||example.com^$third-party
  const ab = s.match(/^\|\|([^\^/$]+)\^?/);
  if (ab) return ab[1].toLowerCase();
  // hosts file: 0.0.0.0 example.com  /  127.0.0.1 example.com
  const hosts = s.match(/^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+(\S+)/);
  if (hosts) s = hosts[1];
  s = s.split(/\s+/)[0];
  s = s.replace(/^\*\./, '').replace(/^\./, '').replace(/\.$/, '').toLowerCase();
  if (!s || s === 'localhost' || s === 'broadcasthost') return null;
  if (!/^[a-z0-9._-]+$/.test(s)) return null;
  if (!s.includes('.')) return null;
  return s;
}

class Blocklists {
  constructor({ dir, settings } = {}) {
    this.dir = dir;
    this.settings = settings;
    /** @type {Map<string, Set<string>>} category -> domains */
    this.lists = new Map();
    /** @type {Array<{re: RegExp, list: string}>} URL-level patterns */
    this.urlPatterns = [];
    this.stats = { lookups: 0, hits: 0 };
    for (const [cat, entries] of Object.entries(SEED)) {
      this.lists.set(cat, new Set(entries.map(normalizeLine).filter(Boolean)));
    }
  }

  /** Load every *.txt in the lists directory. Filename = category. */
  load() {
    if (!this.dir || !fs.existsSync(this.dir)) return this;
    for (const file of fs.readdirSync(this.dir)) {
      if (!file.endsWith('.txt')) continue;
      const category = path.basename(file, '.txt').toLowerCase();
      const set = this.lists.get(category) || new Set();
      const raw = fs.readFileSync(path.join(this.dir, file), 'utf8');
      let added = 0;
      for (const line of raw.split(/\r?\n/)) {
        const d = normalizeLine(line);
        if (d) { set.add(d); added++; }
      }
      this.lists.set(category, set);
      if (process.env.SHADOW_DEBUG) console.log(`[blocklists] ${category}: +${added} (${set.size} total)`);
    }
    return this;
  }

  addCustom(domain) {
    const d = normalizeLine(domain);
    if (!d) return false;
    const set = this.lists.get('custom') || new Set();
    set.add(d);
    this.lists.set('custom', set);
    return true;
  }

  removeCustom(domain) {
    const set = this.lists.get('custom');
    return set ? set.delete(normalizeLine(domain)) : false;
  }

  /** Which categories are enabled right now. */
  enabledCategories() {
    const s = this.settings;
    const on = (key, dflt) => (s ? (s.get(key) ?? dflt) : dflt);
    const cats = ['malware', 'phishing', 'scam', 'custom'];
    if (on('firewall.blockMining', true)) cats.push('mining');
    if (on('firewall.blockTrackers', true)) cats.push('tracker');
    if (on('firewall.blockAds', true)) cats.push('ads');
    return cats;
  }

  /**
   * Match a hostname against every enabled list, walking up the label chain
   * so "cdn.ads.evil.com" hits a rule for "evil.com".
   * @returns {Array<{list, domain, score, severity, title, detail}>}
   */
  match(hostname, url) {
    this.stats.lookups++;
    const host = String(hostname || '').toLowerCase().replace(/\.$/, '');
    if (!host) return [];
    const enabled = this.enabledCategories();
    const labels = host.split('.');
    const candidates = [];
    for (let i = 0; i < labels.length - 1; i++) candidates.push(labels.slice(i).join('.'));

    const hits = [];
    for (const category of enabled) {
      const set = this.lists.get(category);
      if (!set || !set.size) continue;
      for (const cand of candidates) {
        if (set.has(cand)) {
          const meta = LIST_META[category] || LIST_META.custom;
          hits.push({
            list: category,
            domain: cand,
            score: meta.score,
            severity: meta.severity,
            title: meta.title,
            detail: `${meta.detail} (matched "${cand}" on the ${category} list)`,
          });
          break;
        }
      }
    }
    if (url) {
      for (const { re, list } of this.urlPatterns) {
        if (re.test(url)) {
          const meta = LIST_META[list] || LIST_META.custom;
          hits.push({ list, domain: host, score: meta.score, severity: meta.severity, title: meta.title, detail: `${meta.detail} (URL pattern)` });
        }
      }
    }
    if (hits.length) this.stats.hits++;
    return hits;
  }

  /** True if the host should be dropped outright (not just scored). */
  shouldBlock(hostname, url) {
    const hits = this.match(hostname, url);
    return hits.some((h) => h.score >= 60) ? hits[0] : null;
  }

  summary() {
    const out = {};
    for (const [cat, set] of this.lists) out[cat] = set.size;
    return { categories: out, enabled: this.enabledCategories(), stats: this.stats };
  }
}

module.exports = { Blocklists, normalizeLine, LIST_META };
