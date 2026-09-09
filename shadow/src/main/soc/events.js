'use strict';
/**
 * The SOC event log. Every block, verdict, scan and release lands here.
 * Kept in memory for the dashboard, appended to a JSONL file on disk so you
 * can grep it or feed it to a real SIEM later.
 */

const fs = require('fs');
const path = require('path');

class EventLog {
  constructor({ file, max = 5000, settings } = {}) {
    this.file = file;
    this.max = max;
    this.settings = settings;
    this.events = [];
    this.listeners = new Set();
    this.seq = 0;
    if (this.file) {
      fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
    }
  }

  record(event) {
    const entry = {
      seq: ++this.seq,
      at: event.at || Date.now(),
      iso: new Date(event.at || Date.now()).toISOString(),
      ...event,
    };
    this.events.unshift(entry);
    if (this.events.length > this.max) this.events.length = this.max;

    const persist = !this.settings || this.settings.get('privacy.persistLog') !== false;
    if (this.file && persist) {
      try {
        fs.appendFileSync(this.file, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
      } catch { /* logging must never break browsing */ }
    }

    for (const fn of this.listeners) {
      try { fn(entry); } catch { /* a bad listener must not break the log */ }
    }
    return entry;
  }

  on(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }

  query({ type, since, limit = 200, verdict, minScore } = {}) {
    let out = this.events;
    if (type) out = out.filter((e) => e.type === type);
    if (verdict) out = out.filter((e) => e.verdict === verdict);
    if (since) out = out.filter((e) => e.at >= since);
    if (minScore !== undefined) out = out.filter((e) => (e.score || 0) >= minScore);
    return out.slice(0, limit);
  }

  /** Counts for the dashboard tiles. */
  stats(windowMs = 24 * 3600 * 1000) {
    const since = Date.now() - windowMs;
    const recent = this.events.filter((e) => e.at >= since);
    const byType = {};
    const byCategory = {};
    const topHosts = new Map();
    for (const e of recent) {
      byType[e.type] = (byType[e.type] || 0) + 1;
      if (e.category) byCategory[e.category] = (byCategory[e.category] || 0) + 1;
      if (e.hostname) topHosts.set(e.hostname, (topHosts.get(e.hostname) || 0) + 1);
    }
    return {
      windowMs,
      total: recent.length,
      byType,
      byCategory,
      blocked: recent.filter((e) => e.type === 'firewall-block').length,
      pagesBlocked: recent.filter((e) => e.type === 'page-verdict' && e.verdict === 'block').length,
      pagesWarned: recent.filter((e) => e.type === 'page-verdict' && e.verdict === 'warn').length,
      downloadsScanned: recent.filter((e) => e.type === 'download-scanned').length,
      downloadsBlocked: recent.filter((e) => e.type === 'download-scanned' && e.verdict === 'block').length,
      topHosts: [...topHosts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10)
        .map(([host, count]) => ({ host, count })),
    };
  }

  clear() {
    this.events = [];
    if (this.file) { try { fs.rmSync(this.file, { force: true }); } catch { /* ignore */ } }
  }

  /** Export as JSON Lines for external analysis. */
  export(destination) {
    const body = this.events.slice().reverse().map((e) => JSON.stringify(e)).join('\n');
    fs.writeFileSync(destination, `${body}\n`, { mode: 0o600 });
    return destination;
  }
}

module.exports = { EventLog };
