'use strict';
/**
 * Download quarantine.
 *
 * Nothing you download lands in your Downloads folder. Every file is written
 * into a quarantine directory with these properties:
 *
 *   - mode 0600, inside a 0700 directory: only your user can read it
 *   - the executable bit is stripped on POSIX
 *   - a ".shadow-quarantine" marker sits alongside it
 *   - a ".quarantined" suffix is appended so a double-click cannot run it
 *
 * The file is then scanned (scanner.js) and, if configured, detonated in a
 * container (detonate.js). Only an explicit user "release" moves it out, and
 * a release is refused outright for anything the analyst blocked unless the
 * user re-confirms with the force flag.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const { scanFile, humanSize } = require('./scanner');
const { decide } = require('../soc/scoring');

const NEUTRALISED_SUFFIX = '.quarantined';

// Control characters, bidi overrides and path separators are stripped from
// any filename a server hands us before it ever touches the filesystem.
const UNSAFE_NAME_CHARS = /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c\/\\:*?"<>|]/g;

class Quarantine {
  /**
   * @param {object} opts
   * @param {string} opts.dir      quarantine directory
   * @param {object} opts.settings settings store
   * @param {object} [opts.events] SOC event log
   * @param {object} [opts.detonator] optional detonate.js instance
   */
  constructor({ dir, settings, events, detonator } = {}) {
    this.dir = dir || path.join(os.homedir(), '.shadow', 'quarantine');
    this.settings = settings;
    this.events = events;
    this.detonator = detonator;
    /** @type {Map<string, object>} id -> record */
    this.items = new Map();
    this.ensureDir();
  }

  ensureDir() {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(this.dir, 0o700); } catch { /* windows */ }
    const readme = path.join(this.dir, 'READ-ME-FIRST.txt');
    if (!fs.existsSync(readme)) {
      fs.writeFileSync(readme,
        'Shadow quarantine\n' +
        '=================\n\n' +
        'Every file downloaded by Shadow is held here until you release it.\n' +
        'Files in this folder have had their executable bit removed and have been\n' +
        'renamed so a double-click cannot run them.\n\n' +
        'Do not "fix" a file by renaming it back. Use Shadow\'s Downloads panel,\n' +
        'read the scan report, and release it only if you understand what it is.\n', { mode: 0o600 });
    }
  }

  /** Sanitise a server-supplied filename down to something safe to write. */
  static safeName(filename) {
    const base = path.basename(String(filename || 'download.bin'));
    const cleaned = base.replace(UNSAFE_NAME_CHARS, '_').replace(/^\.+/, '_').trim();
    return cleaned.slice(0, 180) || 'download.bin';
  }

  /** Where a download should be written. Called before the transfer starts. */
  reserve(filename, meta = {}) {
    const id = crypto.randomBytes(8).toString('hex');
    const safeName = Quarantine.safeName(filename);
    const itemDir = path.join(this.dir, id);
    fs.mkdirSync(itemDir, { recursive: true, mode: 0o700 });
    const savePath = path.join(itemDir, safeName + NEUTRALISED_SUFFIX);

    const record = {
      id,
      originalName: safeName,
      declaredName: String(filename || ''),
      savePath,
      dir: itemDir,
      state: 'downloading',
      sourceUrl: meta.sourceUrl || '',
      referrer: meta.referrer || '',
      mimeType: meta.mimeType || '',
      startedAt: Date.now(),
      report: null,
      verdict: null,
      released: null,
    };
    this.items.set(id, record);
    return record;
  }

  /**
   * Called when the transfer finishes. Locks the file down, scans it, and
   * returns the completed record including a verdict.
   */
  async complete(id) {
    const rec = this.items.get(id);
    if (!rec) throw new Error(`unknown quarantine item ${id}`);
    if (!fs.existsSync(rec.savePath)) {
      rec.state = 'failed';
      return rec;
    }

    // Strip execute bits and lock permissions before anything else touches it.
    try { fs.chmodSync(rec.savePath, 0o600); } catch { /* windows */ }
    fs.writeFileSync(path.join(rec.dir, '.shadow-quarantine'), JSON.stringify({
      id: rec.id,
      originalName: rec.originalName,
      declaredName: rec.declaredName,
      sourceUrl: rec.sourceUrl,
      quarantinedAt: new Date().toISOString(),
    }, null, 2), { mode: 0o600 });

    // Mark-of-the-web equivalent, so other tools know where this came from.
    if (process.platform === 'win32') {
      try {
        fs.writeFileSync(`${rec.savePath}:Zone.Identifier`,
          `[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=${rec.sourceUrl}\r\n`);
      } catch { /* alternate data streams unsupported here */ }
    }

    rec.state = 'scanning';
    let report;
    try {
      report = await scanFile(rec.savePath, {
        originalName: rec.originalName,
        sourceUrl: rec.sourceUrl,
        mimeType: rec.mimeType,
      });
    } catch (err) {
      report = {
        signals: [{
          id: 'scan.failed', score: 40, severity: 'medium', title: 'Scan failed',
          detail: `Shadow could not read the file: ${err.message}`,
        }],
        file: { name: rec.originalName, size: 0, sizeHuman: '?' },
        hashes: {}, network: {},
      };
    }

    // A name that had to be sanitised is itself a finding.
    if (rec.declaredName && rec.declaredName !== rec.originalName
        && UNSAFE_NAME_CHARS.test(rec.declaredName)) {
      UNSAFE_NAME_CHARS.lastIndex = 0;
      report.signals.push({
        id: 'file.unsafe-name', score: 55, severity: 'high',
        title: 'Server sent a filename containing hidden characters',
        detail: `The download was offered as something Shadow had to rewrite to "${rec.originalName}" before saving it.`,
      });
    }
    UNSAFE_NAME_CHARS.lastIndex = 0;

    const mode = (this.settings && this.settings.get('sandbox.mode')) || 'balanced';
    const verdict = decide(report.signals, { mode });

    rec.report = report;
    rec.verdict = verdict;
    rec.state = 'quarantined';
    rec.finishedAt = Date.now();

    if (this.events) {
      this.events.record({
        type: 'download-scanned',
        id: rec.id,
        name: rec.originalName,
        size: report.file ? report.file.size : 0,
        sourceUrl: rec.sourceUrl,
        sha256: report.hashes ? report.hashes.sha256 : null,
        verdict: verdict.verdict,
        score: verdict.score,
        severity: verdict.severity,
        reasons: verdict.reasons,
      });
    }

    // Optional dynamic analysis for anything not already condemned.
    const wantDetonate = this.settings && this.settings.get('sandbox.detonate');
    if (wantDetonate && this.detonator && verdict.verdict !== 'block') {
      try {
        rec.detonation = await this.detonator.run(rec.savePath, { originalName: rec.originalName });
        if (rec.detonation && rec.detonation.signals && rec.detonation.signals.length) {
          rec.verdict = decide([...report.signals, ...rec.detonation.signals], { mode });
        }
      } catch (err) {
        rec.detonation = { available: false, error: err.message };
      }
    }

    // Auto-delete the worst of it if the user asked for that.
    if (rec.verdict.verdict === 'block' && this.settings && this.settings.get('sandbox.autoDeleteMalicious')) {
      this.discard(rec.id);
      rec.state = 'deleted';
      rec.autoDeleted = true;
    }

    return rec;
  }

  /**
   * Move a file out of quarantine into the user's real download folder.
   * Refuses anything the analyst blocked unless force is set.
   */
  release(id, { destinationDir, force = false } = {}) {
    const rec = this.items.get(id);
    if (!rec) throw new Error(`unknown quarantine item ${id}`);
    if (rec.state !== 'quarantined') throw new Error(`item ${id} is ${rec.state}, not quarantined`);

    if (rec.verdict && rec.verdict.verdict === 'block' && !force) {
      const reason = rec.verdict.reasons[0];
      const err = new Error(
        `Refusing to release "${rec.originalName}". Shadow rated it ${rec.verdict.score}/100 ` +
        `(${rec.verdict.severity}).${reason ? ` Top finding: ${reason.title}.` : ''} ` +
        'Release it only if you are certain, and only with force.');
      err.code = 'BLOCKED';
      err.verdict = rec.verdict;
      throw err;
    }

    const dest = destinationDir
      || (this.settings && this.settings.get('sandbox.releaseDir'))
      || path.join(os.homedir(), 'Downloads');
    fs.mkdirSync(dest, { recursive: true });

    let target = path.join(dest, rec.originalName);
    let n = 1;
    while (fs.existsSync(target)) {
      const ext = path.extname(rec.originalName);
      const base = path.basename(rec.originalName, ext);
      target = path.join(dest, `${base} (${n++})${ext}`);
    }

    fs.copyFileSync(rec.savePath, target);
    try { fs.chmodSync(target, 0o600); } catch { /* windows */ }

    rec.released = { at: Date.now(), path: target, forced: Boolean(force) };
    rec.state = 'released';

    if (this.events) {
      this.events.record({
        type: 'download-released',
        id: rec.id,
        name: rec.originalName,
        to: target,
        forced: Boolean(force),
        verdict: rec.verdict ? rec.verdict.verdict : 'unknown',
        score: rec.verdict ? rec.verdict.score : null,
      });
    }
    return rec;
  }

  discard(id) {
    const rec = this.items.get(id);
    if (!rec) return false;
    try { fs.rmSync(rec.dir, { recursive: true, force: true }); } catch { /* ignore */ }
    rec.state = 'deleted';
    if (this.events) this.events.record({ type: 'download-deleted', id: rec.id, name: rec.originalName });
    return true;
  }

  list() {
    return [...this.items.values()].map((r) => ({
      id: r.id,
      name: r.originalName,
      state: r.state,
      size: r.report && r.report.file ? r.report.file.sizeHuman : null,
      sourceUrl: r.sourceUrl,
      sha256: r.report && r.report.hashes ? r.report.hashes.sha256 : null,
      detectedType: r.report ? r.report.detectedType : null,
      verdict: r.verdict ? r.verdict.verdict : null,
      score: r.verdict ? r.verdict.score : null,
      severity: r.verdict ? r.verdict.severity : null,
      reasons: r.verdict ? r.verdict.reasons : [],
      detonation: r.detonation || null,
      startedAt: r.startedAt,
    })).sort((a, b) => b.startedAt - a.startedAt);
  }

  get(id) { return this.items.get(id); }

  /** Delete quarantined files older than N days. */
  sweep(maxAgeDays = 14) {
    const cutoff = Date.now() - maxAgeDays * 86400000;
    let removed = 0;
    for (const rec of this.items.values()) {
      if (rec.startedAt < cutoff && rec.state === 'quarantined') {
        this.discard(rec.id);
        removed++;
      }
    }
    return removed;
  }
}

module.exports = { Quarantine, NEUTRALISED_SUFFIX, humanSize };
