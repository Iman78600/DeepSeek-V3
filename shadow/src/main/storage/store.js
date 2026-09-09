'use strict';
/**
 * Settings store. Flat dotted keys, JSON on disk, schema-checked so a
 * corrupted file cannot silently turn a protection off.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const DEFAULTS = require('../../../config/default-settings.json');
const { validateSetting } = require('./setting-validators');

/**
 * `key in DEFAULTS` is true for every inherited Object.prototype member, so
 * "__proto__", "constructor" and "toString" all pass a naive guard. Own-key
 * checks only. Today this is caught downstream by accident; relying on an
 * accident is how a refactor reintroduces a bug.
 */
const isSettingKey = (key) => Object.hasOwn(DEFAULTS, key);

/** Keys that must never be weakened by a malformed config file. */
const BOOLEAN_KEYS = Object.entries(DEFAULTS)
  .filter(([, v]) => typeof v === 'boolean').map(([k]) => k);

class SettingsStore {
  constructor({ file } = {}) {
    this.file = file || path.join(os.homedir(), '.shadow', 'settings.json');
    this.values = Object.assign(Object.create(null), DEFAULTS);
    this.listeners = new Set();
    this.load();
  }

  load() {
    try {
      const raw = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      for (const [k, v] of Object.entries(raw)) {
        if (!isSettingKey(k)) continue;                       // ignore unknown and inherited keys
        if (BOOLEAN_KEYS.includes(k) && typeof v !== 'boolean') continue;
        if (typeof DEFAULTS[k] === 'number' && typeof v !== 'number') continue;
        if (Array.isArray(DEFAULTS[k]) && !Array.isArray(v)) continue;
        // A settings file that has been tampered with must not be able to
        // smuggle in a value that set() would have rejected.
        try { validateSetting(k, v); } catch { continue; }
        this.values[k] = v;
      }
    } catch { /* first run, or unreadable: defaults stand */ }
    return this;
  }

  save() {
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
      fs.writeFileSync(this.file, JSON.stringify(this.values, null, 2), { mode: 0o600 });
    } catch { /* read-only home: keep running with in-memory settings */ }
    return this;
  }

  get(key) { return this.values[key]; }

  set(key, value) {
    if (!isSettingKey(key)) throw new Error(`unknown setting "${key}"`);
    const expected = typeof DEFAULTS[key];
    if (Array.isArray(DEFAULTS[key])) {
      if (!Array.isArray(value)) throw new Error(`setting "${key}" must be an array`);
    } else if (typeof value !== expected) {
      throw new Error(`setting "${key}" must be a ${expected}`);
    }
    // Type-correct is not the same as safe. Some settings feed a process
    // spawn, a proxy, or a filesystem write, so they get a content check too.
    validateSetting(key, value);
    const old = this.values[key];
    this.values[key] = value;
    this.save();
    for (const fn of this.listeners) {
      try { fn(key, value, old); } catch { /* ignore */ }
    }
    return value;
  }

  on(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }

  all() { return { ...this.values }; }   // plain object for IPC

  /** Apply a named security preset. */
  applyPreset(name) {
    const presets = require('../../../config/presets.json');
    const preset = presets[name];
    if (!preset) throw new Error(`unknown preset "${name}"`);
    for (const [k, v] of Object.entries(preset.settings)) {
      if (isSettingKey(k)) this.values[k] = v;
    }
    this.values['profile.preset'] = name;
    this.save();
    for (const fn of this.listeners) {
      try { fn('*', name, null); } catch { /* ignore */ }
    }
    return preset;
  }

  reset() {
    this.values = Object.assign(Object.create(null), DEFAULTS);
    this.save();
    return this;
  }
}

module.exports = { SettingsStore, DEFAULTS };
