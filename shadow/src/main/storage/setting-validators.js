'use strict';
/**
 * Content checks for settings whose values do something dangerous.
 *
 * The type check in store.js only proves a value is a string. Several settings
 * are strings that get handed to a process spawn, a proxy configuration, or a
 * filesystem write. Those need to be checked for what they contain, not just
 * what type they are, because the settings API is reachable from the browser
 * UI, and the browser UI is a renderer process.
 *
 * The concrete attack this closes: set `tor.binaryPath` to any executable on
 * disk, then call tor:start, and Shadow spawns it. That turns a renderer
 * compromise into arbitrary code execution outside the sandbox.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const { checkReleaseDir } = require('../hardening/safe-paths');

class SettingRejected extends Error {
  constructor(key, message) {
    super(`setting "${key}" was refused: ${message}`);
    this.name = 'SettingRejected';
    this.code = 'SETTING_REFUSED';
    this.key = key;
  }
}

/** Filenames a genuine Tor binary goes by. Anything else is not Tor. */
const TOR_BINARY_NAMES = new Set(['tor', 'tor.exe', 'tor.real']);

const VALIDATORS = {
  /**
   * Must be an existing regular file, actually named like the Tor binary, and
   * executable. This is not a proof of authenticity, it is a refusal to spawn
   * an arbitrary path chosen by something other than the person at the keyboard.
   */
  'tor.binaryPath': (value, key) => {
    if (value === '') return; // empty means "find it yourself", the default
    const p = path.resolve(String(value));
    if (!TOR_BINARY_NAMES.has(path.basename(p).toLowerCase())) {
      throw new SettingRejected(key,
        `the file must be named "tor", not "${path.basename(p)}". Shadow will not spawn an arbitrary program.`);
    }
    let stat;
    try { stat = fs.statSync(p); } catch {
      throw new SettingRejected(key, `no such file: ${p}`);
    }
    if (!stat.isFile()) throw new SettingRejected(key, `${p} is not a regular file`);
    if (process.platform !== 'win32' && !(stat.mode & 0o111)) {
      throw new SettingRejected(key, `${p} is not executable`);
    }
  },

  /** Proxy rules go straight to Chromium. Keep them to the forms we support. */
  'proxy.url': (value, key) => {
    if (value === '') return;
    const ok = /^(?:https?|socks4|socks5):\/\/[a-z0-9.-]+(?::\d{1,5})?\/?$/i.test(String(value));
    if (!ok) {
      throw new SettingRejected(key,
        'expected something like "socks5://127.0.0.1:9050" or "https://proxy.example:8443".');
    }
  },

  /** DNS-over-HTTPS template must be an https URL, or DNS silently downgrades. */
  'dns.dohUrl': (value, key) => {
    if (value === '') return;
    let u;
    try { u = new URL(String(value)); } catch {
      throw new SettingRejected(key, 'not a valid URL');
    }
    if (u.protocol !== 'https:') {
      throw new SettingRejected(key, 'a DNS-over-HTTPS server must be an https:// address');
    }
  },

  /** Where downloads may be released to. */
  'sandbox.releaseDir': (value, key) => {
    if (value === '') return; // empty means the default Downloads folder
    const result = checkReleaseDir(String(value));
    if (!result.ok) throw new SettingRejected(key, result.reason);
  },

  /**
   * The search engine template is loaded when the user types a plain phrase.
   * An attacker-set file:// or javascript: template would turn every search
   * into a local file read or a script execution.
   */
  'privacy.searchEngine': (value, key) => {
    const raw = String(value);
    if (!raw.includes('%s')) throw new SettingRejected(key, 'the template must contain %s');
    let u;
    try { u = new URL(raw.replace('%s', 'test')); } catch {
      throw new SettingRejected(key, 'not a valid URL');
    }
    if (u.protocol !== 'https:') {
      throw new SettingRejected(key, 'a search engine must be an https:// address');
    }
  },

  'privacy.homepage': (value, key) => {
    const raw = String(value);
    if (raw === 'shadow://home' || raw === '') return;
    let u;
    try { u = new URL(raw); } catch {
      throw new SettingRejected(key, 'not a valid URL');
    }
    if (!['http:', 'https:'].includes(u.protocol)) {
      throw new SettingRejected(key, 'a homepage must be an http:// or https:// address');
    }
  },

  /** A User-Agent goes out on every request; keep it to a printable one-liner. */
  'hardening.userAgent': (value, key) => {
    const raw = String(value);
    if (raw === '') return;
    if (raw.length > 256) throw new SettingRejected(key, 'too long');
    if (/[\r\n\0]/.test(raw)) {
      throw new SettingRejected(key, 'a header value cannot contain newlines (header injection)');
    }
  },

  'tor.socksPort': (value, key) => assertPort(value, key),
  'tor.controlPort': (value, key) => assertPort(value, key),

  'sandbox.retentionDays': (value, key) => {
    if (!Number.isInteger(value) || value < 0 || value > 365) {
      throw new SettingRejected(key, 'must be a whole number of days between 0 and 365');
    }
  },

  'firewall.blockThreshold': (value, key) => {
    if (!Number.isFinite(value) || value < 0 || value > 100) {
      throw new SettingRejected(key, 'must be between 0 and 100');
    }
  },

  /** Bridge lines are written into torrc, so they must not inject directives. */
  'tor.bridges': (value, key) => {
    if (value.length > 32) throw new SettingRejected(key, 'at most 32 bridges');
    for (const bridge of value) {
      const line = String(bridge);
      if (/[\r\n]/.test(line)) {
        throw new SettingRejected(key, 'a bridge line cannot contain a newline (torrc injection)');
      }
      if (line.length > 300) throw new SettingRejected(key, 'bridge line too long');
      if (!/^[A-Za-z0-9 .:_\-=/+\[\]]+$/.test(line)) {
        throw new SettingRejected(key, `"${line.slice(0, 40)}" contains characters a bridge line never has`);
      }
    }
  },

  'soc.allowlist': (value, key) => assertDomainList(value, key, 2000),
  'hardening.allowedPermissions': (value, key) => {
    if (value.length > 500) throw new SettingRejected(key, 'too many entries');
    for (const entry of value) {
      if (!/^[a-z0-9.:*-]{1,255}$/i.test(String(entry))) {
        throw new SettingRejected(key, `"${String(entry).slice(0, 40)}" is not a "host:permission" entry`);
      }
    }
  },

  /**
   * Firewall rules are evaluated against every request. A pathological regex
   * would hang the whole browser on the first page load, so patterns are
   * length-capped and compiled once here to prove they are valid at all.
   */
  'firewall.customRules': (value, key) => {
    if (value.length > 500) throw new SettingRejected(key, 'at most 500 rules');
    for (const rule of value) {
      if (!rule || typeof rule !== 'object') throw new SettingRejected(key, 'each rule must be an object');
      if (!['allow', 'block', 'log'].includes(rule.action || 'block')) {
        throw new SettingRejected(key, `unknown action "${rule.action}"`);
      }
      if (!rule.match || typeof rule.match !== 'object' || !Object.keys(rule.match).length) {
        throw new SettingRejected(key, 'each rule needs a non-empty match');
      }
      if (rule.match.urlPattern !== undefined) {
        const pattern = String(rule.match.urlPattern);
        if (pattern.length > 200) {
          throw new SettingRejected(key, 'a url pattern must be under 200 characters');
        }
        // Nested quantifiers are the shape that causes catastrophic backtracking.
        if (/(\([^)]*[+*]\)[+*])|(\[[^\]]*\][+*]\{?\d*,\}?[+*])/.test(pattern)) {
          throw new SettingRejected(key, 'that pattern can backtrack catastrophically and would hang the browser');
        }
        try { new RegExp(pattern); } catch (err) {
          throw new SettingRejected(key, `invalid pattern: ${err.message}`);
        }
      }
      for (const field of ['host', 'hostSuffix']) {
        if (rule.match[field] !== undefined && String(rule.match[field]).length > 255) {
          throw new SettingRejected(key, `${field} is too long`);
        }
      }
    }
  },
};

function assertPort(value, key) {
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new SettingRejected(key, 'must be a port number between 1 and 65535');
  }
  if (value < 1024 && process.platform !== 'win32') {
    throw new SettingRejected(key, 'ports below 1024 need root and Shadow will not ask for it');
  }
}

function assertDomainList(value, key, max) {
  if (value.length > max) throw new SettingRejected(key, `at most ${max} entries`);
  for (const entry of value) {
    const d = String(entry);
    if (d.length > 255 || !/^[a-z0-9.-]+$/i.test(d)) {
      throw new SettingRejected(key, `"${d.slice(0, 40)}" is not a domain`);
    }
  }
}

/**
 * @throws {SettingRejected} when the value is the right type but unsafe
 */
function validateSetting(key, value) {
  // Own-property lookup only. VALIDATORS[key] would otherwise resolve
  // "constructor" to Object and "__proto__" to a getter, so a crafted key
  // either calls the wrong function or throws a confusing internal error
  // instead of a clean refusal.
  const validator = Object.hasOwn(VALIDATORS, key) ? VALIDATORS[key] : null;
  if (typeof validator === 'function') validator(value, key);
  return value;
}

module.exports = { validateSetting, SettingRejected, VALIDATORS };
