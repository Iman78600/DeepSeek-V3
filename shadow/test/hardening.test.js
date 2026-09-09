'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const vm = require('node:vm');

const { shieldSource } = require('../src/main/hardening/fingerprint-shield');
const { commandLineSwitches, genericUserAgent } = require('../src/main/hardening/profile');
const { SettingsStore, DEFAULTS } = require('../src/main/storage/store');
const { EventLog } = require('../src/main/soc/events');

const fullConfig = { canvasNoise: true, fontProtection: true, timingJitter: true, blockWebgl: false };

test('the injected shield is syntactically valid JavaScript', () => {
  assert.doesNotThrow(() => new vm.Script(shieldSource(fullConfig, 42)));
});

test('the shield actually changes the readouts it claims to', () => {
  // A minimal fake page world: enough surface for the shield to patch.
  const sandbox = {
    window: {},
    navigator: { hardwareConcurrency: 24, deviceMemory: 64, webdriver: true, languages: ['en-GB', 'fr'] },
    screen: { width: 3840, height: 2160, availWidth: 3840, availHeight: 2160, colorDepth: 30, pixelDepth: 30 },
    document: { fonts: null },
    performance: { now: () => 1234.56789 },
    Date: { now: () => 1700000000123 },
    Navigator: function Navigator() {},
    Object,
    Proxy,
    Reflect,
    Math,
    String,
    Number,
    RegExp,
  };
  sandbox.window = sandbox;
  sandbox.Navigator.prototype = { getBattery() {} };
  vm.createContext(sandbox);
  vm.runInContext(shieldSource(fullConfig, 42), sandbox);

  assert.equal(sandbox.navigator.hardwareConcurrency, 8, 'core count must be generic');
  assert.equal(sandbox.navigator.deviceMemory, 8, 'memory must be generic');
  assert.equal(sandbox.navigator.webdriver, false);
  assert.deepEqual(sandbox.navigator.languages, ['en-US', 'en']);
  assert.equal(sandbox.screen.colorDepth, 24, 'colour depth must be generic');
  assert.equal(sandbox.navigator.getBattery, undefined, 'the battery API must be gone');

  // Timers must be quantised, not exact.
  assert.equal(sandbox.performance.now() % 0.1 < 1e-9 || Math.abs(sandbox.performance.now() % 0.1 - 0.1) < 1e-9, true);
  assert.equal(sandbox.Date.now() % 2, 0, 'Date.now must be rounded to 2ms');
});

test('the shield only installs once per world', () => {
  const sandbox = { window: {}, navigator: { hardwareConcurrency: 24 }, screen: {}, document: {}, Object, Proxy, Reflect, Math, String, Number, RegExp, performance: { now: () => 1 }, Date: { now: () => 2 } };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(shieldSource(fullConfig, 1), sandbox);
  assert.equal(sandbox.window.__shadowShield, true);
  // Running it again must be a no-op rather than double-patching.
  assert.doesNotThrow(() => vm.runInContext(shieldSource(fullConfig, 1), sandbox));
});

test('the same seed gives the same noise, different seeds do not', () => {
  const a = shieldSource(fullConfig, 111);
  const b = shieldSource(fullConfig, 111);
  const c = shieldSource(fullConfig, 222);
  assert.equal(a, b, 'a session must be self-consistent so averaging cannot strip the noise');
  assert.notEqual(a, c, 'sessions must differ so the noise is not itself an identifier');
});

test('disabled protections are left out of the shield', () => {
  const src = shieldSource({ canvasNoise: false, fontProtection: false, timingJitter: false }, 1);
  assert.match(src, /"canvasNoise":false/);
  assert.match(src, /"timingJitter":false/);
});

test('command line switches turn off background networking and WebRTC leaks', () => {
  const settings = { get: (k) => ({ 'hardening.webrtc': 'disabled', 'dns.mode': 'doh', 'dns.dohUrl': 'https://dns.quad9.net/dns-query' }[k]) };
  const flat = commandLineSwitches(settings).map(([n, v]) => `${n}=${v}`).join(' ');
  assert.match(flat, /force-webrtc-ip-handling-policy=disable_non_proxied_udp/);
  assert.match(flat, /disable-background-networking/);
  assert.match(flat, /no-pings/);
  assert.match(flat, /dns-over-https-templates=https:\/\/dns\.quad9\.net/);
});

test('the generic User-Agent does not name Shadow or Electron', () => {
  const ua = genericUserAgent();
  assert.ok(!/shadow|electron/i.test(ua), ua);
  assert.match(ua, /Chrome\/\d+/);
});

// --- settings store ---------------------------------------------------------

const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');

test('a corrupted settings file cannot weaken a protection', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shadow-set-'));
  const file = path.join(dir, 'settings.json');
  // A file claiming the firewall is the string "false" must not disable it.
  fs.writeFileSync(file, JSON.stringify({
    'firewall.enabled': 'false',
    'firewall.blockPrivateNetwork': 0,
    'soc.mode': 'balanced',
    'unknown.key': true,
  }));
  const s = new SettingsStore({ file });
  assert.equal(s.get('firewall.enabled'), true, 'a non-boolean must fall back to the default');
  assert.equal(s.get('firewall.blockPrivateNetwork'), true);
  assert.equal(s.get('unknown.key'), undefined, 'unknown keys must be ignored');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('setting an unknown key or a wrong type is rejected', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shadow-set2-'));
  const s = new SettingsStore({ file: path.join(dir, 's.json') });
  assert.throws(() => s.set('does.not.exist', 1), /unknown setting/);
  assert.throws(() => s.set('firewall.enabled', 'yes'), /must be a boolean/);
  assert.equal(s.set('firewall.enabled', false), false);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('presets change the settings they advertise', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shadow-set3-'));
  const s = new SettingsStore({ file: path.join(dir, 's.json') });
  s.applyPreset('ghost');
  assert.equal(s.get('tor.enabled'), true);
  assert.equal(s.get('firewall.lockdown'), true);
  assert.equal(s.get('soc.mode'), 'strict');
  assert.equal(s.get('profile.preset'), 'ghost');

  s.applyPreset('standard');
  assert.equal(s.get('tor.enabled'), false);
  assert.equal(s.get('firewall.lockdown'), false);
  assert.throws(() => s.applyPreset('nope'), /unknown preset/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('every default is one of the documented types', () => {
  for (const [k, v] of Object.entries(DEFAULTS)) {
    assert.ok(['boolean', 'number', 'string'].includes(typeof v) || Array.isArray(v), `${k} is ${typeof v}`);
  }
});

// --- event log ---------------------------------------------------------------

test('the event log keeps a bounded history and computes stats', () => {
  const log = new EventLog({ max: 5 });
  for (let i = 0; i < 10; i++) log.record({ type: 'firewall-block', hostname: `h${i % 3}.com`, category: 'tracker' });
  assert.equal(log.events.length, 5, 'history must be bounded');
  const stats = log.stats();
  assert.equal(stats.blocked, 5);
  assert.equal(stats.byCategory.tracker, 5);
  assert.ok(stats.topHosts.length > 0);
});

test('the event log can be filtered', () => {
  const log = new EventLog({ max: 100 });
  log.record({ type: 'page-verdict', verdict: 'block', score: 90 });
  log.record({ type: 'page-verdict', verdict: 'allow', score: 5 });
  log.record({ type: 'firewall-block', category: 'ads' });
  assert.equal(log.query({ type: 'page-verdict' }).length, 2);
  assert.equal(log.query({ verdict: 'block' }).length, 1);
  assert.equal(log.query({ minScore: 50 }).length, 1);
});

test('a listener that throws does not break logging', () => {
  const log = new EventLog({ max: 10 });
  log.on(() => { throw new Error('bad listener'); });
  assert.doesNotThrow(() => log.record({ type: 'test' }));
  assert.equal(log.events.length, 1);
});
