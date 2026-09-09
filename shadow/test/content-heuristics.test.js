'use strict';
const { test } = require('node:test');
const assert = require('node:assert');

const { analyzeContent } = require('../src/main/soc/heuristics/content-heuristics');
const { analyzeCertificate } = require('../src/main/soc/heuristics/tls-heuristics');
const { decide } = require('../src/main/soc/scoring');
const { decidePermission } = require('../src/main/hardening/permissions');

const ids = (html, url) => analyzeContent(html, url).map((s) => s.id);
const DAY = 86400000;

test('a password field on plain HTTP is critical', () => {
  const s = analyzeContent('<form><input type="password"></form>', 'http://example.com/');
  assert.ok(s.some((x) => x.id === 'content.password-over-http' && x.severity === 'critical'));
});

test('a login form posting to another domain is caught', () => {
  const s = analyzeContent(
    '<form action="https://collector.evil.tk/x"><input type="password"></form>',
    'https://mybank.example/login');
  assert.ok(s.some((x) => x.id === 'content.cross-domain-credentials'));
});

test('a form posting within the same registrable domain is fine', () => {
  const s = analyzeContent(
    '<form action="https://auth.mybank.example/x"><input type="password"></form>',
    'https://www.mybank.example/login');
  assert.ok(!s.some((x) => x.id === 'content.cross-domain-credentials'));
});

test('a brand login page on the wrong domain is critical', () => {
  const s = analyzeContent(
    '<title>Microsoft account sign in</title><form><input type="password"></form>',
    'https://login-micros0ft-verify.tk/');
  assert.ok(s.some((x) => x.id === 'content.brand-impersonation' && x.severity === 'critical'));
});

test('the real brand site is not flagged as impersonating itself', () => {
  const s = analyzeContent(
    '<title>Sign in to your Microsoft account</title><form><input type="password"></form>',
    'https://login.microsoftonline.com/');
  assert.ok(!s.some((x) => x.id === 'content.brand-impersonation'));
});

test('ClickFix "paste this into Run" pages are blocked outright', () => {
  const html = '<h1>Verify you are human</h1><p>Press Windows + R, then press Ctrl+V and hit Enter.</p>';
  const s = analyzeContent(html, 'https://captcha-verify.top/');
  const clickfix = s.find((x) => x.id === 'content.clickfix');
  assert.ok(clickfix, 'clickfix should fire');
  assert.equal(clickfix.severity, 'critical');
  assert.equal(decide(s, { mode: 'relaxed' }).verdict, 'block', 'must block even in relaxed mode');
});

test('seed-phrase harvesting is blocked in every mode', () => {
  const html = '<h2>Restore your wallet</h2><p>Enter your 12 word recovery phrase</p><textarea></textarea>';
  const s = analyzeContent(html, 'https://wallet-restore.xyz/');
  assert.ok(s.some((x) => x.id === 'content.seed-phrase' && x.severity === 'critical'));
  assert.equal(decide(s, { mode: 'relaxed' }).verdict, 'block');
});

test('tech-support scareware is caught', () => {
  const html = '<h1>CRITICAL ALERT</h1><p>Your computer is infected. Call Microsoft support now. '
    + 'Do not restart your computer.</p><script>document.documentElement.requestFullscreen()</script>';
  const s = analyzeContent(html, 'https://alert-microsoft-support.icu/');
  assert.ok(s.some((x) => x.id === 'content.scareware'));
});

test('obfuscated javascript is detected', () => {
  const html = `<script>eval(atob("${'A'.repeat(40)}"));var _0xabc12=1;</script>`;
  assert.ok(ids(html, 'https://x.com/').includes('content.obfuscated-js'));
});

test('cryptominers are detected', () => {
  const html = '<script src="https://cdn.x/coinhive.min.js"></script>'
    + '<script>var m=new CoinHive.Anonymous("k");WebAssembly.instantiate(cryptonight)</script>';
  assert.ok(ids(html, 'https://blog.example/').includes('content.cryptominer'));
});

test('invisible iframes are reported', () => {
  const html = '<iframe src="https://other.tk/" style="display:none"></iframe>';
  assert.ok(ids(html, 'https://x.com/').includes('content.hidden-iframe'));
});

test('drive-by downloads started by script are reported', () => {
  const html = '<script>window.location.href="https://cdn.tk/setup.exe"</script>';
  assert.ok(ids(html, 'https://x.com/').includes('content.drive-by-download'));
});

test('ordinary pages produce no findings', () => {
  const html = '<!doctype html><title>Recipes</title><h1>Bread</h1><p>Mix flour and water.</p>'
    + '<script src="/static/app.js"></script><img src="/img/bread.jpg">';
  const s = analyzeContent(html, 'https://example.com/recipes');
  assert.equal(decide(s, { mode: 'balanced' }).verdict, 'allow');
  assert.equal(s.length, 0, JSON.stringify(s));
});

test('a normal login page on its own site is not flagged', () => {
  const html = '<title>Sign in</title><form action="/session" method="post">'
    + '<input type="email"><input type="password"></form>';
  const s = analyzeContent(html, 'https://app.example.com/login');
  assert.equal(decide(s, { mode: 'balanced' }).verdict, 'allow');
});

// --- certificates ----------------------------------------------------------

test('a certificate for the wrong host is critical', () => {
  const s = analyzeCertificate({
    subjectName: 'shop.other.com',
    subjectAltName: 'DNS:shop.other.com',
    issuerName: 'R3',
  }, 'mybank.example');
  assert.ok(s.some((x) => x.id === 'tls.name-mismatch' && x.severity === 'critical'));
});

test('wildcards are matched only one label deep', () => {
  const cert = { subjectName: '*.example.com', subjectAltName: 'DNS:*.example.com', issuerName: 'R3' };
  assert.ok(!analyzeCertificate(cert, 'www.example.com').some((x) => x.id === 'tls.name-mismatch'));
  assert.ok(analyzeCertificate(cert, 'a.b.example.com').some((x) => x.id === 'tls.name-mismatch'));
});

test('a certificate issued hours ago is a signal, not a verdict', () => {
  const now = Date.now();
  const s = analyzeCertificate({
    subjectName: 'new-site.example',
    subjectAltName: 'DNS:new-site.example',
    issuerName: "R3 Let's Encrypt",
    validStart: Math.floor((now - 3600000) / 1000),
    validExpiry: Math.floor((now + 60 * DAY) / 1000),
  }, 'new-site.example', { now });
  assert.ok(s.some((x) => x.id === 'tls.brand-new-cert'));
  assert.notEqual(decide(s, { mode: 'balanced' }).verdict, 'block');
});

test('chromium certificate errors are translated into plain language', () => {
  const s = analyzeCertificate(null, 'x.example', { errorCode: 'net::ERR_CERT_AUTHORITY_INVALID' });
  assert.equal(s.length, 1);
  assert.equal(s[0].severity, 'critical');
  assert.match(s[0].detail, /interception|self-signed/i);
});

test('a self-signed certificate is flagged', () => {
  const s = analyzeCertificate({
    subjectName: 'internal.box', issuerName: 'internal.box', subjectAltName: 'DNS:internal.box',
  }, 'internal.box');
  assert.ok(s.some((x) => x.id === 'tls.self-signed'));
});

// --- permissions -----------------------------------------------------------

test('dangerous permissions are refused by default', () => {
  const settings = { get: (k) => ({ 'hardening.denyPermissions': true, 'hardening.allowedPermissions': [] }[k]) };
  for (const p of ['media', 'geolocation', 'notifications', 'clipboard-read', 'openExternal', 'usb', 'display-capture']) {
    assert.equal(decidePermission(p, 'https://random.tk', settings).allow, false, p);
  }
  assert.equal(decidePermission('fullscreen', 'https://x.com', settings).allow, true);
});

test('a per-site exception is honoured, and only for that site', () => {
  const settings = { get: (k) => ({
    'hardening.denyPermissions': true,
    'hardening.allowedPermissions': ['meet.google.com:media'],
  }[k]) };
  assert.equal(decidePermission('media', 'https://meet.google.com', settings).allow, true);
  assert.equal(decidePermission('media', 'https://evil.tk', settings).allow, false);
  assert.equal(decidePermission('geolocation', 'https://meet.google.com', settings).allow, false);
});

test('permissions that are never safe stay denied even with hardening off', () => {
  const settings = { get: (k) => ({ 'hardening.denyPermissions': false }[k]) };
  assert.equal(decidePermission('openExternal', 'https://x.com', settings).allow, false);
  assert.equal(decidePermission('usb', 'https://x.com', settings).allow, false);
});
