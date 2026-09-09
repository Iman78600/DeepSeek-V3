'use strict';
const { test } = require('node:test');
const assert = require('node:assert');

const {
  analyzeUrl, splitHost, isIpLiteral, entropy, levenshtein, pronounceability,
} = require('../src/main/soc/heuristics/url-heuristics');
const { decide } = require('../src/main/soc/scoring');

const ids = (url) => analyzeUrl(url).map((s) => s.id);
const verdict = (url, mode = 'balanced') => decide(analyzeUrl(url), { mode }).verdict;

test('splitHost finds the registrable domain through multi-label suffixes', () => {
  assert.equal(splitHost('www.example.co.uk').registrable, 'example.co.uk');
  assert.equal(splitHost('a.b.c.example.com').registrable, 'example.com');
  assert.equal(splitHost('example.com').registrable, 'example.com');
  assert.equal(splitHost('user.github.io').registrable, 'user.github.io');
  assert.equal(splitHost('deep.a.b.co.jp').domain, 'b');
});

test('IP literals are recognised, including obfuscated encodings', () => {
  assert.equal(isIpLiteral('192.168.1.1'), 'ipv4');
  assert.equal(isIpLiteral('2130706433'), 'ipv4-decimal');
  assert.equal(isIpLiteral('0x7f000001'), 'ipv4-hex');
  assert.equal(isIpLiteral('example.com'), null);
});

test('pronounceability separates words from generated names', () => {
  assert.ok(pronounceability('stackoverflow').wordLike);
  assert.ok(pronounceability('cloudflare').wordLike);
  assert.ok(!pronounceability('xkqjvbzmrtpl').wordLike);
  assert.ok(!pronounceability('kjhsdfkjhwqr').wordLike);
});

test('levenshtein is bounded and correct', () => {
  assert.equal(levenshtein('paypal', 'paypal'), 0);
  assert.equal(levenshtein('paypal', 'paypai'), 1);
  assert.equal(levenshtein('microsoft', 'micros0ft'), 1);
  assert.equal(levenshtein('apple', 'aple'), 1);
  assert.ok(levenshtein('short', 'averylongstring', 2) > 2);
});

test('brand in a subdomain is caught, the real brand is not', () => {
  assert.ok(ids('https://paypal.com.login.evil.tk/').includes('url.brand-in-subdomain'));
  assert.ok(ids('https://apple.com-verify.xyz/').includes('url.brand-in-subdomain'));
  assert.ok(!ids('https://www.paypal.com/signin').includes('url.brand-in-subdomain'));
  assert.ok(!ids('https://appleid.apple.com/').includes('url.brand-in-subdomain'));
});

test('typosquats are caught', () => {
  assert.ok(ids('https://micros0ft.com/login').includes('url.typosquat'));
  assert.ok(ids('https://paypa1.com/').includes('url.typosquat'));
  assert.ok(!ids('https://microsoft.com/').includes('url.typosquat'));
});

test('userinfo obfuscation is caught', () => {
  const s = analyzeUrl('https://www.paypal.com@evil.tk/login');
  assert.ok(s.some((x) => x.id === 'url.userinfo'));
});

test('homograph and punycode domains are flagged', () => {
  assert.ok(ids('https://xn--pypal-4ve.com/').includes('url.punycode'));
  // Cyrillic "а" in place of Latin "a"
  assert.ok(ids('https://аpple.com/').includes('url.mixed-script'));
});

test('dangerous ports and schemes are flagged', () => {
  assert.ok(ids('https://example.com:22/').includes('url.odd-port'));
  assert.ok(ids('javascript:alert(1)').includes('url.javascript-scheme'));
  assert.ok(ids('data:text/html,<script>x</script>').includes('url.data-scheme'));
});

test('login pages over plain HTTP are high severity', () => {
  const s = analyzeUrl('http://example.com/account/login/verify');
  assert.ok(s.some((x) => x.id === 'url.login-over-http' && x.severity === 'high'));
});

test('open-redirect parameters are noticed', () => {
  assert.ok(ids('https://example.com/go?redirect=https://evil.tk/x').includes('url.open-redirect'));
});

test('known-good sites produce no findings', () => {
  const clean = [
    'https://www.google.com/search?q=test',
    'https://github.com/torvalds/linux',
    'https://en.wikipedia.org/wiki/Security',
    'https://www.bbc.co.uk/news',
    'https://stackoverflow.com/questions/12345/some-question-title',
    'https://cdn.jsdelivr.net/npm/pkg@1.2.3/dist/pkg.min.js',
    'https://news.ycombinator.com/item?id=1',
    'https://developer.mozilla.org/en-US/docs/Web/API',
  ];
  for (const url of clean) {
    assert.equal(verdict(url), 'allow', `${url} should be allowed, got ${JSON.stringify(analyzeUrl(url))}`);
  }
});

test('classic phishing URLs are blocked', () => {
  const bad = [
    'http://paypal.com.secure-verify.tk/login/confirm-account',
    'https://appleid.apple.com.verify-account.icu/signin/password',
    'http://192.168.0.1@203.0.113.9/login/verify/account',
  ];
  for (const url of bad) {
    assert.equal(verdict(url), 'block', `${url} should be blocked`);
  }
});

test('entropy is sane', () => {
  assert.equal(entropy(''), 0);
  assert.equal(entropy('aaaa'), 0);
  assert.ok(entropy('abcd') > 1.9);
});
