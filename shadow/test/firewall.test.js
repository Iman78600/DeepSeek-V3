'use strict';
const { test } = require('node:test');
const assert = require('node:assert');

const { decideRequest, parseRequest, hardenRequestHeaders } = require('../src/main/firewall/firewall');
const { Blocklists, normalizeLine } = require('../src/main/firewall/blocklists');
const { classifyHost, classifyIp, evaluate, BLOCKED_PORTS } = require('../src/main/firewall/rules');

const settings = (overrides = {}) => ({
  get: (k) => ({
    'firewall.blockPrivateNetwork': true,
    'firewall.httpsOnly': true,
    'firewall.blockTrackers': true,
    'firewall.blockAds': true,
    'firewall.blockMining': true,
    'firewall.lockdown': false,
    'firewall.blockThreshold': 10,
    ...overrides,
  })[k],
});

const blocklists = new Blocklists({ settings: settings() });

const ask = (details, opts = {}) => decideRequest(
  parseRequest(details),
  { settings: settings(opts.settings), blocklists, rules: opts.rules || [] },
);

test('a page on the internet cannot reach the local network', () => {
  for (const host of ['192.168.1.1', '10.0.0.5', '127.0.0.1', 'router.local', '172.16.4.4']) {
    const d = ask({ url: `http://${host}/admin`, referrer: 'https://evil.com/', resourceType: 'xhr' });
    assert.equal(d.action, 'block', `${host} should be blocked`);
    assert.equal(d.category, 'ssrf');
  }
});

test('cloud metadata endpoints are always blocked', () => {
  const d = ask({ url: 'http://169.254.169.254/latest/meta-data/iam/', referrer: 'https://evil.com/', resourceType: 'xhr' });
  assert.equal(d.action, 'block');
  assert.equal(d.reason, 'metadata');
});

test('a local page may still reach the local network', () => {
  const d = ask({ url: 'http://192.168.1.50:8080/api', referrer: 'http://192.168.1.50:3000/', resourceType: 'xhr' });
  assert.equal(d.action, 'allow');
});

test('typing a LAN address yourself is allowed', () => {
  const d = ask({ url: 'http://192.168.1.1/', resourceType: 'mainFrame' });
  assert.equal(d.action, 'allow');
});

test('non-web ports are refused', () => {
  for (const port of [22, 25, 445, 3389, 6379, 5432]) {
    const d = ask({ url: `https://example.com:${port}/`, resourceType: 'xhr' });
    assert.equal(d.action, 'block', `port ${port} should be blocked`);
    assert.equal(d.reason, 'port');
  }
  assert.ok(BLOCKED_PORTS.has(445));
});

test('non-web schemes never leave the browser', () => {
  const d = ask({ url: 'smb://fileserver/share', resourceType: 'subFrame' });
  assert.equal(d.action, 'block');
  assert.equal(d.reason, 'scheme');
});

test('plain HTTP is upgraded, not silently allowed', () => {
  const d = ask({ url: 'http://example.com/page', resourceType: 'mainFrame' });
  assert.equal(d.action, 'upgrade');
  assert.equal(d.redirectURL, 'https://example.com/page');
});

test('HTTPS-only can be turned off', () => {
  const d = ask({ url: 'http://example.com/page', resourceType: 'mainFrame' },
    { settings: { 'firewall.httpsOnly': false } });
  assert.equal(d.action, 'allow');
});

test('blocklisted hosts are dropped, and toggles are honoured', () => {
  const tracker = ask({ url: 'https://doubleclick.net/pixel', referrer: 'https://news.com/', resourceType: 'image' });
  assert.equal(tracker.action, 'block');
  assert.equal(tracker.category, 'tracker');

  const bl = new Blocklists({ settings: settings({ 'firewall.blockTrackers': false }) });
  const allowed = decideRequest(
    parseRequest({ url: 'https://doubleclick.net/pixel', referrer: 'https://news.com/', resourceType: 'image' }),
    { settings: settings({ 'firewall.blockTrackers': false }), blocklists: bl, rules: [] });
  assert.equal(allowed.action, 'allow');
});

test('cryptominers are blocked even with ads and trackers allowed', () => {
  const bl = new Blocklists({ settings: settings({ 'firewall.blockTrackers': false, 'firewall.blockAds': false }) });
  const d = decideRequest(
    parseRequest({ url: 'https://coinhive.com/lib/miner.min.js', referrer: 'https://blog.com/', resourceType: 'script' }),
    { settings: settings({ 'firewall.blockTrackers': false, 'firewall.blockAds': false }), blocklists: bl, rules: [] });
  assert.equal(d.action, 'block');
  assert.equal(d.category, 'mining');
});

test('lockdown mode blocks third-party scripts but not first-party ones', () => {
  const third = ask({ url: 'https://cdn.other.com/a.js', referrer: 'https://site.com/', resourceType: 'script' },
    { settings: { 'firewall.lockdown': true } });
  assert.equal(third.action, 'block');
  assert.equal(third.reason, 'lockdown');

  const first = ask({ url: 'https://site.com/a.js', referrer: 'https://site.com/', resourceType: 'script' },
    { settings: { 'firewall.lockdown': true } });
  assert.equal(first.action, 'allow');
});

test('user rules run first and can allow or block', () => {
  const allowRule = [{ action: 'allow', match: { hostSuffix: 'doubleclick.net' } }];
  assert.equal(ask({ url: 'https://doubleclick.net/x', resourceType: 'image' }, { rules: allowRule }).action, 'allow');

  const blockRule = [{ action: 'block', match: { host: '*.example.com' }, comment: 'nope' }];
  const d = ask({ url: 'https://a.example.com/', resourceType: 'mainFrame' }, { rules: blockRule });
  assert.equal(d.action, 'block');
  assert.equal(d.detail, 'nope');
});

test('subdomains of a blocklisted domain are also blocked', () => {
  const d = ask({ url: 'https://metrics.cdn.doubleclick.net/x', referrer: 'https://a.com/', resourceType: 'image' });
  assert.equal(d.action, 'block');
});

test('blocklist parsing accepts hosts, adblock and plain formats', () => {
  assert.equal(normalizeLine('0.0.0.0 ads.example.com'), 'ads.example.com');
  assert.equal(normalizeLine('||tracker.example.org^$third-party'), 'tracker.example.org');
  assert.equal(normalizeLine('  Bad.Example.NET  '), 'bad.example.net');
  assert.equal(normalizeLine('# a comment'), null);
  assert.equal(normalizeLine('localhost'), null);
  assert.equal(normalizeLine('not a domain'), null);
});

test('private IP classification covers the ranges that matter', () => {
  assert.ok(classifyIp('10.1.2.3').private);
  assert.ok(classifyIp('172.31.255.255').private);
  assert.ok(!classifyIp('172.32.0.1'));
  assert.ok(classifyIp('::1').private);
  assert.ok(classifyIp('::ffff:192.168.1.1').private);
  assert.equal(classifyIp('8.8.8.8'), null);
  assert.ok(classifyHost('printer.lan').private);
  assert.ok(classifyHost('metadata.google.internal').metadata);
});

test('rule evaluation matches on the fields it advertises', () => {
  const rules = [{ action: 'block', match: { resourceType: ['script'], thirdParty: true } }];
  assert.ok(evaluate(rules, { resourceType: 'script', thirdParty: true }));
  assert.equal(evaluate(rules, { resourceType: 'script', thirdParty: false }), null);
  assert.equal(evaluate(rules, { resourceType: 'image', thirdParty: true }), null);
});

test('identifying request headers are stripped and privacy headers added', () => {
  const out = hardenRequestHeaders({
    requestHeaders: {
      'Sec-CH-UA-Model': ['Pixel 8'],
      'Device-Memory': ['8'],
      Referer: ['https://example.com/secret/path?token=abc'],
      Accept: ['*/*'],
    },
  }, { settings: settings() });
  assert.ok(!('Sec-CH-UA-Model' in out));
  assert.ok(!('Device-Memory' in out));
  assert.deepEqual(out.Referer, ['https://example.com/']);
  assert.deepEqual(out.DNT, ['1']);
  assert.deepEqual(out['Sec-GPC'], ['1']);
  assert.deepEqual(out.Accept, ['*/*']);
});

test('ordinary traffic is left alone', () => {
  for (const url of ['https://example.com/', 'https://cdn.jsdelivr.net/npm/x/x.js', 'wss://chat.example.com/socket']) {
    assert.equal(ask({ url, referrer: 'https://example.com/', resourceType: 'script' }).action, 'allow', url);
  }
});
