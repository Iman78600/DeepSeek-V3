'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { decide, combine, CERTAIN_SCORE } = require('../src/main/soc/scoring');

const sig = (score, severity = 'medium', id = 'x') => ({ id, score, severity, title: 't', detail: 'd' });

test('combining has diminishing returns and never exceeds 100', () => {
  assert.ok(combine([sig(50), sig(50)]) < 100);
  assert.ok(combine([sig(50), sig(50)]) > 50);
  assert.ok(combine(Array.from({ length: 20 }, () => sig(30))) <= 100);
});

test('many weak signals do not outrank one certain signal', () => {
  const weak = decide(Array.from({ length: 6 }, () => sig(12, 'low')), { mode: 'balanced' });
  const certain = decide([sig(90, 'critical')], { mode: 'balanced' });
  assert.equal(certain.verdict, 'block');
  assert.notEqual(weak.verdict, 'block');
});

test('a single signal at or above the certainty bar always blocks', () => {
  const d = decide([sig(CERTAIN_SCORE, 'critical', 'content.seed-phrase')], { mode: 'relaxed' });
  assert.equal(d.verdict, 'block');
  assert.deepEqual(d.certain, ['content.seed-phrase']);
});

test('trust signals (negative scores) reduce the total', () => {
  const without = decide([sig(60)], { mode: 'balanced' }).score;
  const with_ = decide([sig(60), sig(-20, 'info')], { mode: 'balanced' }).score;
  assert.ok(with_ < without);
});

test('strictness modes move the thresholds', () => {
  // Two moderate signals combine to ~52: over the strict block line (45),
  // under the relaxed warn line (55).
  const signals = [sig(40), sig(20)];
  assert.equal(decide(signals, { mode: 'strict' }).verdict, 'block');
  assert.equal(decide(signals, { mode: 'balanced' }).verdict, 'warn');
  assert.equal(decide(signals, { mode: 'relaxed' }).verdict, 'allow');

  // A stronger set warns in relaxed mode rather than being ignored.
  assert.equal(decide([sig(50), sig(30)], { mode: 'relaxed' }).verdict, 'warn');
});

test('an allowlisted origin is downgraded to a warning, never blocked', () => {
  const d = decide([sig(80, 'high')], { mode: 'balanced', allowlisted: true });
  assert.equal(d.verdict, 'warn');
});

test('an allowlisted origin is still blocked when it is on a blocklist', () => {
  const d = decide([sig(95, 'critical')], { mode: 'balanced', allowlisted: true, blocklisted: true });
  assert.equal(d.verdict, 'block');
});

test('reasons are ranked highest-score-first and capped', () => {
  const d = decide([sig(10), sig(90), sig(50), sig(20), sig(30), sig(40), sig(15), sig(5)], {});
  assert.equal(d.reasons[0].id, 'x');
  assert.equal(d.reasons.length, 6);
  assert.equal(d.signals[0].score, 90);
});

test('no signals means allow with score zero', () => {
  const d = decide([], {});
  assert.equal(d.verdict, 'allow');
  assert.equal(d.score, 0);
});
