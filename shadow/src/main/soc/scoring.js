'use strict';
/**
 * Turns a pile of signals into one decision.
 *
 * Design notes:
 *  - Scores are combined with diminishing returns, not a plain sum. Ten weak
 *    signals should not outrank one certain one, and one strong signal should
 *    not be diluted by a lot of noise.
 *  - Any signal at or above CERTAIN_SCORE forces a block regardless of the
 *    combined total. Those are the "no legitimate site does this" checks.
 *  - Allowlisted origins can only ever reach "warn", never "block", so a
 *    false positive on your bank cannot lock you out.
 */

const CERTAIN_SCORE = 85;

const THRESHOLDS = {
  strict:   { block: 45, warn: 20 },
  balanced: { block: 65, warn: 35 },
  relaxed:  { block: 85, warn: 55 },
};

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * Combine positive signal scores with diminishing returns:
 *   total = 100 * (1 - product(1 - s_i/100))
 * Negative scores (trust signals) are subtracted afterwards.
 */
function combine(signals) {
  let survival = 1;
  let credit = 0;
  for (const s of signals) {
    const v = Number(s.score) || 0;
    if (v > 0) survival *= 1 - Math.min(v, 99) / 100;
    else credit += -v;
  }
  const raw = 100 * (1 - survival);
  return Math.max(0, Math.min(100, raw - credit));
}

function highestSeverity(signals) {
  let best = 'info';
  for (const s of signals) {
    if ((SEVERITY_RANK[s.severity] ?? 0) > (SEVERITY_RANK[best] ?? 0)) best = s.severity;
  }
  return best;
}

/**
 * @param {Array} signals
 * @param {object} [opts] { mode, allowlisted, blocklisted }
 * @returns {{score, verdict, severity, certain, signals, reasons, threshold}}
 */
function decide(signals, opts = {}) {
  const mode = THRESHOLDS[opts.mode] ? opts.mode : 'balanced';
  const t = THRESHOLDS[mode];
  const list = (signals || []).filter(Boolean);

  const score = Math.round(combine(list));
  const certain = list.filter((s) => (Number(s.score) || 0) >= CERTAIN_SCORE);

  let verdict;
  if (opts.blocklisted) verdict = 'block';
  else if (certain.length) verdict = 'block';
  else if (score >= t.block) verdict = 'block';
  else if (score >= t.warn) verdict = 'warn';
  else verdict = 'allow';

  // An explicitly trusted origin is never hard-blocked by heuristics.
  if (opts.allowlisted && verdict === 'block' && !opts.blocklisted) verdict = 'warn';

  const ranked = [...list].sort((a, b) => (Number(b.score) || 0) - (Number(a.score) || 0));

  return {
    score,
    verdict,
    severity: highestSeverity(list),
    certain: certain.map((s) => s.id),
    mode,
    threshold: t,
    signals: ranked,
    reasons: ranked.filter((s) => (Number(s.score) || 0) > 0).slice(0, 6)
      .map((s) => ({ id: s.id, title: s.title, detail: s.detail, severity: s.severity })),
  };
}

module.exports = { decide, combine, highestSeverity, THRESHOLDS, CERTAIN_SCORE, SEVERITY_RANK };
