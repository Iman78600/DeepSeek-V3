#!/usr/bin/env node
'use strict';
/**
 * Generates a Safari content blocker rule list from Shadow's blocklists.
 *
 * Safari on iOS accepts a declarative JSON rule list, applied by WebKit itself
 * before a request is made. It is the one part of Shadow's firewall that can
 * run inside Safari rather than only inside Shadow.
 *
 * Limits imposed by WebKit, which is why this file caps things:
 *   - 150,000 rules per list, hard ceiling
 *   - purely declarative: no JavaScript, no scoring, no per-request decisions
 *   - the extension cannot see what was blocked, so there is no SOC log
 *
 * Ordering matters: highest-value categories are emitted first so that if the
 * cap truncates anything, it truncates advertising rather than malware.
 */

const fs = require('fs');
const path = require('path');
const { Blocklists } = require('../src/main/firewall/blocklists');

const MAX_RULES = 150000;
const OUT = path.join(__dirname, 'shadow-blocker.json');

// Most consequential first. Truncation should cost you ad blocking, not
// malware blocking.
const PRIORITY = ['malware', 'phishing', 'scam', 'mining', 'custom', 'tracker', 'ads'];

function build() {
  const lists = new Blocklists({ dir: path.join(__dirname, '..', 'config', 'lists') }).load();
  const rules = [];
  const seen = new Set();
  const counts = {};

  for (const category of PRIORITY) {
    const set = lists.lists.get(category);
    if (!set || !set.size) continue;
    counts[category] = 0;

    for (const domain of set) {
      if (rules.length >= MAX_RULES) break;
      if (seen.has(domain)) continue;
      seen.add(domain);

      // Anchored to the domain and its subdomains. if-domain would match the
      // page's domain; unless-domain the opposite. We want the *destination*,
      // so the filter is on the URL itself.
      rules.push({
        action: { type: 'block' },
        trigger: {
          'url-filter': `^https?://([^/]+\\.)?${domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[:/]`,
          'load-type': category === 'tracker' || category === 'ads' ? ['third-party'] : undefined,
        },
      });
      counts[category]++;
    }
  }

  // Drop undefined keys: WebKit rejects a rule list with unknown or null values.
  for (const rule of rules) {
    if (rule.trigger['load-type'] === undefined) delete rule.trigger['load-type'];
  }

  // Upgrade plain HTTP wherever the site supports it, the same intent as the
  // desktop firewall's https-only mode.
  rules.push({
    action: { type: 'make-https' },
    trigger: { 'url-filter': '^http://', 'resource-type': ['document', 'image', 'style-sheet', 'script', 'raw'] },
  });

  fs.writeFileSync(OUT, JSON.stringify(rules));
  const kb = (fs.statSync(OUT).size / 1024).toFixed(0);

  console.log(`built ${path.relative(process.cwd(), OUT)}`);
  console.log(`  ${rules.length.toLocaleString()} rules, ${kb} KB (WebKit cap is ${MAX_RULES.toLocaleString()})`);
  for (const [cat, n] of Object.entries(counts)) {
    console.log(`  ${cat.padEnd(10)} ${n.toLocaleString()}`);
  }
  if (rules.length >= MAX_RULES) {
    console.log('\n  Cap reached. Lower-priority categories were truncated.');
    console.log('  Run npm run update-lists for the full feeds, then regenerate.');
  }
  return OUT;
}

if (require.main === module) build();
module.exports = { build, MAX_RULES };
