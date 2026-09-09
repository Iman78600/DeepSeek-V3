#!/usr/bin/env node
'use strict';
/**
 * Refresh Shadow's blocklists from public feeds.
 *
 *   node tools/update-blocklists.js            all categories
 *   node tools/update-blocklists.js malware    one category
 *
 * Shadow ships with a small built-in seed so it works offline. This pulls the
 * real lists. Everything is written to config/lists/<category>.txt in a plain
 * one-domain-per-line format, so you can inspect or edit them by hand.
 *
 * Nothing here sends your browsing anywhere: these are downloads of public
 * files, run when you choose to run them.
 */

const fs = require('fs');
const path = require('path');
const { normalizeLine } = require('../src/main/firewall/blocklists');

const LIST_DIR = path.join(__dirname, '..', 'config', 'lists');

const FEEDS = {
  malware: [
    'https://urlhaus.abuse.ch/downloads/hostfile/',
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts',
  ],
  phishing: [
    'https://phishing.army/download/phishing_army_blocklist_extended.txt',
    'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
  ],
  mining: [
    'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt',
  ],
  scam: [
    'https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt',
  ],
  tracker: [
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts',
    'https://easylist.to/easyprivacy/easyprivacy.txt',
  ],
  ads: [
    'https://easylist.to/easylist/easylist.txt',
  ],
};

const MAX_BYTES = 40 * 1024 * 1024;

async function fetchList(url) {
  const res = await fetch(url, {
    headers: { 'User-Agent': 'Shadow-Browser/0.1 (blocklist updater)' },
    redirect: 'follow',
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  if (text.length > MAX_BYTES) throw new Error(`list too large (${text.length} bytes)`);
  return text;
}

async function updateCategory(category) {
  const feeds = FEEDS[category];
  if (!feeds) throw new Error(`unknown category "${category}"`);
  const domains = new Set();
  const problems = [];

  for (const url of feeds) {
    process.stdout.write(`  ${url} ... `);
    try {
      const text = await fetchList(url);
      let added = 0;
      for (const line of text.split(/\r?\n/)) {
        const d = normalizeLine(line);
        if (d) { if (!domains.has(d)) added++; domains.add(d); }
      }
      console.log(`${added.toLocaleString()} new`);
    } catch (err) {
      console.log(`FAILED (${err.message})`);
      problems.push({ url, error: err.message });
    }
  }

  if (!domains.size) {
    console.log(`  no entries for ${category}, leaving the existing list alone`);
    return { category, count: 0, problems };
  }

  fs.mkdirSync(LIST_DIR, { recursive: true });
  const out = path.join(LIST_DIR, `${category}.txt`);
  const header = [
    `# Shadow blocklist: ${category}`,
    `# Generated ${new Date().toISOString()}`,
    `# Sources: ${feeds.join(', ')}`,
    `# ${domains.size} domains`,
    '',
  ].join('\n');
  fs.writeFileSync(out, header + [...domains].sort().join('\n') + '\n');
  console.log(`  wrote ${domains.size.toLocaleString()} domains to ${path.relative(process.cwd(), out)}`);
  return { category, count: domains.size, problems };
}

(async function main() {
  const only = process.argv[2];
  const categories = only ? [only] : Object.keys(FEEDS);

  console.log('Updating Shadow blocklists\n');
  const results = [];
  for (const category of categories) {
    console.log(`${category}:`);
    try {
      results.push(await updateCategory(category));
    } catch (err) {
      console.error(`  ${err.message}`);
      process.exitCode = 1;
    }
    console.log('');
  }

  const total = results.reduce((s, r) => s + r.count, 0);
  console.log(`Done. ${total.toLocaleString()} domains across ${results.length} categories.`);
  const failed = results.flatMap((r) => r.problems);
  if (failed.length) {
    console.log(`\n${failed.length} feed(s) could not be fetched. The categories they belong to`);
    console.log('still contain whatever the other feeds provided.');
  }
}());
