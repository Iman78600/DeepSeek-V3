#!/usr/bin/env node
'use strict';
/**
 * Shadow's analyst, on the command line.
 *
 *   npm run scan -- url  https://paypal.com.verify-login.tk/account
 *   npm run scan -- file ./suspicious.docx
 *   npm run scan -- page https://example.com          (fetches, then analyses)
 *
 * Same code the browser runs. Useful for testing rules, triaging a file
 * someone sent you, and proving the engine works without launching a GUI.
 */

const fs = require('fs');
const path = require('path');

const { analyzeUrl } = require('../src/main/soc/heuristics/url-heuristics');
const { analyzeContent } = require('../src/main/soc/heuristics/content-heuristics');
const { decide } = require('../src/main/soc/scoring');
const { Blocklists } = require('../src/main/firewall/blocklists');
const { scanFile } = require('../src/main/sandbox/scanner');
const { decideRequest, parseRequest } = require('../src/main/firewall/firewall');

const C = process.stdout.isTTY ? {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', yellow: '\x1b[33m', green: '\x1b[32m',
  orange: '\x1b[38;5;208m', grey: '\x1b[90m', cyan: '\x1b[36m',
} : new Proxy({}, { get: () => '' });

const SEV_COLOR = {
  critical: C.red, high: C.orange, medium: C.yellow, low: C.grey, info: C.cyan,
};

function printVerdict(verdict, subject) {
  const color = verdict.verdict === 'block' ? C.red : verdict.verdict === 'warn' ? C.yellow : C.green;
  console.log('');
  console.log(`${C.bold}${subject}${C.reset}`);
  console.log(`${color}${C.bold}${verdict.verdict.toUpperCase()}${C.reset}  risk ${C.bold}${verdict.score}${C.reset}/100  severity ${verdict.severity}  (${verdict.mode} mode, blocks at ${verdict.threshold.block})`);
  console.log('');
  if (!verdict.signals.length) {
    console.log(`  ${C.grey}No findings.${C.reset}`);
  }
  for (const s of verdict.signals) {
    const col = SEV_COLOR[s.severity] || '';
    const score = String(s.score).padStart(3);
    console.log(`  ${col}[${String(s.severity).padEnd(8)}]${C.reset} ${C.dim}${score}${C.reset}  ${C.bold}${s.title}${C.reset}`);
    if (s.detail) console.log(`             ${C.grey}${s.detail}${C.reset}`);
  }
  console.log('');
}

async function cmdUrl(target, mode) {
  const blocklists = new Blocklists({ dir: path.join(__dirname, '..', 'config', 'lists') }).load();
  const signals = analyzeUrl(target);
  let hostname = '';
  try { hostname = new URL(target).hostname; } catch { /* analyzeUrl already flagged it */ }
  if (hostname) {
    for (const hit of blocklists.match(hostname, target)) {
      signals.push({ id: `blocklist.${hit.list}`, score: hit.score, severity: hit.severity, title: hit.title, detail: hit.detail });
    }
  }
  printVerdict(decide(signals, { mode }), target);
}

async function cmdPage(target, mode) {
  process.stdout.write(`${C.grey}fetching ${target} ...${C.reset}\n`);
  let html = '';
  try {
    const res = await fetch(target, { redirect: 'follow', headers: { 'User-Agent': 'Mozilla/5.0' } });
    html = await res.text();
  } catch (err) {
    console.error(`${C.red}fetch failed: ${err.message}${C.reset}`);
    process.exitCode = 2;
    return;
  }
  const signals = [...analyzeUrl(target), ...analyzeContent(html, target)];
  printVerdict(decide(signals, { mode }), target);
}

async function cmdFile(target, mode) {
  if (!fs.existsSync(target)) {
    console.error(`${C.red}no such file: ${target}${C.reset}`);
    process.exitCode = 2;
    return;
  }
  const report = await scanFile(target, { originalName: path.basename(target) });
  const verdict = decide(report.signals, { mode });

  console.log('');
  console.log(`${C.bold}${report.file.name}${C.reset}  ${C.grey}${report.file.sizeHuman}${C.reset}`);
  console.log(`  real type: ${C.bold}${report.detectedType}${C.reset}   declared: ${report.declaredExtension || '(none)'}`);
  console.log(`  sha256:    ${C.grey}${report.hashes.sha256}${C.reset}`);
  if (report.network.urls.length) console.log(`  urls:      ${C.grey}${report.network.urls.slice(0, 3).join(', ')}${C.reset}`);
  if (report.network.ips.length) console.log(`  ips:       ${C.grey}${report.network.ips.slice(0, 5).join(', ')}${C.reset}`);
  if (report.formatInfo.pe) {
    const pe = report.formatInfo.pe;
    console.log(`  pe:        ${pe.machine || '?'}${pe.isDll ? ' dll' : ''}, ${pe.sections.length} sections, built ${pe.compiledAt || '?'}`);
  }
  if (report.formatInfo.zip) {
    console.log(`  archive:   ${report.formatInfo.zip.entryCount} entries${report.formatInfo.zip.encrypted ? ', ENCRYPTED' : ''}`);
  }
  printVerdict(verdict, target);
}

function cmdRequest(target, mode) {
  const settings = { get: (k) => ({
    'firewall.blockPrivateNetwork': true,
    'firewall.httpsOnly': true,
    'firewall.blockTrackers': true,
    'firewall.blockAds': true,
    'firewall.blockMining': true,
  }[k]) };
  const blocklists = new Blocklists({ dir: path.join(__dirname, '..', 'config', 'lists'), settings }).load();
  const decision = decideRequest(parseRequest({ url: target, resourceType: 'xhr', referrer: 'https://example.com/' }),
    { settings, blocklists, rules: [] });
  const color = decision.action === 'block' ? C.red : decision.action === 'upgrade' ? C.yellow : C.green;
  console.log('');
  console.log(`${C.bold}${target}${C.reset}`);
  console.log(`${color}${C.bold}${decision.action.toUpperCase()}${C.reset}  ${decision.reason || ''}`);
  if (decision.detail) console.log(`  ${C.grey}${decision.detail}${C.reset}`);
  if (decision.redirectURL) console.log(`  ${C.grey}-> ${decision.redirectURL}${C.reset}`);
  console.log('');
  void mode;
}

function usage() {
  console.log(`
${C.bold}Shadow analyst CLI${C.reset}

  node tools/scan-cli.js url     <url>    score a link without visiting it
  node tools/scan-cli.js page    <url>    fetch the page and score its content
  node tools/scan-cli.js file    <path>   take a file apart in the sandbox scanner
  node tools/scan-cli.js request <url>    ask the firewall what it would do

Options
  --mode strict|balanced|relaxed   how much evidence it takes to block (default balanced)
`);
}

(async function main() {
  const args = process.argv.slice(2);
  const modeIdx = args.indexOf('--mode');
  const mode = modeIdx >= 0 ? args[modeIdx + 1] : 'balanced';
  const positional = args.filter((a, i) => a !== '--mode' && (modeIdx < 0 || i !== modeIdx + 1));

  const [cmd, target] = positional;
  if (!cmd || !target) { usage(); process.exitCode = 1; return; }

  switch (cmd) {
    case 'url': await cmdUrl(target, mode); break;
    case 'page': await cmdPage(target, mode); break;
    case 'file': await cmdFile(target, mode); break;
    case 'request': cmdRequest(target, mode); break;
    default: usage(); process.exitCode = 1;
  }
}());
