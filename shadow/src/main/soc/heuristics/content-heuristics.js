'use strict';
/**
 * Content heuristics - what Shadow's analyst looks for once the page HTML is
 * in hand. Runs on a string, so it works on fetched HTML, on the live DOM
 * snapshot reported by the site preload script, and in unit tests.
 */

const { splitHost, entropy } = require('./url-heuristics');
const { PROTECTED_BRANDS, LEGITIMATE_BRAND_DOMAINS } = require('../data/brands');

function signal(id, score, severity, title, detail) {
  return { id, score, severity, title, detail };
}

const CRYPTO_MINER_MARKERS = [
  'coinhive', 'coin-hive', 'cryptonight', 'crypto-loot', 'cryptoloot',
  'jsecoin', 'minero.cc', 'webminepool', 'coinimp', 'deepminer',
  'webassembly.instantiate', 'stratum+tcp', 'monero', 'nimiq', 'minergate',
  'hashvault', 'coinwebmining', 'cpu-miner',
];

const OBFUSCATION_MARKERS = [
  { re: /eval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)/i, id: 'eval-decode', weight: 30, label: 'eval() around a decoder' },
  { re: /document\.write\s*\(\s*unescape\s*\(/i, id: 'docwrite-unescape', weight: 30, label: 'document.write(unescape(...))' },
  { re: /new\s+Function\s*\(\s*(?:atob|["'`])/i, id: 'function-ctor', weight: 25, label: 'Function() constructor building code from a string' },
  { re: /String\.fromCharCode\s*\((?:\s*\d+\s*,){20,}/i, id: 'charcode-blob', weight: 25, label: 'long String.fromCharCode payload' },
  { re: /(?:\\x[0-9a-f]{2}){30,}/i, id: 'hex-escape-blob', weight: 25, label: 'long hex-escaped string' },
  { re: /(?:\\u00[0-9a-f]{2}){30,}/i, id: 'unicode-escape-blob', weight: 20, label: 'long unicode-escaped string' },
  { re: /_0x[0-9a-f]{4,}/i, id: 'obfuscator-io', weight: 30, label: 'obfuscator.io variable mangling' },
  { re: /atob\s*\(\s*["'][A-Za-z0-9+/=]{200,}["']\s*\)/, id: 'big-base64', weight: 30, label: 'large inline base64 blob passed to atob()' },
  { re: /setTimeout\s*\(\s*(?:atob|unescape|["'])/i, id: 'timeout-string', weight: 15, label: 'setTimeout executing a string' },
  { re: /\[["']constructor["']\]\s*\[["']constructor["']\]/, id: 'constructor-chain', weight: 30, label: 'constructor-of-constructor code execution' },
];

const CLIPBOARD_HIJACK = [
  /navigator\.clipboard\.writeText/i,
  /document\.execCommand\s*\(\s*["']copy["']\s*\)/i,
  /addEventListener\s*\(\s*["']copy["']/i,
];

const KEYLOGGER_MARKERS = [
  /addEventListener\s*\(\s*["']key(?:down|press|up)["'][\s\S]{0,400}?(?:fetch|XMLHttpRequest|sendBeacon|WebSocket)/i,
  /onkeypress\s*=\s*["'][^"']*(?:fetch|ajax|post)/i,
];

const FAKE_UPDATE_TEXT = [
  /your\s+(?:chrome|browser|flash|adobe\s+flash|java|windows)\s+is\s+(?:out\s*of\s*date|outdated)/i,
  /update\s+(?:required|your\s+browser)\s+to\s+continue/i,
  /critical\s+(?:security\s+)?(?:alert|warning)/i,
  /your\s+(?:computer|pc|device)\s+(?:is|has\s+been)\s+infected/i,
  /call\s+(?:microsoft|apple|windows)\s+support/i,
  /do\s+not\s+(?:restart|shut\s*down|turn\s+off)\s+your\s+computer/i,
  /virus(?:es)?\s+detected/i,
  /your\s+(?:subscription|account)\s+(?:has\s+)?expired/i,
];

const CLICKFIX_MARKERS = [
  /press\s+(?:the\s+)?(?:windows|win)\s*(?:\+|\s)\s*r/i,
  /(?:press|hit|type)?\s*ctrl\s*\+\s*v.{0,120}(?:enter|return)\b/i,
  /paste\s+(?:it|this|the\s+code)\s+(?:in|into)\s+(?:the\s+)?(?:run|terminal|powershell|command)/i,
  /verify\s+you\s+are\s+(?:human|not\s+a\s+robot).{0,200}(?:powershell|cmd\.exe|mshta|curl|wget|iwr)/i,
  /(?:powershell|mshta|certutil|bitsadmin|regsvr32)\s+[-/]/i,
];

const SEED_PHRASE_MARKERS = [
  /(?:seed|recovery|mnemonic)\s+(?:phrase|words)/i,
  /12\s*(?:or\s*24\s*)?words?\s+(?:phrase|recovery)/i,
  /(?:private\s+key|wallet\s+passphrase)/i,
];

function countMatches(re, text) {
  const m = text.match(new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g'));
  return m ? m.length : 0;
}

/**
 * @param {string} html   raw page HTML (or a DOM snapshot)
 * @param {string} pageUrl the URL the HTML came from
 * @param {object} [opts]  { forms, externalScripts } observed live by the preload
 */
function analyzeContent(html, pageUrl, opts = {}) {
  const signals = [];
  const text = String(html || '');
  if (!text) return signals;

  let pageHost = '';
  let pageParts = { registrable: '', domain: '', suffix: '' };
  let pageScheme = 'https';
  try {
    const u = new URL(pageUrl);
    pageHost = u.hostname.toLowerCase();
    pageScheme = u.protocol.replace(':', '');
    pageParts = splitHost(pageHost);
  } catch { /* pageUrl optional */ }

  const visible = text
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ');

  // --- Password / credential forms ----------------------------------------
  const passwordInputs = countMatches(/<input[^>]+type\s*=\s*["']?password/i, text);
  const forms = [...text.matchAll(/<form[^>]*>/gi)].map((m) => m[0]);

  if (passwordInputs > 0) {
    if (pageScheme !== 'https') {
      signals.push(signal('content.password-over-http', 70, 'critical', 'Password field on an unencrypted page',
        'Anything you type here is sent in the clear and can be captured by anyone between you and the server.'));
    }
    for (const form of forms) {
      const action = (form.match(/action\s*=\s*["']([^"']+)["']/i) || [])[1];
      if (!action) continue;
      if (/^javascript:/i.test(action)) {
        signals.push(signal('content.form-javascript-action', 55, 'high', 'Login form submits to script',
          'The form hands your credentials to page JavaScript instead of a server, which is how credential stealers exfiltrate them.'));
        continue;
      }
      let actionHost = '';
      try { actionHost = new URL(action, pageUrl || 'https://x.invalid').hostname.toLowerCase(); } catch { continue; }
      if (!actionHost || actionHost === pageHost) continue;
      const actionParts = splitHost(actionHost);
      if (actionParts.registrable !== pageParts.registrable) {
        signals.push(signal('content.cross-domain-credentials', 65, 'high', 'Login form posts to a different domain',
          `The password box on ${pageHost} sends what you type to ${actionHost}.`));
      }
    }
  }

  // --- Brand impersonation in page text vs. real owner ---------------------
  if (pageParts.registrable && !LEGITIMATE_BRAND_DOMAINS.has(pageParts.registrable)) {
    const title = (text.match(/<title[^>]*>([\s\S]{0,200}?)<\/title>/i) || [])[1] || '';
    const haystack = `${title} ${visible.slice(0, 4000)}`.toLowerCase();
    for (const brand of PROTECTED_BRANDS) {
      const mentions = countMatches(new RegExp(brand.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'), haystack);
      const brandInTitle = new RegExp(brand.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i').test(title);
      if ((brandInTitle || mentions >= 3) && passwordInputs > 0) {
        signals.push(signal('content.brand-impersonation', 75, 'critical',
          `Page presents itself as ${brand.name} but is hosted on ${pageParts.registrable}`,
          `A ${brand.name} sign-in page lives on ${brand.domain}. This one asks for a password on a domain ${brand.name} does not own.`));
        break;
      }
    }
  }

  // --- Obfuscated / packed JavaScript --------------------------------------
  const obfHits = OBFUSCATION_MARKERS.filter((m) => m.re.test(text));
  if (obfHits.length) {
    const score = Math.min(80, obfHits.reduce((s, m) => s + m.weight, 0));
    signals.push(signal('content.obfuscated-js', score, score >= 55 ? 'high' : 'medium',
      'Deliberately obfuscated JavaScript',
      `Found ${obfHits.length} obfuscation pattern${obfHits.length > 1 ? 's' : ''}: ${obfHits.map((m) => m.label).join('; ')}.`));
  }

  // --- Crypto mining -------------------------------------------------------
  const lower = text.toLowerCase();
  const minerHits = CRYPTO_MINER_MARKERS.filter((m) => lower.includes(m));
  if (minerHits.length >= 2 || (minerHits.length === 1 && /wasm|webassembly/i.test(text))) {
    signals.push(signal('content.cryptominer', 70, 'high', 'In-browser cryptocurrency miner',
      `Markers found: ${minerHits.join(', ')}. This burns your CPU and battery for someone else's profit.`));
  }

  // --- Tech-support scare pages and fake updates ---------------------------
  const scareHits = FAKE_UPDATE_TEXT.filter((re) => re.test(visible));
  if (scareHits.length) {
    const hasBlockers = /(?:requestFullscreen|beforeunload|history\.pushState[\s\S]{0,200}setInterval|window\.print\s*\(\s*\)|Notification\.requestPermission)/i.test(text);
    signals.push(signal('content.scareware', hasBlockers ? 75 : 55, hasBlockers ? 'critical' : 'high',
      'Fake security warning / tech-support scam',
      `The page uses alarm language ("${(visible.match(scareHits[0]) || [''])[0].slice(0, 80)}")${hasBlockers ? ' together with fullscreen or navigation-trapping code' : ''}. Real virus warnings never come from a web page.`));
  }

  // --- ClickFix: page tells you to paste a command into a terminal ---------
  const clickfixHits = CLICKFIX_MARKERS.filter((re) => re.test(visible) || re.test(text));
  if (clickfixHits.length >= 2 || (clickfixHits.length === 1 && CLIPBOARD_HIJACK.some((re) => re.test(text)))) {
    signals.push(signal('content.clickfix', 90, 'critical', 'Page is instructing you to run a command',
      'This is the "ClickFix"/fake-CAPTCHA technique: the page copies a command to your clipboard and asks you to paste it into Run or PowerShell. Pasting it installs malware. Never do this.'));
  }

  // --- Clipboard hijacking on its own --------------------------------------
  if (CLIPBOARD_HIJACK.some((re) => re.test(text)) && /addEventListener\s*\(\s*["']copy["']/i.test(text)) {
    signals.push(signal('content.clipboard-hijack', 45, 'high', 'Page rewrites what you copy',
      'The page intercepts copy events. Crypto-clipper scripts use this to swap a wallet address you copied for the attacker\'s.'));
  }

  // --- Seed-phrase harvesting ----------------------------------------------
  if (SEED_PHRASE_MARKERS.some((re) => re.test(visible)) && (passwordInputs > 0 || /<textarea/i.test(text))) {
    signals.push(signal('content.seed-phrase', 95, 'critical', 'Page is asking for a wallet recovery phrase',
      'No legitimate wallet, exchange, or support agent ever asks for your seed phrase. Entering it hands over every coin in the wallet, permanently.'));
  }

  // --- Keylogging ----------------------------------------------------------
  if (KEYLOGGER_MARKERS.some((re) => re.test(text))) {
    signals.push(signal('content.keylogger', 60, 'high', 'Keystrokes are being sent to a server',
      'The page listens to every key you press and forwards it over the network.'));
  }

  // --- Hidden iframes / clickjacking ---------------------------------------
  const hiddenFrames = [...text.matchAll(/<iframe[^>]*>/gi)].filter((m) => {
    const tag = m[0];
    return /(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?!\.)|width\s*=\s*["']?0|height\s*=\s*["']?0)/i.test(tag);
  });
  if (hiddenFrames.length) {
    signals.push(signal('content.hidden-iframe', 40, 'medium', `${hiddenFrames.length} invisible iframe${hiddenFrames.length > 1 ? 's' : ''}`,
      'Invisible frames load another site behind what you see, used for clickjacking and drive-by loads.'));
  }

  // --- Automatic downloads --------------------------------------------------
  if (/<a[^>]+download[^>]*>/i.test(text) && /\.(?:exe|msi|scr|jar|apk|dmg|bat|cmd|ps1|vbs|hta|iso)["'\s>]/i.test(text)) {
    signals.push(signal('content.executable-offer', 45, 'high', 'Page offers an executable download',
      'The page links directly to a program file. Shadow will sandbox it, but be sure you meant to download it.'));
  }
  if (/(?:document\.createElement\s*\(\s*["']a["']\s*\)[\s\S]{0,300}?\.click\s*\(\s*\))|(?:window\.location(?:\.href)?\s*=\s*["'][^"']+\.(?:exe|msi|apk|dmg|jar))/i.test(text)) {
    signals.push(signal('content.drive-by-download', 60, 'high', 'Script starts a download by itself',
      'The page triggers a file download without you clicking anything.'));
  }

  // --- Suspicious external script origins -----------------------------------
  const scriptSrcs = [...text.matchAll(/<script[^>]+src\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1]);
  const foreign = new Set();
  for (const src of scriptSrcs) {
    let h = '';
    try { h = new URL(src, pageUrl || 'https://x.invalid').hostname.toLowerCase(); } catch { continue; }
    if (!h || h === pageHost) continue;
    const p = splitHost(h);
    if (p.registrable && p.registrable !== pageParts.registrable) foreign.add(h);
  }
  if (foreign.size >= 8) {
    signals.push(signal('content.script-sprawl', 20, 'low', `Scripts loaded from ${foreign.size} other domains`,
      `Each one can change the page and read what you type. Sources: ${[...foreign].slice(0, 6).join(', ')}...`));
  }
  for (const h of foreign) {
    const p = splitHost(h);
    if (p.domain.length >= 12 && entropy(p.domain) > 3.6) {
      signals.push(signal('content.random-script-host', 40, 'medium', 'Script from a randomly named domain',
        `${h} looks machine-generated. Injected skimmers commonly load from domains like this.`));
      break;
    }
  }

  // --- Meta refresh redirects to another origin ----------------------------
  const metaRefresh = (text.match(/<meta[^>]+http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["'][^"']*url=([^"';]+)/i) || [])[1];
  if (metaRefresh) {
    let h = '';
    try { h = new URL(metaRefresh.trim(), pageUrl || 'https://x.invalid').hostname.toLowerCase(); } catch { /* ignore */ }
    if (h && splitHost(h).registrable !== pageParts.registrable) {
      signals.push(signal('content.meta-redirect', 30, 'medium', 'Automatic redirect to another site',
        `The page immediately forwards you to ${h}.`));
    }
  }

  // --- Anti-analysis behaviour ---------------------------------------------
  if (/(?:oncontextmenu\s*=\s*["']?return\s+false|addEventListener\s*\(\s*["']contextmenu["'][\s\S]{0,120}preventDefault)/i.test(text)
      && /(?:keydown[\s\S]{0,200}(?:123|"F12"|'F12')|devtools)/i.test(text)) {
    signals.push(signal('content.anti-inspection', 35, 'medium', 'Page blocks right-click and developer tools',
      'Legitimate sites rarely fight inspection. Phishing kits do it to stop you reading the code.'));
  }

  return signals;
}

module.exports = { analyzeContent };
