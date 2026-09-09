'use strict';
/**
 * URL heuristics - the first thing Shadow's SOC analyst looks at.
 *
 * Every check returns zero or more "signals". A signal is a small object:
 *   { id, score, severity, title, detail }
 * Scores are additive and consumed by ../scoring.js. Nothing here does I/O,
 * so it is fast enough to run on every single request and is trivially
 * unit-testable (see test/url-heuristics.test.js).
 */

const { domainToUnicode } = require('node:url');

const { PUBLIC_SUFFIXES } = require('../data/public-suffixes');
const { HIGH_RISK_TLDS, SHORTENERS, DYNAMIC_DNS, FREE_HOSTS } = require('../data/tld-reputation');
const { PROTECTED_BRANDS } = require('../data/brands');

const CREDENTIAL_WORDS = [
  'login', 'signin', 'sign-in', 'logon', 'account', 'verify', 'verification',
  'secure', 'security', 'update', 'confirm', 'password', 'passwd', 'credential',
  'billing', 'invoice', 'payment', 'wallet', 'seed', 'recovery', 'unlock',
  'suspended', 'limited', 'appeal', 'authenticate', 'mfa', '2fa', 'otp',
];

const DANGEROUS_EXTENSIONS = [
  '.exe', '.scr', '.pif', '.com', '.bat', '.cmd', '.msi', '.msix', '.appx',
  '.jar', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.cpl',
  '.dll', '.ps1', '.psm1', '.reg', '.lnk', '.iso', '.img', '.vhd', '.apk',
  '.dmg', '.pkg', '.deb', '.rpm', '.sh', '.run', '.elf', '.msc', '.scf',
];

const ARCHIVE_EXTENSIONS = ['.zip', '.rar', '.7z', '.tar', '.gz', '.cab', '.ace', '.iso'];

// Characters that look like ASCII letters but are not. Used for homograph checks.
const CONFUSABLES = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
  'ѕ': 's', 'і': 'i', 'ј': 'j', 'ԁ': 'd', 'һ': 'h', 'ӏ': 'l', 'ν': 'v',
  'α': 'a', 'ο': 'o', 'ρ': 'p', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'τ': 't',
  'ᴀ': 'a', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', '0': 'o', '1': 'l', '5': 's',
};

function signal(id, score, severity, title, detail) {
  return { id, score, severity, title, detail };
}

/** Shannon entropy in bits per character. High values suggest generated names. */
function entropy(str) {
  if (!str.length) return 0;
  const counts = new Map();
  for (const ch of str) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * How word-like a string is. Entropy alone cannot separate "stackoverflow"
 * (3.55) from "xkqjvbzmrtpl" (3.59), but vowel distribution can: real words
 * carry vowels at regular intervals, generated names usually do not.
 * Returns { vowelRatio, maxConsonantRun, wordLike }.
 */
function pronounceability(str) {
  const s = String(str).toLowerCase().replace(/[^a-z]/g, '');
  if (!s.length) return { vowelRatio: 0, maxConsonantRun: 0, wordLike: false };
  const vowels = (s.match(/[aeiouy]/g) || []).length;
  const vowelRatio = vowels / s.length;
  let run = 0;
  let maxRun = 0;
  for (const ch of s) {
    if ('aeiouy'.includes(ch)) run = 0;
    else { run++; if (run > maxRun) maxRun = run; }
  }
  return {
    vowelRatio,
    maxConsonantRun: maxRun,
    wordLike: vowelRatio >= 0.25 && maxRun <= 4,
  };
}

/** Classic Levenshtein distance, capped for speed. */
function levenshtein(a, b, cap = 4) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > cap) return cap + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    if (rowMin > cap) return cap + 1;
    prev = cur;
  }
  return prev[b.length];
}

/**
 * Split a hostname into { subdomain, domain, suffix }. Uses a trimmed public
 * suffix list so "a.b.co.uk" yields domain "b", suffix "co.uk".
 */
function splitHost(hostname) {
  const host = String(hostname || '').toLowerCase().replace(/\.$/, '');
  const labels = host.split('.');
  let suffixLen = 1;
  for (let i = labels.length - 1; i >= 0; i--) {
    const candidate = labels.slice(i).join('.');
    if (PUBLIC_SUFFIXES.has(candidate)) suffixLen = labels.length - i;
  }
  if (labels.length <= suffixLen) {
    return { subdomain: '', domain: host, suffix: '', registrable: host, labels };
  }
  const suffix = labels.slice(labels.length - suffixLen).join('.');
  const domain = labels[labels.length - suffixLen - 1];
  const subdomain = labels.slice(0, labels.length - suffixLen - 1).join('.');
  return { subdomain, domain, suffix, registrable: `${domain}.${suffix}`, labels };
}

function isIpLiteral(hostname) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return 'ipv4';
  if (/^\[?[0-9a-f:]+\]?$/i.test(hostname) && hostname.includes(':')) return 'ipv6';
  if (/^\d{8,10}$/.test(hostname)) return 'ipv4-decimal';
  if (/^0x[0-9a-f]+$/i.test(hostname)) return 'ipv4-hex';
  return null;
}

/**
 * Loopback, link-local, private ranges and local-only names. Kept in step with
 * firewall/rules.js, which enforces the policy; this only decides how to score.
 */
function isLocalAddress(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!h) return null;
  if (h === 'localhost' || h.endsWith('.localhost')) return 'localhost';
  if (h === '::1' || h === '0:0:0:0:0:0:0:1') return 'loopback';
  if (/^127\./.test(h)) return 'loopback';
  if (/^10\./.test(h)) return 'private network';
  if (/^192\.168\./.test(h)) return 'private network';
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return 'private network';
  if (/^169\.254\./.test(h)) return 'link-local';
  if (/^f[cd][0-9a-f]{2}:/.test(h)) return 'private network';
  if (/^fe80:/.test(h)) return 'link-local';
  if (/\.(?:local|internal|lan|home|intranet|private)$/.test(h)) return 'local network name';
  return null;
}

/** Normalise confusable unicode down to ASCII so we can compare to brands. */
function deconfuse(str) {
  let out = '';
  for (const ch of str) out += CONFUSABLES[ch] !== undefined ? CONFUSABLES[ch] : ch;
  return out;
}

function scriptsUsed(str) {
  const scripts = new Set();
  for (const ch of str) {
    const c = ch.codePointAt(0);
    if (c < 0x80) { if (/[a-z]/i.test(ch)) scripts.add('latin'); continue; }
    if (c >= 0x0400 && c <= 0x04ff) scripts.add('cyrillic');
    else if (c >= 0x0370 && c <= 0x03ff) scripts.add('greek');
    else if (c >= 0x0590 && c <= 0x05ff) scripts.add('hebrew');
    else if (c >= 0x0600 && c <= 0x06ff) scripts.add('arabic');
    else if (c >= 0x4e00 && c <= 0x9fff) scripts.add('han');
    else if (c >= 0x0100 && c <= 0x024f) scripts.add('latin-ext');
    else scripts.add('other');
  }
  return scripts;
}

/**
 * Main entry point. Give it a URL string, get back an array of signals.
 */
function analyzeUrl(rawUrl) {
  const signals = [];
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return [signal('url.unparseable', 30, 'medium', 'Malformed address',
      `Shadow could not parse "${String(rawUrl).slice(0, 120)}" as a URL.`)];
  }

  const scheme = url.protocol.replace(':', '');
  const hostname = url.hostname.toLowerCase();
  // new URL() converts an internationalised host to punycode, which hides the
  // very characters a homograph check needs to see. Convert it back.
  const decodedHost = (() => {
    try {
      const uni = hostname.includes('xn--') ? domainToUnicode(hostname) : hostname;
      return uni || hostname;
    } catch { return hostname; }
  })();
  const path = url.pathname + url.search;
  const full = url.href;

  // --- Scheme checks -------------------------------------------------------
  if (scheme === 'javascript') {
    signals.push(signal('url.javascript-scheme', 90, 'critical', 'javascript: URL',
      'Pages that navigate to javascript: URLs are usually running injected code.'));
  }
  if (scheme === 'data') {
    const isHtml = /^data:text\/html/i.test(full);
    signals.push(signal('url.data-scheme', isHtml ? 70 : 25, isHtml ? 'high' : 'low',
      'data: URL navigation',
      isHtml ? 'A data:text/html URL renders attacker-controlled HTML with no real origin.'
             : 'data: URLs hide the true source of content.'));
  }
  if (scheme === 'file') {
    signals.push(signal('url.file-scheme', 20, 'low', 'Local file access',
      'The page is reading from the local filesystem.'));
  }
  if (scheme === 'http') {
    signals.push(signal('url.plaintext', 20, 'low', 'Unencrypted connection',
      'HTTP traffic can be read and modified by anyone on the network path.'));
  }

  // --- Userinfo obfuscation ------------------------------------------------
  if (url.username || url.password) {
    signals.push(signal('url.userinfo', 55, 'high', 'Credentials embedded in URL',
      `The part before "@" ("${url.username}") is not the real site. The browser connects to "${hostname}".`));
  }

  // --- Host shape ----------------------------------------------------------
  // Loopback and private addresses are judged differently. Plain HTTP, a raw
  // IP and a high port are all completely normal for a development server or a
  // device on your own network, and scoring them the way we score a public
  // site puts a warning on every page of anyone running one. The security
  // question for these addresses is "may a web page reach them", which is the
  // firewall's job, not the analyst's.
  const localKind = isLocalAddress(hostname);
  if (localKind) {
    return [signal('url.local-address', 0, 'info', `Local address (${localKind})`,
      'This address is on your own machine or your own network, so it is not scored like a public website. '
      + 'Shadow still stops web pages from reaching addresses like this.')];
  }

  const ipKind = isIpLiteral(hostname);
  if (ipKind) {
    const obfuscated = ipKind !== 'ipv4' && ipKind !== 'ipv6';
    signals.push(signal('url.ip-literal', obfuscated ? 60 : 35, obfuscated ? 'high' : 'medium',
      'Raw IP address instead of a domain',
      obfuscated ? `The host is an obfuscated IP encoding (${ipKind}), a classic filter-evasion trick.`
                 : 'Legitimate services almost always use a domain name with a certificate.'));
  }

  const parts = splitHost(hostname);

  if (!ipKind) {
    // Punycode / homograph
    if (hostname.includes('xn--')) {
      signals.push(signal('url.punycode', 45, 'high', 'Punycode (non-Latin) domain',
        `"${hostname}" is an internationalised domain. These are frequently used to imitate real brands.`));
    }
    const scripts = scriptsUsed(decodedHost);
    if (scripts.size > 1 && scripts.has('latin')) {
      signals.push(signal('url.mixed-script', 60, 'high', 'Mixed alphabets in domain',
        `The domain mixes ${[...scripts].join(' + ')} characters, which is how homograph attacks are built.`));
    }

    // High-risk TLD
    if (parts.suffix && HIGH_RISK_TLDS.has(parts.suffix)) {
      signals.push(signal('url.risky-tld', 22, 'medium', `Abuse-heavy TLD (.${parts.suffix})`,
        `The .${parts.suffix} top-level domain has an unusually high share of malicious registrations.`));
    }

    // Shorteners / dynamic DNS / free hosting
    if (SHORTENERS.has(parts.registrable)) {
      signals.push(signal('url.shortener', 18, 'low', 'Link shortener',
        'The real destination is hidden behind a redirect.'));
    }
    if (DYNAMIC_DNS.has(parts.registrable)) {
      signals.push(signal('url.dynamic-dns', 35, 'medium', 'Dynamic DNS host',
        `${parts.registrable} hands out free subdomains and is common in malware command-and-control.`));
    }
    if (FREE_HOSTS.has(parts.registrable) && parts.subdomain) {
      signals.push(signal('url.free-hosting', 25, 'medium', 'Free hosting subdomain',
        `Anyone can publish under ${parts.registrable} in minutes with no identity check.`));
    }

    // Subdomain depth
    const depth = parts.subdomain ? parts.subdomain.split('.').length : 0;
    if (depth >= 4) {
      signals.push(signal('url.deep-subdomain', 25, 'medium', 'Unusually deep subdomain',
        `${depth} levels of subdomain ("${parts.subdomain}") is a common way to bury a fake brand name.`));
    }

    // Brand impersonation: brand appears somewhere in the host, but the
    // registrable domain is not actually owned by that brand.
    const flatHost = deconfuse(decodedHost).replace(/[^a-z0-9.]/g, '');
    for (const brand of PROTECTED_BRANDS) {
      if (parts.registrable === brand.domain) break; // it really is them
      const brandInHost = flatHost.includes(brand.token);
      const brandIsRegistrable = parts.domain === brand.token;

      // The registrable label IS the brand once confusable characters are
      // normalised: "micros0ft.com", "paypa1.com", "app1e.com". That is a
      // lookalike domain, not a brand buried in a subdomain.
      if (!brandIsRegistrable && deconfuse(parts.domain) === brand.token) {
        signals.push(signal('url.typosquat', 75, 'high',
          `Lookalike of ${brand.name}`,
          `"${parts.domain}" is "${brand.token}" with characters swapped for ones that look the same. The real site is ${brand.domain}.`));
        break;
      }

      if (brandInHost && !brandIsRegistrable) {
        signals.push(signal('url.brand-in-subdomain', 65, 'high',
          `"${brand.name}" appears in the address but this is not ${brand.domain}`,
          `Everything before the last dot is chosen by whoever registered "${parts.registrable}". The real owner of this page is ${parts.registrable}.`));
        break;
      }
      // Typosquat: registrable domain is one or two edits from the brand.
      if (!brandInHost && parts.domain.length >= 4) {
        const d = levenshtein(deconfuse(parts.domain), brand.token, 2);
        if (d > 0 && d <= (brand.token.length >= 8 ? 2 : 1)) {
          signals.push(signal('url.typosquat', 70, 'high',
            `Looks like a misspelling of ${brand.name}`,
            `"${parts.domain}" is ${d} character${d > 1 ? 's' : ''} away from "${brand.token}". The real site is ${brand.domain}.`));
          break;
        }
      }
    }

    // DGA-ish hostnames
    if (parts.domain.length >= 10 && !parts.domain.includes('-')) {
      const h = entropy(parts.domain);
      const digitRatio = (parts.domain.match(/\d/g) || []).length / parts.domain.length;
      const speech = pronounceability(parts.domain);
      // High entropy on its own is not evidence: real English words score the
      // same. Require the name to also be unpronounceable, or digit-heavy.
      const looksGenerated = (h > 3.4 && !speech.wordLike) || digitRatio > 0.4;
      if (looksGenerated) {
        signals.push(signal('url.random-domain', 30, 'medium', 'Machine-generated domain name',
          `"${parts.domain}" has the shape of an algorithmically generated domain: entropy ${h.toFixed(2)}, ` +
          `${Math.round(speech.vowelRatio * 100)}% vowels, ${speech.maxConsonantRun} consonants in a row.`));
      }
    }

    // Hyphen stuffing, e.g. secure-login-apple-id-verify.tld
    const hyphens = (parts.domain.match(/-/g) || []).length;
    if (hyphens >= 3) {
      signals.push(signal('url.hyphen-stuffing', 25, 'medium', 'Keyword-stuffed domain',
        `"${parts.domain}" strings together ${hyphens + 1} words, a pattern used to make fake domains look official.`));
    }
  }

  // --- Port ---------------------------------------------------------------
  if (url.port && !['80', '443', '8080', '8443'].includes(url.port)) {
    signals.push(signal('url.odd-port', 25, 'medium', `Unusual port (${url.port})`,
      'Normal web services listen on 80 or 443. Odd ports often front malware panels.'));
  }

  // --- Path and query ------------------------------------------------------
  const lowerPath = path.toLowerCase();
  const credHits = CREDENTIAL_WORDS.filter((w) => lowerPath.includes(w));
  if (credHits.length >= 2) {
    signals.push(signal('url.credential-path', 30, 'medium', 'Account/urgency wording in the link',
      `The path contains ${credHits.slice(0, 4).map((w) => `"${w}"`).join(', ')}, typical phishing bait.`));
  }
  if (credHits.length >= 1 && scheme === 'http') {
    signals.push(signal('url.login-over-http', 55, 'high', 'Login page over plain HTTP',
      'Anything typed into this page travels unencrypted.'));
  }

  const ext = (lowerPath.split('?')[0].match(/\.[a-z0-9]{1,6}$/) || [''])[0];
  // .js, .dll and .com are normal in a URL (scripts, CDN paths, domain-like
  // filenames). They stay dangerous as *downloads*, which scanner.js handles.
  const URL_SAFE_EXTENSIONS = ['.js', '.dll', '.com'];
  if (DANGEROUS_EXTENSIONS.includes(ext) && !URL_SAFE_EXTENSIONS.includes(ext)) {
    signals.push(signal('url.executable-link', 45, 'high', `Direct link to an executable (${ext})`,
      'Following this link starts a download that can run code on your machine.'));
  } else if (ARCHIVE_EXTENSIONS.includes(ext)) {
    signals.push(signal('url.archive-link', 18, 'low', `Archive download (${ext})`,
      'Archives are used to smuggle executables past scanners.'));
  }

  if (full.length > 300) {
    signals.push(signal('url.excessive-length', 15, 'low', 'Very long URL',
      `${full.length} characters. Long URLs hide the real domain on small screens.`));
  }

  const encodedRatio = ((full.match(/%[0-9a-f]{2}/gi) || []).length * 3) / Math.max(full.length, 1);
  if (encodedRatio > 0.25) {
    signals.push(signal('url.over-encoded', 35, 'medium', 'Heavily percent-encoded URL',
      'Encoding this much of a URL is normally done to defeat filters, not to transmit data.'));
  }

  if (/(?:%2f|%5c|\.\.\/|\.\.\\)/i.test(lowerPath)) {
    signals.push(signal('url.traversal', 30, 'medium', 'Path traversal characters',
      'The link contains "../" style sequences used to escape a directory.'));
  }

  // Open-redirect style parameters carrying another absolute URL
  for (const [key, value] of url.searchParams) {
    if (/^(?:https?:\/\/|\/\/)/i.test(value) && /(?:url|redirect|next|dest|target|goto|continue|return)/i.test(key)) {
      signals.push(signal('url.open-redirect', 30, 'medium', 'Redirect parameter in the link',
        `"${key}" carries another address (${value.slice(0, 80)}). This is used to bounce you off a trusted domain.`));
      break;
    }
  }

  // Base64 blobs in the query, often used to smuggle payloads or emails
  for (const [key, value] of url.searchParams) {
    if (value.length >= 40 && /^[A-Za-z0-9+/=_-]+$/.test(value) && entropy(value) > 4.2) {
      signals.push(signal('url.encoded-blob', 15, 'low', 'Encoded payload in the query string',
        `Parameter "${key}" holds a ${value.length}-character encoded blob.`));
      break;
    }
  }

  return signals;
}

module.exports = {
  analyzeUrl,
  splitHost,
  isIpLiteral,
  isLocalAddress,
  entropy,
  pronounceability,
  levenshtein,
  deconfuse,
  scriptsUsed,
  DANGEROUS_EXTENSIONS,
  ARCHIVE_EXTENSIONS,
};
