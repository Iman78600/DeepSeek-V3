'use strict';
/**
 * Certificate heuristics. Electron hands us a certificate object on
 * 'certificate-error' and via webContents; this module turns one into signals.
 * Pure function so it can be unit tested with a plain object.
 */

const { splitHost } = require('./url-heuristics');

function signal(id, score, severity, title, detail) {
  return { id, score, severity, title, detail };
}

const DAY = 86400000;

// Issuers that hand out free, unvalidated, instantly-issued certificates.
// Not bad on their own, but "brand new free cert" + "brand lookalike" is a
// much stronger phishing signal than either alone.
const FREE_ISSUERS = [
  "let's encrypt", 'lets encrypt', 'zerossl', 'buypass', 'r3', 'r10', 'r11',
  'e5', 'e6', 'actalis authentication root', 'ssl.com dv', 'cpanel',
  'google trust services', 'gts ca 1p5', 'gts ca 1d4',
];

function certAge(cert, now = Date.now()) {
  const start = cert && (cert.validStart ?? cert.valid_from ?? cert.validStartDate);
  if (start === undefined || start === null) return null;
  const ms = typeof start === 'number'
    ? (start < 1e12 ? start * 1000 : start) // Electron gives seconds
    : Date.parse(start);
  if (!Number.isFinite(ms)) return null;
  return now - ms;
}

function certRemaining(cert, now = Date.now()) {
  const end = cert && (cert.validExpiry ?? cert.valid_to ?? cert.validExpiryDate);
  if (end === undefined || end === null) return null;
  const ms = typeof end === 'number'
    ? (end < 1e12 ? end * 1000 : end)
    : Date.parse(end);
  if (!Number.isFinite(ms)) return null;
  return ms - now;
}

function hostMatchesCert(hostname, cert) {
  const names = [];
  if (cert.subjectName) names.push(cert.subjectName);
  if (cert.subject && cert.subject.commonName) names.push(cert.subject.commonName);
  for (const alt of cert.subjectAltName ? String(cert.subjectAltName).split(/[,\s]+/) : []) {
    names.push(alt.replace(/^DNS:/i, ''));
  }
  if (!names.length) return null;
  const host = String(hostname || '').toLowerCase();
  return names.some((n) => {
    const name = String(n).toLowerCase().trim();
    if (!name) return false;
    if (name.startsWith('*.')) {
      const base = name.slice(2);
      return host === base || (host.endsWith(`.${base}`) && host.slice(0, -(base.length + 1)).indexOf('.') === -1);
    }
    return name === host;
  });
}

/**
 * @param {object} cert     Electron-style certificate object
 * @param {string} hostname host we intended to reach
 * @param {object} [opts]   { errorCode, now }
 */
function analyzeCertificate(cert, hostname, opts = {}) {
  const signals = [];
  const now = opts.now || Date.now();

  if (opts.errorCode) {
    const code = String(opts.errorCode);
    const map = {
      'net::ERR_CERT_AUTHORITY_INVALID': [80, 'critical', 'Certificate signed by an unknown authority',
        'Nothing your system trusts vouches for this certificate. On a public site this usually means interception or a self-signed certificate.'],
      'net::ERR_CERT_COMMON_NAME_INVALID': [80, 'critical', 'Certificate is for a different site',
        'The certificate presented does not cover the address you asked for.'],
      'net::ERR_CERT_DATE_INVALID': [55, 'high', 'Certificate is expired or not yet valid',
        'Expired certificates cannot be checked for revocation.'],
      'net::ERR_CERT_REVOKED': [95, 'critical', 'Certificate has been revoked',
        'The issuer withdrew this certificate. That normally means its private key was stolen.'],
      'net::ERR_CERT_INVALID': [80, 'critical', 'Malformed certificate', 'The certificate could not be parsed.'],
      'net::ERR_CERT_WEAK_SIGNATURE_ALGORITHM': [60, 'high', 'Weak signature algorithm',
        'The certificate is signed with an algorithm that can be forged.'],
      'net::ERR_CERT_SYMANTEC_LEGACY': [50, 'high', 'Distrusted legacy certificate authority', 'This issuer is no longer trusted.'],
      'net::ERR_SSL_PINNED_KEY_NOT_IN_CERT_LIST': [95, 'critical', 'Certificate pinning failure',
        'The site publishes which keys are valid for it, and this is not one of them. This is a strong sign of interception.'],
    };
    const hit = map[code] || [65, 'high', 'TLS certificate error', `The connection failed certificate validation (${code}).`];
    signals.push(signal(`tls.${code.replace(/^net::ERR_/, '').toLowerCase()}`, hit[0], hit[1], hit[2], hit[3]));
  }

  if (!cert || typeof cert !== 'object') return signals;

  const age = certAge(cert, now);
  const remaining = certRemaining(cert, now);
  const issuer = String(cert.issuerName || (cert.issuer && cert.issuer.commonName) || '').toLowerCase();
  const parts = splitHost(hostname);

  if (age !== null && age < 2 * DAY) {
    signals.push(signal('tls.brand-new-cert', 30, 'medium', 'Certificate issued in the last 48 hours',
      `This certificate is ${Math.max(0, Math.round(age / 3600000))} hours old. Phishing sites get a fresh certificate the day they go live.`));
  } else if (age !== null && age < 7 * DAY) {
    signals.push(signal('tls.new-cert', 15, 'low', 'Certificate issued this week',
      `The certificate is ${Math.round(age / DAY)} days old.`));
  }

  if (remaining !== null && remaining < 0) {
    signals.push(signal('tls.expired', 55, 'high', 'Certificate expired',
      `It stopped being valid ${Math.round(-remaining / DAY)} days ago.`));
  }

  const isFreeIssuer = FREE_ISSUERS.some((i) => issuer.includes(i));
  if (isFreeIssuer && age !== null && age < 7 * DAY) {
    signals.push(signal('tls.free-new-cert', 20, 'low', 'Brand-new free certificate',
      `Issued by "${cert.issuerName || issuer}" days ago. Free automated certificates are normal, but combined with a lookalike domain they are how phishing pages get a padlock.`));
  }

  // Self-signed: issuer equals subject
  const subjectName = String(cert.subjectName || (cert.subject && cert.subject.commonName) || '');
  if (subjectName && cert.issuerName && subjectName === cert.issuerName) {
    signals.push(signal('tls.self-signed', 60, 'high', 'Self-signed certificate',
      'The site vouched for itself. No independent authority checked who runs it.'));
  }

  // Hostname mismatch, computed independently of the Chromium error
  const matches = hostMatchesCert(hostname, cert);
  if (matches === false) {
    signals.push(signal('tls.name-mismatch', 75, 'critical', 'Certificate does not cover this hostname',
      `The certificate is for "${subjectName || 'an unrelated name'}", not ${hostname}.`));
  }

  // Very broad wildcards, e.g. *.com or *.co.uk should never validate
  if (/^\*\./.test(subjectName)) {
    const base = subjectName.slice(2).toLowerCase();
    const baseParts = splitHost(base);
    if (!baseParts.domain || base === baseParts.suffix) {
      signals.push(signal('tls.overbroad-wildcard', 70, 'critical', 'Over-broad wildcard certificate',
        `"${subjectName}" would cover an entire top-level domain. No legitimate CA issues this.`));
    }
  }

  // A certificate covering hundreds of unrelated names is typical of shared
  // bulletproof hosting and of some CDNs; low weight, context only.
  const altCount = cert.subjectAltName ? String(cert.subjectAltName).split(/[,\s]+/).filter(Boolean).length : 0;
  if (altCount > 100) {
    signals.push(signal('tls.mass-san', 10, 'low', `Certificate shared by ${altCount} hostnames`,
      'Shared certificates are common on CDNs, but also on bulk phishing hosts.'));
  }

  // Organisation-validated certificates are a mild positive signal
  const org = (cert.subject && (cert.subject.organizations || [])[0]) || '';
  if (org && !isFreeIssuer) {
    signals.push(signal('tls.org-validated', -15, 'info', 'Organisation-validated certificate',
      `The issuer verified the legal identity "${org}" before issuing this certificate.`));
  }

  if (parts.registrable && subjectName && !subjectName.includes(parts.registrable) && matches === null) {
    // No SAN data available; nothing conclusive, stay quiet.
  }

  return signals;
}

module.exports = { analyzeCertificate, hostMatchesCert, certAge, certRemaining };
