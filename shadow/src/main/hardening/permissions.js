'use strict';
/**
 * Permission policy. Web pages ask for a lot; almost none of it is needed.
 * Default is deny. Pure function so the policy is testable and auditable.
 */

const DENY_ALWAYS = [
  'media',                 // camera and microphone
  'geolocation',
  'midi', 'midiSysex',
  'hid', 'serial', 'usb', 'bluetooth',
  'idle-detection',
  'window-management', 'window-placement',
  'display-capture',       // screen sharing
  'pointerLock',
  'openExternal',          // launching another application
  'unknown',
];

const DENY_BY_DEFAULT = [
  'notifications',
  'clipboard-read',
  'clipboard-sanitized-write',
  'persistent-storage',
  'background-sync',
  'payment-handler',
  'storage-access',
  'top-level-storage-access',
  'speaker-selection',
  'keyboardLock',
];

const ALLOW_BY_DEFAULT = [
  'fullscreen',
  'clipboard-write',       // writing is how "copy" buttons work
];

const PERMISSION_POLICY = { DENY_ALWAYS, DENY_BY_DEFAULT, ALLOW_BY_DEFAULT };

const REASONS = {
  media: 'Camera and microphone access is never granted automatically. Turn it on for one site in Settings if you need a video call.',
  geolocation: 'Your location is not shared with web pages.',
  notifications: 'Notification prompts are a common vector for scam pop-ups, so Shadow refuses them.',
  'clipboard-read': 'Pages cannot read your clipboard. That is how passwords and wallet addresses get stolen.',
  openExternal: 'Shadow will not let a web page launch another program on your computer.',
  'display-capture': 'Screen sharing is blocked.',
  usb: 'Hardware access from a web page is blocked.',
};

/**
 * @param {string} permission
 * @param {string} origin
 * @param {object} settings
 * @returns {{allow: boolean, reason: string}}
 */
function decidePermission(permission, origin, settings) {
  const get = (k, d) => (settings && settings.get(k) !== undefined ? settings.get(k) : d);

  if (!get('hardening.denyPermissions', true)) {
    return { allow: !DENY_ALWAYS.includes(permission), reason: 'permission hardening is off' };
  }

  // Per-site exceptions the user added deliberately, in the form
  // "example.com:media".
  const allowed = get('hardening.allowedPermissions', []) || [];
  let host = '';
  try { host = new URL(origin).hostname.toLowerCase(); } catch { /* non-URL origin */ }
  if (host && (allowed.includes(`${host}:${permission}`) || allowed.includes(`${host}:*`))) {
    return { allow: true, reason: 'you granted this site an exception' };
  }

  if (DENY_ALWAYS.includes(permission)) {
    return { allow: false, reason: REASONS[permission] || 'This permission is never granted automatically.' };
  }
  if (DENY_BY_DEFAULT.includes(permission)) {
    return { allow: false, reason: REASONS[permission] || 'Denied by default. You can add an exception in Settings.' };
  }
  if (ALLOW_BY_DEFAULT.includes(permission)) {
    return { allow: true, reason: 'low risk' };
  }
  return { allow: false, reason: 'Unrecognised permission, denied.' };
}

module.exports = { decidePermission, PERMISSION_POLICY, DENY_ALWAYS, DENY_BY_DEFAULT, ALLOW_BY_DEFAULT };
