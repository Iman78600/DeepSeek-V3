'use strict';
/**
 * Where a quarantined file is allowed to be released to.
 *
 * Releasing a download is the one operation that deliberately moves attacker
 * -controlled bytes out of the sandbox. The destination therefore matters as
 * much as the verdict: dropping even a "clean" file into an autostart folder,
 * a shell profile directory or a systemd unit path turns a download into
 * persistence. The release directory is a user setting, so it is also
 * reachable from the browser UI, which is a renderer process.
 */

const path = require('path');
const os = require('os');

/** Directory names that give a file the ability to run without being opened. */
const FORBIDDEN_SEGMENTS = [
  'autostart', 'startup', 'launchagents', 'launchdaemons', 'systemd',
  'init.d', 'cron.d', 'cron.daily', 'cron.hourly', 'rc.d', 'profile.d',
  'bin', 'sbin', 'lib', 'lib64', 'usr', 'etc', 'boot', 'dev', 'proc', 'sys',
  'windows', 'system32', 'syswow64', 'programdata', 'program files',
  'kernel_extensions', 'extensions', 'startupitems',
];

/** Dotfiles and directories that are executed or sourced on login. */
const FORBIDDEN_BASENAMES = [
  '.ssh', '.gnupg', '.config', '.local', '.bashrc', '.bash_profile',
  '.zshrc', '.profile', '.shadow',
];

function normalise(p) {
  return path.resolve(String(p || ''));
}

/**
 * @param {string} dir
 * @returns {{ok: boolean, reason?: string, path: string}}
 */
function checkReleaseDir(dir) {
  const target = normalise(dir);
  const home = normalise(os.homedir());
  const root = path.parse(target).root;

  if (target === root) {
    return { ok: false, path: target, reason: 'Shadow will not release files into the root of a drive.' };
  }
  if (target === home) {
    return { ok: true, path: target };
  }

  const segments = target.split(path.sep).filter(Boolean).map((s) => s.toLowerCase());

  for (const seg of segments) {
    if (FORBIDDEN_SEGMENTS.includes(seg)) {
      return {
        ok: false,
        path: target,
        reason: `"${seg}" is a directory the system runs things from. A file released there could start itself without you opening it.`,
      };
    }
    if (FORBIDDEN_BASENAMES.includes(seg)) {
      return {
        ok: false,
        path: target,
        reason: `"${seg}" holds configuration your shell and tools load automatically.`,
      };
    }
  }

  // Everything else must still live under the user's home directory, so a
  // release can never write into another account or a system location.
  const insideHome = target === home || target.startsWith(home + path.sep);
  if (!insideHome) {
    return {
      ok: false,
      path: target,
      reason: 'Downloads can only be released somewhere inside your own home folder.',
    };
  }

  return { ok: true, path: target };
}

/** The default, always-acceptable destination. */
function defaultReleaseDir() {
  return path.join(os.homedir(), 'Downloads');
}

module.exports = { checkReleaseDir, defaultReleaseDir, FORBIDDEN_SEGMENTS, FORBIDDEN_BASENAMES };
